from __future__ import annotations

import asyncio
import contextlib
import ctypes
import hashlib
import json
import os
import re
import struct
import subprocess
import shutil
import msvcrt
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUNS_ROOT = PROJECT_ROOT / "builds" / "mcp-runs"
ALLOWED_ROOTS = (
    PROJECT_ROOT,
    Path(r"C:\Program Files\Alea"),
    Path(r"C:\Program Files\FACEIT AC"),
)

MAX_DRIVER_BYTES = 512 * 1024 * 1024
MAX_ACTIVE_RUNS = 4
MAX_TIMEOUT_SECONDS = 3600
MAX_INSTRUCTIONS = 1_000_000_000
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_LOG_READ_BYTES = 64 * 1024
RUN_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
TERMINAL_STATUSES = {
    "succeeded", "failed", "timed_out", "cancelled", "interrupted",
    "analysis_only", "termination_failed",
}

Configuration = Literal["Debug", "Release"]
RunStatus = Literal[
    "queued", "running", "cancelling", "succeeded", "failed", "timed_out",
    "cancelled", "interrupted", "analysis_only", "termination_failed",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class InspectDriverRequest(StrictModel):
    path: str = Field(min_length=1, max_length=4096, description="Absolute path, or a path relative to the project root.")


class BuildRequest(StrictModel):
    configuration: Configuration = "Release"
    timeout_seconds: int = Field(default=1800, ge=1, le=MAX_TIMEOUT_SECONDS)
    output_limit_bytes: int = Field(default=MAX_OUTPUT_BYTES, ge=1024, le=MAX_OUTPUT_BYTES)


class RunDriverRequest(StrictModel):
    driver_path: str = Field(min_length=1, max_length=4096)
    configuration: Configuration = "Release"
    max_insns: int = Field(default=5_000_000, ge=1, le=MAX_INSTRUCTIONS)
    timeout_seconds: int = Field(default=300, ge=1, le=MAX_TIMEOUT_SECONDS)
    output_limit_bytes: int = Field(default=MAX_OUTPUT_BYTES, ge=1024, le=MAX_OUTPUT_BYTES)
    diagnostics: bool = False
    module_reads: bool = False
    disable_seh: bool = False
    seed: int | None = Field(default=None, ge=0, le=0xFFFFFFFFFFFFFFFF)
    vgk_override: bool = False
    devirtualize: bool = False
    strict_exports: bool = False
    provenance: bool = False
    workers_deep: bool = False
    eac_service_emu: bool = False
    target_compat: bool = Field(
        default=False,
        description="Analysis-only exact-version status normalization. It never counts as complete emulation.",
    )
    inject_hypervideo: bool = False
    profile: str | None = Field(default=None, min_length=1, max_length=128)
    trace_path: str | None = Field(
        default=None, min_length=1, max_length=255,
        description="Trace file name stored under the server-owned MCP run directory.",
    )
    check_trace_path: str | None = Field(default=None, min_length=1, max_length=4096)


class SelftestRequest(StrictModel):
    configuration: Configuration = "Release"
    timeout_seconds: int = Field(default=300, ge=1, le=MAX_TIMEOUT_SECONDS)
    output_limit_bytes: int = Field(default=MAX_OUTPUT_BYTES, ge=1024, le=MAX_OUTPUT_BYTES)


class GenerateDriverRequest(StrictModel):
    output_path: str = Field(
        min_length=1, max_length=255,
        description="Generated .sys file name stored under the server-owned MCP run directory.",
    )
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    output_limit_bytes: int = Field(default=256 * 1024, ge=1024, le=MAX_OUTPUT_BYTES)
    verify: bool = True
    with_import: bool = False
    manual_map_only: bool = False
    infinite_loop: bool = False
    overwrite: bool = False


class ReadLogRequest(StrictModel):
    run_id: str = Field(pattern=RUN_ID_RE.pattern)
    offset: int = Field(default=0, ge=0)
    max_bytes: int = Field(default=MAX_LOG_READ_BYTES, ge=1, le=MAX_LOG_READ_BYTES)


class ListRunsRequest(StrictModel):
    limit: int = Field(default=25, ge=1, le=100)
    status: RunStatus | None = None


class CancelRunRequest(StrictModel):
    run_id: str = Field(pattern=RUN_ID_RE.pattern)


class DriverSection(StrictModel):
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int


class DriverInspection(StrictModel):
    path: str
    allowed_root: str
    size_bytes: int
    sha256: str
    machine: int
    architecture: str
    timestamp: int
    section_count: int
    optional_header_magic: int
    entry_point_rva: int
    image_base: int
    size_of_image: int
    subsystem: int
    dll_characteristics: int
    sections: list[DriverSection]


class RunSummary(StrictModel):
    run_id: str
    kind: str
    status: RunStatus
    created_at: str
    started_at: str | None
    completed_at: str | None
    timeout_seconds: int
    output_limit_bytes: int
    output_bytes: int
    output_truncated: bool
    return_code: int | None
    command: list[str]
    cwd: str
    log_path: str
    details: dict[str, Any]


class RunList(StrictModel):
    runs: list[RunSummary]


class LogChunk(StrictModel):
    run: RunSummary
    offset: int
    next_offset: int
    total_bytes: int
    eof: bool
    text: str


class CancelResult(StrictModel):
    cancelled: bool
    run: RunSummary


@dataclass
class _ActiveRun:
    metadata: dict[str, Any]
    task: asyncio.Task[None] | None = None
    process: asyncio.subprocess.Process | None = None
    cancel_requested: bool = False
    termination_succeeded: bool | None = None


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _inside(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((_path_key(path), _path_key(root))) == _path_key(root)
    except ValueError:
        return False


def _allowed_root(path: Path) -> Path | None:
    for root in ALLOWED_ROOTS:
        if _inside(path, root):
            return root
    return None


def resolve_allowed_path(
    value: str,
    *,
    must_exist: bool,
    file_only: bool = False,
    output: bool = False,
) -> tuple[Path, Path]:
    """Resolve a user path and prove it remains inside an explicit allowed root."""
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    candidate = Path(os.path.abspath(candidate))

    lexical_root = _allowed_root(candidate)
    if lexical_root is None:
        raise ValueError(f"path is outside the allowed roots: {candidate}")

    try:
        if output and not candidate.exists():
            parent = candidate.parent.resolve(strict=True)
            resolved = parent / candidate.name
        else:
            resolved = candidate.resolve(strict=must_exist)
    except FileNotFoundError as exc:
        raise ValueError(f"path does not exist: {candidate}") from exc
    except OSError as exc:
        raise ValueError(f"could not resolve path {candidate}: {exc}") from exc

    resolved_root = _allowed_root(resolved)
    if resolved_root is None:
        raise ValueError(f"resolved path escapes the allowed roots: {candidate}")
    if must_exist and file_only and not resolved.is_file():
        raise ValueError(f"path is not a regular file: {resolved}")
    return resolved, resolved_root


def _final_path_from_open_file(stream: Any) -> Path:
    if os.name != "nt":
        return Path(stream.name).resolve(strict=True)
    handle = msvcrt.get_osfhandle(stream.fileno())
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetFinalPathNameByHandleW(
        ctypes.c_void_p(handle), buffer, len(buffer), 0
    )
    if length == 0 or length >= len(buffer):
        raise ValueError("could not resolve the opened file handle")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


def _stage_allowed_file(
    value: str, *, suffix: str | None = None, maximum_bytes: int = MAX_DRIVER_BYTES
) -> tuple[Path, Path, Path]:
    resolved, _ = resolve_allowed_path(value, must_exist=True, file_only=True)
    staging = RUNS_ROOT / "staged-inputs"
    staging.mkdir(parents=True, exist_ok=True)
    temporary = staging / f".{uuid.uuid4().hex}.tmp"
    digest = hashlib.sha256()
    size = 0
    try:
        with resolved.open("rb") as source, temporary.open("xb") as destination:
            final_path = _final_path_from_open_file(source)
            allowed_root = _allowed_root(final_path)
            if allowed_root is None:
                raise ValueError(f"opened file escapes the allowed roots: {resolved}")
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum_bytes:
                    raise ValueError(f"input exceeds the {maximum_bytes}-byte limit")
                digest.update(chunk)
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        extension = suffix or final_path.suffix
        if suffix is not None and final_path.suffix.casefold() != suffix.casefold():
            raise ValueError(f"input must have a {suffix} extension")
        staged_directory = staging / digest.hexdigest()
        staged_directory.mkdir(parents=True, exist_ok=True)
        staged = staged_directory / final_path.name
        if staged.exists():
            temporary.unlink()
        else:
            os.replace(temporary, staged)
        return staged, final_path, allowed_root
    except Exception:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise


def _server_output_path(value: str, directory: str, suffix: str) -> Path:
    requested = Path(value)
    if requested.name != value or any(separator in value for separator in ("/", "\\")):
        raise ValueError("output_path must be a file name without directory components")
    if requested.suffix.casefold() != suffix.casefold():
        raise ValueError(f"output file must have a {suffix} extension")
    root = RUNS_ROOT / directory
    root.mkdir(parents=True, exist_ok=True)
    return root / requested.name

def _require_driver(value: str) -> tuple[Path, Path]:
    path, root = resolve_allowed_path(value, must_exist=True, file_only=True)
    if path.suffix.casefold() != ".sys":
        raise ValueError(f"driver path must have a .sys extension: {path}")
    size = path.stat().st_size
    if size <= 0 or size > MAX_DRIVER_BYTES:
        raise ValueError(f"driver size must be between 1 and {MAX_DRIVER_BYTES} bytes")
    return path, root


def _require_executable(configuration: Configuration) -> Path:
    exe = PROJECT_ROOT / "builds" / configuration / "KEVLAR.exe"
    if not exe.is_file():
        raise ValueError(f"KEVLAR executable does not exist; build {configuration} first: {exe}")
    return exe.resolve(strict=True)


def _parse_driver(path: Path, root: Path) -> DriverInspection:
    size = path.stat().st_size
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)

    with path.open("rb") as stream:
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise ValueError("driver is not a PE image (missing MZ header)")
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        if pe_offset < 64 or pe_offset > min(size - 24, 16 * 1024 * 1024):
            raise ValueError("driver has an invalid PE header offset")
        stream.seek(pe_offset)
        if stream.read(4) != b"PE\0\0":
            raise ValueError("driver is not a PE image (missing PE signature)")
        coff = stream.read(20)
        if len(coff) != 20:
            raise ValueError("driver has a truncated COFF header")
        machine, section_count, timestamp, _, _, optional_size, _ = struct.unpack("<HHIIIHH", coff)
        if section_count == 0 or section_count > 96:
            raise ValueError("driver has an invalid section count")
        if optional_size < 72 or optional_size > 4096:
            raise ValueError("driver has an invalid optional header size")
        optional = stream.read(optional_size)
        if len(optional) != optional_size:
            raise ValueError("driver has a truncated optional header")
        magic = struct.unpack_from("<H", optional)[0]
        if magic == 0x20B:
            image_base = struct.unpack_from("<Q", optional, 24)[0]
            architecture = "x64" if machine == 0x8664 else "unknown"
        elif magic == 0x10B:
            image_base = struct.unpack_from("<I", optional, 28)[0]
            architecture = "x86" if machine == 0x14C else "unknown"
        else:
            raise ValueError(f"unsupported PE optional header magic: 0x{magic:04x}")
        entry_point = struct.unpack_from("<I", optional, 16)[0]
        size_of_image = struct.unpack_from("<I", optional, 56)[0]
        subsystem, dll_characteristics = struct.unpack_from("<HH", optional, 68)

        sections: list[DriverSection] = []
        for _ in range(section_count):
            header = stream.read(40)
            if len(header) != 40:
                raise ValueError("driver has a truncated section table")
            raw_name, virtual_size, virtual_address, raw_size, raw_offset, _, _, _, _, characteristics = struct.unpack(
                "<8sIIIIIIHHI", header
            )
            name = raw_name.split(b"\0", 1)[0].decode("ascii", errors="replace")
            if raw_size and (raw_offset > size or raw_size > size - raw_offset):
                raise ValueError(f"section {name!r} extends beyond the driver image")
            sections.append(
                DriverSection(
                    name=name,
                    virtual_address=virtual_address,
                    virtual_size=virtual_size,
                    raw_offset=raw_offset,
                    raw_size=raw_size,
                    characteristics=characteristics,
                )
            )

    return DriverInspection(
        path=str(path),
        allowed_root=str(root),
        size_bytes=size,
        sha256=digest.hexdigest(),
        machine=machine,
        architecture=architecture,
        timestamp=timestamp,
        section_count=section_count,
        optional_header_magic=magic,
        entry_point_rva=entry_point,
        image_base=image_base,
        size_of_image=size_of_image,
        subsystem=subsystem,
        dll_characteristics=dll_characteristics,
        sections=sections,
    )


class RunManager:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.active: dict[str, _ActiveRun] = {}
        self._mark_interrupted_runs()

    def _run_dir(self, run_id: str) -> Path:
        if not RUN_ID_RE.fullmatch(run_id):
            raise ValueError("invalid run id")
        return self.root / run_id

    def _metadata_path(self, run_id: str) -> Path:
        return self._run_dir(run_id) / "metadata.json"

    def _persist(self, metadata: dict[str, Any]) -> None:
        run_dir = self._run_dir(metadata["run_id"])
        run_dir.mkdir(parents=True, exist_ok=True)
        temporary = run_dir / "metadata.json.tmp"
        temporary.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temporary, run_dir / "metadata.json")

    def _load(self, run_id: str) -> dict[str, Any]:
        path = self._metadata_path(run_id)
        if not path.is_file():
            raise ValueError(f"unknown run id: {run_id}")
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"run metadata is unreadable: {run_id}") from exc
        return metadata

    def _mark_interrupted_runs(self) -> None:
        for metadata_path in self.root.glob("*/metadata.json"):
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                if metadata.get("status") in {"queued", "running", "cancelling"}:
                    metadata["status"] = "interrupted"
                    metadata["completed_at"] = _utc_now()
                    metadata["details"] = {
                        **metadata.get("details", {}),
                        "error": "server exited while the subprocess was active",
                    }
                    self._persist(metadata)
            except (OSError, ValueError, json.JSONDecodeError, TypeError, KeyError):
                continue

    def summary(self, metadata: dict[str, Any]) -> RunSummary:
        return RunSummary.model_validate(metadata)

    def get(self, run_id: str) -> RunSummary:
        active = self.active.get(run_id)
        metadata = active.metadata if active else self._load(run_id)
        return self.summary(metadata)

    def list(self, limit: int, status: RunStatus | None) -> list[RunSummary]:
        records: list[RunSummary] = []
        for metadata_path in self.root.glob("*/metadata.json"):
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                if status is None or metadata.get("status") == status:
                    records.append(self.summary(metadata))
            except (OSError, ValueError, json.JSONDecodeError):
                continue
        records.sort(key=lambda item: (item.created_at, item.run_id), reverse=True)
        return records[:limit]

    def start(
        self,
        *,
        kind: str,
        argv: list[str],
        cwd: Path,
        timeout_seconds: int,
        output_limit_bytes: int,
        details: dict[str, Any],
    ) -> RunSummary:
        if len(self.active) >= MAX_ACTIVE_RUNS:
            raise ValueError(f"at most {MAX_ACTIVE_RUNS} subprocess runs may be active")
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12]
        run_dir = self._run_dir(run_id)
        log_path = run_dir / "run.log"
        metadata: dict[str, Any] = {
            "run_id": run_id,
            "kind": kind,
            "status": "queued",
            "created_at": _utc_now(),
            "started_at": None,
            "completed_at": None,
            "timeout_seconds": timeout_seconds,
            "output_limit_bytes": output_limit_bytes,
            "output_bytes": 0,
            "output_truncated": False,
            "return_code": None,
            "command": argv,
            "cwd": str(cwd),
            "log_path": str(log_path),
            "details": details,
        }
        active = _ActiveRun(metadata=metadata)
        self.active[run_id] = active
        self._persist(metadata)
        active.task = asyncio.create_task(self._execute(active), name=f"kevlar-mcp-{run_id}")
        return self.summary(metadata)

    async def _execute(self, active: _ActiveRun) -> None:
        metadata = active.metadata
        run_id = metadata["run_id"]
        log_path = Path(metadata["log_path"])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if active.cancel_requested:
                metadata["status"] = "cancelled"
                return
            metadata["status"] = "running"
            metadata["started_at"] = _utc_now()
            self._persist(metadata)
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            active.process = await asyncio.create_subprocess_exec(
                *metadata["command"],
                cwd=metadata["cwd"],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                shell=False,
                creationflags=creationflags,
            )
            if active.cancel_requested:
                active.termination_succeeded = await self._terminate(active.process)

            reader = asyncio.create_task(
                self._capture_output(active.process, log_path, metadata["output_limit_bytes"])
            )
            timed_out = False
            try:
                await asyncio.wait_for(active.process.wait(), timeout=metadata["timeout_seconds"])
            except TimeoutError:
                timed_out = True
                active.termination_succeeded = await self._terminate(active.process)
            try:
                output_bytes, truncated = await asyncio.wait_for(reader, timeout=5)
            except TimeoutError:
                reader.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await reader
                output_bytes, truncated = log_path.stat().st_size if log_path.exists() else 0, True

            metadata["output_bytes"] = output_bytes
            metadata["output_truncated"] = truncated
            metadata["return_code"] = active.process.returncode
            if metadata["kind"] == "driver" and log_path.exists():
                text = log_path.read_text(encoding="utf-8", errors="replace")
                dll_success = "DllMain completed successfully" in text
                driver_success = "DriverEntry returned: 0x0" in text
                lifecycle = next((line for line in text.splitlines() if "[LIFECYCLE]" in line), "")
                nonempty_lifecycle = bool(lifecycle) and not all(
                    token in lifecycle
                    for token in (
                        "add_device=0x0", "unload=0x0", "device=0x0",
                        "dispatch=0", "tracked_devices=0", "ps=0/0/0",
                        "ob=0", "cm=0", "flt=0",
                    )
                )
                metadata["details"]["entry_success"] = dll_success or driver_success
                metadata["details"]["lifecycle_nonempty"] = nonempty_lifecycle
                metadata["details"]["emulation_complete"] = (
                    (dll_success or (driver_success and nonempty_lifecycle))
                    and not metadata["details"].get("analysis_only", False)
                )
            if active.cancel_requested:
                metadata["status"] = (
                    "cancelled" if active.termination_succeeded is not False
                    else "termination_failed"
                )
            elif timed_out:
                metadata["status"] = (
                    "timed_out" if active.termination_succeeded is not False
                    else "termination_failed"
                )
            elif active.process.returncode == 0:
                metadata["status"] = (
                    "analysis_only" if metadata["details"].get("analysis_only", False)
                    else "succeeded"
                )
            else:
                metadata["status"] = "failed"
        except asyncio.CancelledError:
            metadata["status"] = "cancelled"
            raise
        except Exception as exc:
            metadata["status"] = (
                "termination_failed"
                if active.cancel_requested and active.termination_succeeded is False
                else ("cancelled" if active.cancel_requested else "failed")
            )
            metadata["details"] = {**metadata["details"], "error": f"{type(exc).__name__}: {exc}"}
            message = f"MCP launcher error: {type(exc).__name__}: {exc}\n".encode("utf-8", errors="replace")
            try:
                with log_path.open("ab") as stream:
                    remaining = max(0, metadata["output_limit_bytes"] - stream.tell())
                    stream.write(message[:remaining])
                metadata["output_bytes"] = log_path.stat().st_size
                metadata["output_truncated"] = len(message) > remaining
            except OSError:
                pass
        finally:
            metadata["completed_at"] = _utc_now()
            self._persist(metadata)
            self.active.pop(run_id, None)

    async def _capture_output(
        self, process: asyncio.subprocess.Process, log_path: Path, limit: int
    ) -> tuple[int, bool]:
        assert process.stdout is not None
        written = 0
        truncated = False
        with log_path.open("wb") as stream:
            while True:
                chunk = await process.stdout.read(64 * 1024)
                if not chunk:
                    break
                remaining = limit - written
                if remaining > 0:
                    portion = chunk[:remaining]
                    stream.write(portion)
                    stream.flush()
                    written += len(portion)
                if len(chunk) > max(remaining, 0):
                    truncated = True
        return written, truncated

    async def _terminate(self, process: asyncio.subprocess.Process) -> bool:
        if process.returncode is not None:
            return True
        tree_killed = os.name != "nt"
        if os.name == "nt" and process.pid:
            try:
                killer = await asyncio.create_subprocess_exec(
                    "taskkill.exe",
                    "/PID",
                    str(process.pid),
                    "/T",
                    "/F",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    shell=False,
                )
                await asyncio.wait_for(killer.wait(), timeout=5)
                tree_killed = killer.returncode == 0
            except (OSError, TimeoutError):
                tree_killed = False
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except (ProcessLookupError, TimeoutError):
            return False
        return tree_killed and process.returncode is not None

    async def cancel(self, run_id: str) -> CancelResult:
        active = self.active.get(run_id)
        if active is None:
            return CancelResult(cancelled=False, run=self.get(run_id))
        active.cancel_requested = True
        active.metadata["status"] = "cancelling"
        self._persist(active.metadata)
        if active.process is not None:
            active.termination_succeeded = await self._terminate(active.process)
        if active.task is not None:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(asyncio.shield(active.task), timeout=10)
        run = self.get(run_id)
        return CancelResult(cancelled=run.status == "cancelled", run=run)

    async def shutdown(self) -> None:
        active_runs = list(self.active.values())
        for active in active_runs:
            active.cancel_requested = True
            active.metadata["status"] = "cancelling"
            self._persist(active.metadata)
        await asyncio.gather(
            *(self._terminate(active.process) for active in active_runs if active.process is not None),
            return_exceptions=True,
        )
        tasks = [active.task for active in active_runs if active.task is not None]
        if tasks:
            _, pending = await asyncio.wait(tasks, timeout=10)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

    def read_log(self, run_id: str, offset: int, max_bytes: int) -> LogChunk:
        run = self.get(run_id)
        path = Path(run.log_path)
        total = path.stat().st_size if path.is_file() else 0
        start = min(offset, total)
        data = b""
        if path.is_file():
            with path.open("rb") as stream:
                stream.seek(start)
                data = stream.read(max_bytes)
        next_offset = start + len(data)
        return LogChunk(
            run=run,
            offset=start,
            next_offset=next_offset,
            total_bytes=total,
            eof=next_offset >= total and run.status in TERMINAL_STATUSES,
            text=data.decode("utf-8", errors="replace"),
        )


manager = RunManager(RUNS_ROOT)


@contextlib.asynccontextmanager
async def _server_lifespan(_: MCPServer[Any]):
    try:
        yield {}
    finally:
        await manager.shutdown()


server = MCPServer(
    name="kevlar",
    description="Bounded local build and driver-emulation tools for Kevlar.",
    instructions=(
        "Use inspect_driver before run_driver. All paths are confined to the Kevlar project, "
        r"C:\Program Files\Alea, or C:\Program Files\FACEIT AC. Long operations return a run ID; "
        "poll with read_run_log or list_runs, and stop them with cancel_run."
    ),
    lifespan=_server_lifespan,
)
@server.tool(structured_output=True)
async def inspect_driver(request: InspectDriverRequest) -> DriverInspection:
    """Inspect an allowlisted driver through a pinned, server-staged file copy."""
    staged, original, root = await asyncio.to_thread(
        _stage_allowed_file, request.path, suffix=".sys"
    )
    inspection = await asyncio.to_thread(_parse_driver, staged, root)
    return inspection.model_copy(update={"path": str(original)})


@server.tool(structured_output=True)
async def build_kevlar(request: BuildRequest) -> RunSummary:
    """Start a bounded Debug or Release build and return its persistent run record."""
    argv = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(PROJECT_ROOT / "build.ps1"),
        request.configuration,
    ]
    return manager.start(
        kind="build",
        argv=argv,
        cwd=PROJECT_ROOT,
        timeout_seconds=request.timeout_seconds,
        output_limit_bytes=request.output_limit_bytes,
        details={"configuration": request.configuration},
    )

@server.tool(structured_output=True)
async def run_driver(request: RunDriverRequest) -> RunSummary:
    """Run one staged driver; target compatibility is analysis-only and never proves full emulation."""
    driver, original_driver, allowed_root = await asyncio.to_thread(
        _stage_allowed_file, request.driver_path, suffix=".sys"
    )
    executable = _require_executable(request.configuration)
    argv = [str(executable), str(driver), "--no-pause", "--max-insns", str(request.max_insns)]
    switches = (
        (request.diagnostics, "--diag"),
        (request.module_reads, "--modreads"),
        (request.disable_seh, "--no-seh"),
        (request.vgk_override, "--vgk-override"),
        (request.devirtualize, "--devirt"),
        (request.strict_exports, "--strict-exports"),
        (request.provenance, "--provenance"),
        (request.workers_deep, "--workers-deep"),
        (request.eac_service_emu, "--eac-service-emu"),
        (request.inject_hypervideo, "--inject-hypervideo"),
        (request.target_compat, "--target-compat"),
    )
    argv.extend(flag for enabled, flag in switches if enabled)
    if not request.target_compat:
        argv.append("--no-target-compat")
    if request.profile is not None:
        argv.extend(("--profile", request.profile))
    if request.seed is not None:
        argv.extend(("--seed", str(request.seed)))
    if request.trace_path is not None:
        trace = _server_output_path(request.trace_path, "traces", ".trace")
        argv.extend(("--trace", str(trace)))
    if request.check_trace_path is not None:
        check, _, _ = await asyncio.to_thread(
            _stage_allowed_file, request.check_trace_path, maximum_bytes=MAX_OUTPUT_BYTES
        )
        argv.extend(("--check", str(check)))
    return manager.start(
        kind="driver",
        argv=argv,
        cwd=executable.parent,
        timeout_seconds=request.timeout_seconds,
        output_limit_bytes=request.output_limit_bytes,
        details={
            "configuration": request.configuration,
            "driver_path": str(original_driver),
            "staged_driver_path": str(driver),
            "allowed_root": str(allowed_root),
            "max_insns": request.max_insns,
            "analysis_only": request.target_compat,
            "target_compat": request.target_compat,
            "emulation_complete": False,
        },
    )


@server.tool(structured_output=True)
async def run_selftest(request: SelftestRequest) -> RunSummary:
    """Start KEVLAR's built-in host semantics self-test with bounded time and output."""
    executable = _require_executable(request.configuration)
    return manager.start(
        kind="selftest",
        argv=[str(executable), "--selftest", "--no-pause"],
        cwd=executable.parent,
        timeout_seconds=request.timeout_seconds,
        output_limit_bytes=request.output_limit_bytes,
        details={"configuration": request.configuration},
    )


@server.tool(structured_output=True)
async def generate_test_driver(request: GenerateDriverRequest) -> RunSummary:
    """Generate a minimal test .sys through the repository's fixed generator interface."""
    output = _server_output_path(request.output_path, "generated", ".sys")
    allowed_root = RUNS_ROOT
    if output.exists() and not request.overwrite:
        raise ValueError(f"output already exists and overwrite is false: {output}")
    generator = PROJECT_ROOT / "tests" / "make_test_driver.py"
    if not generator.is_file():
        raise ValueError(f"test driver generator does not exist: {generator}")
    if request.with_import and request.manual_map_only:
        raise ValueError("with_import and manual_map_only are mutually exclusive")
    argv = [sys.executable, str(generator), str(output)]
    switches = (
        (request.verify, "--verify"),
        (request.with_import, "--with-import"),
        (request.manual_map_only, "--manual-map-only"),
        (request.infinite_loop, "--infinite-loop"),
    )
    argv.extend(flag for enabled, flag in switches if enabled)
    return manager.start(
        kind="generate_test_driver",
        argv=argv,
        cwd=PROJECT_ROOT,
        timeout_seconds=request.timeout_seconds,
        output_limit_bytes=request.output_limit_bytes,
        details={"output_path": str(output), "allowed_root": str(allowed_root)},
    )


@server.tool(structured_output=True)
async def read_run_log(request: ReadLogRequest) -> LogChunk:
    """Read one bounded UTF-8 chunk from a persistent run log."""
    return await asyncio.to_thread(manager.read_log, request.run_id, request.offset, request.max_bytes)


@server.tool(structured_output=True)
async def list_runs(request: ListRunsRequest) -> RunList:
    """List recent persistent build, generation, self-test, and driver runs."""
    return RunList(runs=await asyncio.to_thread(manager.list, request.limit, request.status))


@server.tool(structured_output=True)
async def cancel_run(request: CancelRunRequest) -> CancelResult:
    """Cancel an active process tree by run ID; completed runs are left unchanged."""
    return await manager.cancel(request.run_id)

def _enforce_strict_tool_arguments() -> None:
    # MCPServer's generated outer argument model ignores extra keys by default.
    # The request models are already strict; make the protocol envelope strict too.
    for tool in server._tool_manager._tools.values():
        argument_model = tool.fn_metadata.arg_model
        argument_model.model_config["extra"] = "forbid"
        argument_model.model_rebuild(force=True)
        tool.parameters = argument_model.model_json_schema()


_enforce_strict_tool_arguments()


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
