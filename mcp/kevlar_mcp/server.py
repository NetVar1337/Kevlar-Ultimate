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
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Paths and hard limits
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUNS_ROOT = PROJECT_ROOT / "builds" / "mcp-runs"
INDEX_PATH = RUNS_ROOT / "runs-index.jsonl"

ALLOWED_ROOTS = (
    PROJECT_ROOT,
    Path(r"C:\Program Files\Alea"),
    Path(r"C:\Program Files\FACEIT AC"),
)

MAX_DRIVER_BYTES     = 512 * 1024 * 1024
MAX_ACTIVE_RUNS      = 4
MAX_TIMEOUT_SECONDS  = 3600
MAX_INSTRUCTIONS     = 1_000_000_000
MAX_OUTPUT_BYTES     = 4 * 1024 * 1024
MAX_LOG_READ_BYTES   = 64 * 1024
MIN_RUN_INTERVAL_S   = 2.0          # rate-limit: minimum seconds between run_driver calls

RUN_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
PID_MAP_RE = re.compile(r"^\d+=[\x20-\x7E]{1,15}$")   # <decimal>=<ascii 1-15 chars>

# KEVLAR log color-tag pattern: {CYN}, {RED}, {WHT}, {GRN}, {RESET}, etc.
_KEVLAR_TAG_RE = re.compile(r"\{[A-Z]{2,8}\}")

TERMINAL_STATUSES = {
    "succeeded", "failed", "timed_out", "cancelled", "interrupted",
    "analysis_only", "termination_failed",
}

Configuration = Literal["Debug", "Release"]
RunStatus = Literal[
    "queued", "running", "cancelling", "succeeded", "failed", "timed_out",
    "cancelled", "interrupted", "analysis_only", "termination_failed",
]


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class InspectDriverRequest(StrictModel):
    path: str = Field(min_length=1, max_length=4096,
                      description="Absolute path, or a path relative to the project root.")


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
    eos_pipe: bool = Field(default=False,
        description="Intercept EOS_AntiCheat_Server NtCreateFile paths with a synthetic named pipe.")
    target_compat: bool = Field(default=False,
        description="Analysis-only exact-version status normalization. Never counts as complete emulation.")
    inject_hypervideo: bool = False
    profile: str | None = Field(default=None, min_length=1, max_length=128)
    trace_path: str | None = Field(default=None, min_length=1, max_length=255,
        description="Trace file name stored under the server-owned MCP run directory.")
    check_trace_path: str | None = Field(default=None, min_length=1, max_length=4096)
    # --- new fields ---
    afl_bitmap: str | None = Field(default=None, min_length=1, max_length=255,
        description="File name (under run directory) for the 65536-byte AFL++ edge-coverage bitmap.")
    coverage_out: str | None = Field(default=None, min_length=1, max_length=255,
        description="File name (under run directory) to write the edge-coverage snapshot.")
    coverage_base: str | None = Field(default=None, min_length=1, max_length=4096,
        description="Path to a prior coverage snapshot to compare against.")
    json_out: bool = Field(default=False,
        description="Write a structured JSON analysis report (seh, cpuid, unmapped_reads, etc.) to the run directory.")
    pid_map: list[str] = Field(default_factory=list,
        description="PID→name entries in <decimal_pid>=<name_1-15_chars> format (repeatable).")
    override_status: list[str] = Field(default_factory=list,
        description="NTSTATUS remaps in 0xHEX=0xHEX format applied after DriverEntry returns (repeatable).")

    @field_validator("pid_map", mode="before")
    @classmethod
    def _validate_pid_map(cls, v: object) -> object:
        if not isinstance(v, list):
            raise ValueError("pid_map must be a list")
        for entry in v:
            if not isinstance(entry, str) or not PID_MAP_RE.fullmatch(entry):
                raise ValueError(
                    f"invalid pid_map entry {entry!r}: must be '<decimal_pid>=<ascii_name_1-15_chars>'"
                )
        return v

    @field_validator("override_status", mode="before")
    @classmethod
    def _validate_override_status(cls, v: object) -> object:
        if not isinstance(v, list):
            raise ValueError("override_status must be a list")
        pat = re.compile(r"^0x[0-9A-Fa-f]{1,8}=0x[0-9A-Fa-f]{1,8}$")
        for entry in v:
            if not isinstance(entry, str) or not pat.fullmatch(entry):
                raise ValueError(
                    f"invalid override_status entry {entry!r}: must be '0xHEX=0xHEX'"
                )
        return v


class SelftestRequest(StrictModel):
    configuration: Configuration = "Release"
    timeout_seconds: int = Field(default=300, ge=1, le=MAX_TIMEOUT_SECONDS)
    output_limit_bytes: int = Field(default=MAX_OUTPUT_BYTES, ge=1024, le=MAX_OUTPUT_BYTES)


class GenerateDriverRequest(StrictModel):
    output_path: str = Field(min_length=1, max_length=255,
        description="Generated .sys file name stored under the server-owned MCP run directory.")
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
    strip_tags: bool = Field(default=True,
        description="Strip KEVLAR color tags ({CYN}, {RED}, etc.) from the returned text.")


class ListRunsRequest(StrictModel):
    limit: int = Field(default=25, ge=1, le=100)
    status: RunStatus | None = None


class CancelRunRequest(StrictModel):
    run_id: str = Field(pattern=RUN_ID_RE.pattern)


class WaitRunRequest(StrictModel):
    run_id: str = Field(pattern=RUN_ID_RE.pattern)
    timeout_seconds: int = Field(default=300, ge=1, le=MAX_TIMEOUT_SECONDS)


class GetRunRequest(StrictModel):
    run_id: str = Field(pattern=RUN_ID_RE.pattern)


class SearchLogRequest(StrictModel):
    run_id: str = Field(pattern=RUN_ID_RE.pattern)
    pattern: str = Field(min_length=1, max_length=512,
        description="Python regex pattern to search for in the run log.")
    max_matches: int = Field(default=50, ge=1, le=500)
    strip_tags: bool = True


class PruneRunsRequest(StrictModel):
    older_than_days: int = Field(default=7, ge=1, le=365,
        description="Delete terminal runs whose completed_at is older than this many days.")
    status: RunStatus | None = Field(default=None,
        description="Only prune runs with this terminal status. None = all terminal statuses.")
    dry_run: bool = Field(default=True,
        description="When true, report what would be pruned without deleting anything.")


class DiffRunsRequest(StrictModel):
    run_id_a: str = Field(pattern=RUN_ID_RE.pattern)
    run_id_b: str = Field(pattern=RUN_ID_RE.pattern)


class ListStagedRequest(StrictModel):
    limit: int = Field(default=50, ge=1, le=200)


class CoverageSummaryRequest(StrictModel):
    run_id: str = Field(pattern=RUN_ID_RE.pattern,
        description="Run ID whose coverage_out snapshot to summarize.")
    top_n: int = Field(default=10, ge=1, le=100,
        description="Number of highest-hit edges to include in the summary.")


# ---------------------------------------------------------------------------
# Inspection models
# ---------------------------------------------------------------------------

class DriverSection(StrictModel):
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    characteristics_decoded: list[str]


class DriverImport(StrictModel):
    module: str
    functions: list[str]


class DriverExport(StrictModel):
    ordinal: int
    name: str | None
    rva: int


class DriverDebugInfo(StrictModel):
    type: int
    pdb_path: str | None
    guid: str | None
    age: int | None


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
    dll_characteristics_decoded: list[str]
    sections: list[DriverSection]
    imports: list[DriverImport]
    exports: list[DriverExport]
    debug_info: list[DriverDebugInfo]


# ---------------------------------------------------------------------------
# Run response models
# ---------------------------------------------------------------------------

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
    total: int


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


class WaitResult(StrictModel):
    run: RunSummary
    timed_out: bool


class SearchResult(StrictModel):
    run_id: str
    pattern: str
    matches: list[dict[str, Any]]    # [{line_number, byte_offset, text}]
    total_matches: int
    truncated: bool


class PruneResult(StrictModel):
    dry_run: bool
    pruned_count: int
    pruned_run_ids: list[str]
    bytes_freed: int


class RunDiff(StrictModel):
    run_id_a: str
    run_id_b: str
    status_changed: bool
    status_a: str
    status_b: str
    ntstatus_a: str | None
    ntstatus_b: str | None
    ntstatus_changed: bool
    entry_success_a: bool | None
    entry_success_b: bool | None
    emulation_complete_a: bool | None
    emulation_complete_b: bool | None
    lifecycle_nonempty_a: bool | None
    lifecycle_nonempty_b: bool | None
    seh_count_a: int | None
    seh_count_b: int | None
    new_edges: int | None
    details_delta: dict[str, Any]


class StagedInput(StrictModel):
    sha256: str
    name: str
    size_bytes: int
    staged_path: str


class StagedInputList(StrictModel):
    inputs: list[StagedInput]
    total: int


class EdgeSummary(StrictModel):
    from_module: str
    from_rva: int
    to_module: str
    to_rva: int
    hits: int


class CoverageSummary(StrictModel):
    run_id: str
    coverage_file: str
    total_edges: int
    total_hits: int
    top_edges: list[EdgeSummary]


# ---------------------------------------------------------------------------
# _ActiveRun
# ---------------------------------------------------------------------------

@dataclass
class _ActiveRun:
    metadata: dict[str, Any]
    task: asyncio.Task[None] | None = None
    process: asyncio.subprocess.Process | None = None
    cancel_requested: bool = False
    termination_succeeded: bool | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
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
    must_exist: bool = True,
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
    if requested.is_absolute() or ".." in requested.parts:
        raise ValueError("output_path must be a plain file name, not a path")
    if requested.suffix.casefold() != suffix.casefold():
        raise ValueError(f"output_path must end with {suffix}")
    root = RUNS_ROOT / directory
    root.mkdir(parents=True, exist_ok=True)
    return root / requested.name


def _require_driver(value: str) -> tuple[Path, Path]:
    path, root = resolve_allowed_path(value, must_exist=True, file_only=True)
    if path.suffix.casefold() != ".sys":
        raise ValueError(f"driver path must end with .sys: {path}")
    return path, root


def _require_executable(configuration: Configuration) -> Path:
    exe = PROJECT_ROOT / "builds" / configuration / "KEVLAR.exe"
    if not exe.is_file():
        raise ValueError(
            f"KEVLAR executable does not exist; build {configuration} first: {exe}"
        )
    return exe.resolve(strict=True)


def _strip_tags(text: str) -> str:
    """Remove KEVLAR color tags like {CYN}, {RED}, {RESET} from log text."""
    return _KEVLAR_TAG_RE.sub("", text)


# ---------------------------------------------------------------------------
# PE parsing helpers
# ---------------------------------------------------------------------------

_DLL_CHARS: list[tuple[int, str]] = [
    (0x0001, "RESERVED_1"),
    (0x0002, "RESERVED_2"),
    (0x0004, "RESERVED_4"),
    (0x0008, "RESERVED_8"),
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
]

_SEC_CHARS: list[tuple[int, str]] = [
    (0x00000020, "CNT_CODE"),
    (0x00000040, "CNT_INITIALIZED_DATA"),
    (0x00000080, "CNT_UNINITIALIZED_DATA"),
    (0x00000200, "LNK_INFO"),
    (0x00000800, "LNK_REMOVE"),
    (0x00001000, "LNK_COMDAT"),
    (0x00004000, "NO_DEFER_SPEC_EXC"),
    (0x00008000, "GPREL"),
    (0x01000000, "LNK_NRELOC_OVFL"),
    (0x02000000, "MEM_DISCARDABLE"),
    (0x04000000, "MEM_NOT_CACHED"),
    (0x08000000, "MEM_NOT_PAGED"),
    (0x10000000, "MEM_SHARED"),
    (0x20000000, "MEM_EXECUTE"),
    (0x40000000, "MEM_READ"),
    (0x80000000, "MEM_WRITE"),
]


def _decode_flags(value: int, table: list[tuple[int, str]]) -> list[str]:
    return [name for mask, name in table if value & mask]


def _parse_driver(path: Path, root: Path) -> DriverInspection:  # noqa: C901
    size = path.stat().st_size
    digest = hashlib.sha256()
    raw = path.read_bytes()
    for i in range(0, len(raw), 1024 * 1024):
        digest.update(raw[i:i + 1024 * 1024])

    # --- DOS / COFF / Optional ---
    if len(raw) < 64 or raw[:2] != b"MZ":
        raise ValueError("driver is not a PE image (missing MZ header)")
    pe_offset = struct.unpack_from("<I", raw, 0x3C)[0]
    if pe_offset < 64 or pe_offset > min(size - 24, 16 * 1024 * 1024):
        raise ValueError("driver has an invalid PE header offset")
    if raw[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("driver is not a PE image (missing PE signature)")
    coff_off = pe_offset + 4
    machine, section_count, timestamp, _, _, optional_size, _ = struct.unpack_from(
        "<HHIIIHH", raw, coff_off
    )
    if section_count == 0 or section_count > 96:
        raise ValueError("driver has an invalid section count")
    if optional_size < 72 or optional_size > 4096:
        raise ValueError("driver has an invalid optional header size")
    opt_off = coff_off + 20
    magic = struct.unpack_from("<H", raw, opt_off)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", raw, opt_off + 24)[0]
        architecture = "x64" if machine == 0x8664 else "unknown"
        num_data_dirs = struct.unpack_from("<I", raw, opt_off + 92)[0]
        data_dir_off = opt_off + 96
    elif magic == 0x10B:
        image_base = struct.unpack_from("<I", raw, opt_off + 28)[0]
        architecture = "x86" if machine == 0x14C else "unknown"
        num_data_dirs = struct.unpack_from("<I", raw, opt_off + 92)[0]
        data_dir_off = opt_off + 96
    else:
        raise ValueError(f"unsupported PE optional header magic: 0x{magic:04x}")
    entry_point  = struct.unpack_from("<I", raw, opt_off + 16)[0]
    size_of_image = struct.unpack_from("<I", raw, opt_off + 56)[0]
    subsystem, dll_chars = struct.unpack_from("<HH", raw, opt_off + 68)

    def _data_dir(idx: int) -> tuple[int, int]:
        off = data_dir_off + idx * 8
        if idx >= num_data_dirs or off + 8 > len(raw):
            return 0, 0
        return struct.unpack_from("<II", raw, off)

    def _rva_to_offset(rva: int) -> int | None:
        """Convert a virtual RVA to a file offset using the section table."""
        sec_table_off = opt_off + optional_size
        for i in range(section_count):
            s = sec_table_off + i * 40
            if s + 40 > len(raw):
                break
            s_va, s_vsz, s_raw_off, s_raw_sz = struct.unpack_from("<IIII", raw, s + 12)
            if s_va <= rva < s_va + max(s_vsz, s_raw_sz):
                return s_raw_off + (rva - s_va)
        return None

    # --- Sections ---
    sec_table_off = opt_off + optional_size
    sections: list[DriverSection] = []
    for i in range(section_count):
        s = sec_table_off + i * 40
        if s + 40 > len(raw):
            raise ValueError("driver has a truncated section table")
        raw_name, s_vsz, s_va, s_raw_sz, s_raw_off, _, _, _, _, s_chars = struct.unpack_from(
            "<8sIIIIIIHHI", raw, s
        )
        name = raw_name.split(b"\0", 1)[0].decode("ascii", errors="replace")
        if s_raw_sz and (s_raw_off > size or s_raw_sz > size - s_raw_off):
            raise ValueError(f"section {name!r} extends beyond the driver image")
        sections.append(DriverSection(
            name=name,
            virtual_address=s_va,
            virtual_size=s_vsz,
            raw_offset=s_raw_off,
            raw_size=s_raw_sz,
            characteristics=s_chars,
            characteristics_decoded=_decode_flags(s_chars, _SEC_CHARS),
        ))

    # --- Imports ---
    imports: list[DriverImport] = []
    imp_rva, imp_size = _data_dir(1)
    if imp_rva and imp_size:
        off = _rva_to_offset(imp_rva)
        if off is not None:
            pos = off
            while pos + 20 <= len(raw):
                orig_first_thunk, ts, forwarder, name_rva, first_thunk = struct.unpack_from(
                    "<IIIII", raw, pos
                )
                pos += 20
                if orig_first_thunk == 0 and name_rva == 0:
                    break
                mod_off = _rva_to_offset(name_rva)
                if mod_off is None:
                    continue
                end = raw.find(b"\0", mod_off)
                mod_name = raw[mod_off:end].decode("ascii", errors="replace") if end != -1 else ""
                thunk_rva = orig_first_thunk or first_thunk
                thunk_off = _rva_to_offset(thunk_rva) if thunk_rva else None
                funcs: list[str] = []
                if thunk_off is not None:
                    t = thunk_off
                    is64 = magic == 0x20B
                    entry_sz = 8 if is64 else 4
                    ordinal_flag = 0x8000000000000000 if is64 else 0x80000000
                    while t + entry_sz <= len(raw):
                        val = struct.unpack_from("<Q" if is64 else "<I", raw, t)[0]
                        t += entry_sz
                        if val == 0:
                            break
                        if val & ordinal_flag:
                            funcs.append(f"#{val & 0xFFFF}")
                        else:
                            hint_off = _rva_to_offset(val & 0x7FFFFFFFFFFFFFFF)
                            if hint_off is not None and hint_off + 2 < len(raw):
                                fn_end = raw.find(b"\0", hint_off + 2)
                                fn = raw[hint_off + 2:fn_end].decode("ascii", errors="replace") if fn_end != -1 else "?"
                                funcs.append(fn)
                if mod_name:
                    imports.append(DriverImport(module=mod_name, functions=funcs[:256]))

    # --- Exports ---
    exports: list[DriverExport] = []
    exp_rva, exp_size = _data_dir(0)
    if exp_rva and exp_size:
        off = _rva_to_offset(exp_rva)
        if off is not None and off + 40 <= len(raw):
            _, _, _, _, _, num_funcs, num_names, fn_rva_off_rva, name_ptr_rva, ord_tbl_rva = struct.unpack_from(
                "<IIIIIIIIII", raw, off
            )
            fn_off  = _rva_to_offset(fn_rva_off_rva)  if fn_rva_off_rva  else None
            np_off  = _rva_to_offset(name_ptr_rva)     if name_ptr_rva    else None
            ord_off = _rva_to_offset(ord_tbl_rva)      if ord_tbl_rva     else None
            name_map: dict[int, str] = {}
            if np_off is not None and ord_off is not None:
                for i in range(min(num_names, 4096)):
                    if np_off + i * 4 + 4 > len(raw) or ord_off + i * 2 + 2 > len(raw):
                        break
                    n_rva = struct.unpack_from("<I", raw, np_off + i * 4)[0]
                    ordinal = struct.unpack_from("<H", raw, ord_off + i * 2)[0]
                    n_off = _rva_to_offset(n_rva)
                    if n_off is not None:
                        n_end = raw.find(b"\0", n_off)
                        name_map[ordinal] = raw[n_off:n_end].decode("ascii", errors="replace") if n_end != -1 else "?"
            if fn_off is not None:
                for i in range(min(num_funcs, 4096)):
                    if fn_off + i * 4 + 4 > len(raw):
                        break
                    fn_rva = struct.unpack_from("<I", raw, fn_off + i * 4)[0]
                    exports.append(DriverExport(
                        ordinal=i,
                        name=name_map.get(i),
                        rva=fn_rva,
                    ))

    # --- Debug / PDB ---
    debug_info: list[DriverDebugInfo] = []
    dbg_rva, dbg_size = _data_dir(6)
    if dbg_rva and dbg_size:
        off = _rva_to_offset(dbg_rva)
        if off is not None:
            entry_count = dbg_size // 28
            for i in range(min(entry_count, 16)):
                de = off + i * 28
                if de + 28 > len(raw):
                    break
                dbg_type, dbg_data_size, dbg_rva2, dbg_raw_off = struct.unpack_from("<IIII", raw, de + 12)
                pdb_path: str | None = None
                guid_str: str | None = None
                age_val: int | None = None
                if dbg_type == 2 and dbg_data_size >= 24:  # IMAGE_DEBUG_TYPE_CODEVIEW
                    cv_off = dbg_raw_off if dbg_raw_off else (_rva_to_offset(dbg_rva2) or 0)
                    if cv_off and cv_off + 4 <= len(raw):
                        sig = raw[cv_off:cv_off + 4]
                        if sig == b"RSDS" and cv_off + 24 <= len(raw):
                            g = raw[cv_off + 4:cv_off + 20]
                            age_val = struct.unpack_from("<I", raw, cv_off + 20)[0]
                            pdb_end = raw.find(b"\0", cv_off + 24)
                            pdb_path = raw[cv_off + 24:pdb_end].decode("utf-8", errors="replace") if pdb_end != -1 else None
                            guid_str = (
                                f"{g[0:4][::-1].hex()}-{g[4:6][::-1].hex()}-"
                                f"{g[6:8][::-1].hex()}-{g[8:10].hex()}-{g[10:16].hex()}"
                            ).upper()
                debug_info.append(DriverDebugInfo(
                    type=dbg_type,
                    pdb_path=pdb_path,
                    guid=guid_str,
                    age=age_val,
                ))

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
        dll_characteristics=dll_chars,
        dll_characteristics_decoded=_decode_flags(dll_chars, _DLL_CHARS),
        sections=sections,
        imports=imports,
        exports=exports,
        debug_info=debug_info,
    )


def _parse_coverage_file(path: Path) -> list[tuple[str, int, str, int, int]]:
    """Parse a .cov snapshot: each line is module_from:rva_from->module_to:rva_to:hits"""
    results = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            left, right = line.split("->", 1)
            li = left.rfind(":")
            ri = right.rfind(":")
            ri2 = right.rfind(":", 0, ri)
            mod_from = left[:li]
            rva_from = int(left[li + 1:], 16)
            mod_to = right[:ri2]
            rva_to = int(right[ri2 + 1:ri], 16)
            hits = int(right[ri + 1:])
            results.append((mod_from, rva_from, mod_to, rva_to, hits))
        except (ValueError, IndexError):
            continue
    return results


# ---------------------------------------------------------------------------
# RunManager
# ---------------------------------------------------------------------------

class RunManager:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.active: dict[str, _ActiveRun] = {}
        self._last_run_time: float = 0.0
        self._mark_interrupted_runs()
        self._rebuild_index_if_missing()

    # ---- index ----

    def _append_index(self, metadata: dict[str, Any]) -> None:
        record = {
            "run_id":       metadata["run_id"],
            "kind":         metadata["kind"],
            "status":       metadata["status"],
            "created_at":   metadata["created_at"],
            "completed_at": metadata.get("completed_at"),
        }
        try:
            with INDEX_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except OSError:
            pass

    def _update_index(self, run_id: str, status: str, completed_at: str | None) -> None:
        """Rewrite the last matching index entry for this run_id with updated status."""
        try:
            if not INDEX_PATH.is_file():
                return
            lines = INDEX_PATH.read_text(encoding="utf-8").splitlines()
            updated = []
            found = False
            for line in reversed(lines):
                if not found:
                    try:
                        rec = json.loads(line)
                        if rec.get("run_id") == run_id:
                            rec["status"] = status
                            rec["completed_at"] = completed_at
                            updated.insert(0, json.dumps(rec))
                            found = True
                            continue
                    except (json.JSONDecodeError, KeyError):
                        pass
                updated.insert(0, line)
            tmp = INDEX_PATH.with_suffix(".jsonl.tmp")
            tmp.write_text("\n".join(updated) + "\n", encoding="utf-8")
            os.replace(tmp, INDEX_PATH)
        except OSError:
            pass

    def _rebuild_index_if_missing(self) -> None:
        if INDEX_PATH.is_file():
            return
        records = []
        for p in self.root.glob("*/metadata.json"):
            try:
                m = json.loads(p.read_text(encoding="utf-8"))
                records.append({
                    "run_id":       m["run_id"],
                    "kind":         m["kind"],
                    "status":       m["status"],
                    "created_at":   m["created_at"],
                    "completed_at": m.get("completed_at"),
                })
            except (OSError, json.JSONDecodeError, KeyError):
                continue
        records.sort(key=lambda r: r["created_at"])
        try:
            INDEX_PATH.write_text(
                "\n".join(json.dumps(r) for r in records) + ("\n" if records else ""),
                encoding="utf-8",
            )
        except OSError:
            pass

    # ---- core ----

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
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"run metadata is unreadable: {run_id}") from exc

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

    def list(self, limit: int, status: RunStatus | None) -> tuple[list[RunSummary], int]:
        """O(1) listing from the JSONL index; falls back to glob scan if index is missing."""
        records: list[RunSummary] = []
        seen: set[str] = set()
        total = 0
        try:
            if INDEX_PATH.is_file():
                lines = INDEX_PATH.read_text(encoding="utf-8").splitlines()
                for line in reversed(lines):
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                        run_id = rec["run_id"]
                        if run_id in seen:
                            continue
                        seen.add(run_id)
                        if status is None or rec.get("status") == status:
                            total += 1
                            if len(records) < limit:
                                # Hydrate from active dict or metadata file
                                active = self.active.get(run_id)
                                if active:
                                    records.append(self.summary(active.metadata))
                                else:
                                    meta_path = self._metadata_path(run_id)
                                    if meta_path.is_file():
                                        try:
                                            records.append(self.summary(json.loads(meta_path.read_text(encoding="utf-8"))))
                                        except (OSError, json.JSONDecodeError):
                                            pass
                    except (json.JSONDecodeError, KeyError):
                        continue
                return records, total
        except OSError:
            pass
        # Fallback: glob scan
        for metadata_path in self.root.glob("*/metadata.json"):
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                if status is None or metadata.get("status") == status:
                    records.append(self.summary(metadata))
                    total += 1
            except (OSError, ValueError, json.JSONDecodeError):
                continue
        records.sort(key=lambda item: (item.created_at, item.run_id), reverse=True)
        return records[:limit], total

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
        # Rate limiting for driver runs
        if kind == "driver":
            now = time.monotonic()
            elapsed = now - self._last_run_time
            if elapsed < MIN_RUN_INTERVAL_S:
                raise ValueError(
                    f"rate limit: wait {MIN_RUN_INTERVAL_S - elapsed:.1f}s before starting another run"
                )
            self._last_run_time = now
        # Enforce --no-pause for all runs (never hang waiting for a keypress)
        argv_final = list(argv)
        if "--no-pause" not in argv_final:
            argv_final.append("--no-pause")
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12]
        run_dir = self._run_dir(run_id)
        log_path = run_dir / "run.log"
        metadata: dict[str, Any] = {
            "run_id":             run_id,
            "kind":               kind,
            "status":             "queued",
            "created_at":         _utc_now(),
            "started_at":         None,
            "completed_at":       None,
            "timeout_seconds":    timeout_seconds,
            "output_limit_bytes": output_limit_bytes,
            "output_bytes":       0,
            "output_truncated":   False,
            "return_code":        None,
            "command":            argv_final,
            "cwd":                str(cwd),
            "log_path":           str(log_path),
            "details":            details,
        }
        active = _ActiveRun(metadata=metadata)
        self.active[run_id] = active
        self._persist(metadata)
        self._append_index(metadata)
        active.task = asyncio.create_task(self._execute(active), name=f"kevlar-mcp-{run_id}")
        return self.summary(metadata)

    async def _execute(self, active: _ActiveRun) -> None:  # noqa: C901
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
                stdin=asyncio.subprocess.DEVNULL,
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
                output_bytes = log_path.stat().st_size if log_path.exists() else 0
                truncated = True

            metadata["output_bytes"] = output_bytes
            metadata["output_truncated"] = truncated
            metadata["return_code"] = active.process.returncode

            # --- Structured result extraction ---
            if metadata["kind"] == "driver" and log_path.exists():
                text = log_path.read_text(encoding="utf-8", errors="replace")
                dll_success    = "DllMain completed successfully" in text
                driver_success = "DriverEntry returned: 0x0" in text
                lifecycle = next(
                    (line for line in text.splitlines() if "[LIFECYCLE]" in line), ""
                )
                nonempty_lifecycle = bool(lifecycle) and not all(
                    token in lifecycle for token in (
                        "add_device=0x0", "unload=0x0", "device=0x0",
                        "dispatch=0", "tracked_devices=0", "ps=0/0/0",
                        "ob=0", "cm=0", "flt=0",
                    )
                )
                metadata["details"]["entry_success"]      = dll_success or driver_success
                metadata["details"]["lifecycle_nonempty"] = nonempty_lifecycle
                metadata["details"]["emulation_complete"] = (
                    (dll_success or (driver_success and nonempty_lifecycle))
                    and not metadata["details"].get("analysis_only", False)
                )
                # Extract NTSTATUS from log
                for line in text.splitlines():
                    if "DriverEntry returned:" in line:
                        m = re.search(r"0x([0-9A-Fa-f]+)", line)
                        if m:
                            metadata["details"]["ntstatus"] = "0x" + m.group(1).upper().zfill(8)
                        break
                # Pull SEH count from diagnostics if present
                for line in text.splitlines():
                    m = re.search(r"SEH events recorded[:\s]+(\d+)", line, re.IGNORECASE)
                    if m:
                        metadata["details"]["seh_count"] = int(m.group(1))
                        break
                # Parse --json-out file if it was requested
                json_out_path = metadata["details"].get("json_out_path")
                if json_out_path and Path(json_out_path).is_file():
                    try:
                        jr = json.loads(Path(json_out_path).read_text(encoding="utf-8"))
                        metadata["details"]["json_report_summary"] = {
                            "seh_events":      len(jr.get("seh", [])),
                            "mem_probes":      len(jr.get("mem_probes", [])),
                            "cpuid_events":    len(jr.get("cpuid", [])),
                            "unmapped_reads":  len(jr.get("unmapped_reads", [])),
                            "consistency":     len(jr.get("consistency", [])),
                        }
                    except (OSError, json.JSONDecodeError):
                        pass

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
                    "analysis_only"
                    if metadata["details"].get("analysis_only", False)
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
            self._update_index(metadata["run_id"], metadata["status"], metadata["completed_at"])
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
                    "taskkill.exe", "/PID", str(process.pid), "/T", "/F",
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

    async def wait_for_run(self, run_id: str, timeout_seconds: int) -> WaitResult:
        active = self.active.get(run_id)
        if active is None:
            # Already terminal
            return WaitResult(run=self.get(run_id), timed_out=False)
        if active.task is not None:
            timed_out = False
            try:
                await asyncio.wait_for(asyncio.shield(active.task), timeout=timeout_seconds)
            except TimeoutError:
                timed_out = True
            return WaitResult(run=self.get(run_id), timed_out=timed_out)
        return WaitResult(run=self.get(run_id), timed_out=False)

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

    def read_log(self, run_id: str, offset: int, max_bytes: int, strip_tags: bool = True) -> LogChunk:
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
        text = data.decode("utf-8", errors="replace")
        if strip_tags:
            text = _strip_tags(text)
        return LogChunk(
            run=run,
            offset=start,
            next_offset=next_offset,
            total_bytes=total,
            eof=next_offset >= total and run.status in TERMINAL_STATUSES,
            text=text,
        )

    def search_log(self, run_id: str, pattern: str, max_matches: int, strip_tags: bool) -> SearchResult:
        run = self.get(run_id)
        path = Path(run.log_path)
        compiled = re.compile(pattern)
        matches: list[dict[str, Any]] = []
        total = 0
        byte_offset = 0
        if path.is_file():
            with path.open("rb") as f:
                for lineno, raw_line in enumerate(f, 1):
                    line = raw_line.decode("utf-8", errors="replace")
                    if strip_tags:
                        line = _strip_tags(line)
                    if compiled.search(line):
                        total += 1
                        if len(matches) < max_matches:
                            matches.append({
                                "line_number":  lineno,
                                "byte_offset":  byte_offset,
                                "text":         line.rstrip("\n"),
                            })
                    byte_offset += len(raw_line)
        return SearchResult(
            run_id=run_id,
            pattern=pattern,
            matches=matches,
            total_matches=total,
            truncated=total > max_matches,
        )

    def prune(self, older_than_days: int, status: RunStatus | None, dry_run: bool) -> PruneResult:
        now = datetime.now(UTC)
        pruned_ids: list[str] = []
        bytes_freed = 0
        for metadata_path in list(self.root.glob("*/metadata.json")):
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                run_id = metadata["run_id"]
                if run_id in self.active:
                    continue
                run_status = metadata.get("status", "")
                if run_status not in TERMINAL_STATUSES:
                    continue
                if status is not None and run_status != status:
                    continue
                completed_at_str = metadata.get("completed_at")
                if not completed_at_str:
                    continue
                completed_at = datetime.fromisoformat(completed_at_str)
                age_days = (now - completed_at).days
                if age_days < older_than_days:
                    continue
                run_dir = metadata_path.parent
                dir_bytes = sum(
                    f.stat().st_size for f in run_dir.rglob("*") if f.is_file()
                )
                pruned_ids.append(run_id)
                bytes_freed += dir_bytes
                if not dry_run:
                    shutil.rmtree(run_dir, ignore_errors=True)
            except (OSError, json.JSONDecodeError, KeyError, ValueError):
                continue
        if not dry_run and pruned_ids:
            self._rebuild_index_if_missing()
            # Regenerate index excluding pruned runs
            try:
                if INDEX_PATH.is_file():
                    pruned_set = set(pruned_ids)
                    lines = INDEX_PATH.read_text(encoding="utf-8").splitlines()
                    kept = [l for l in lines if l.strip() and json.loads(l).get("run_id") not in pruned_set]
                    INDEX_PATH.write_text("\n".join(kept) + "\n", encoding="utf-8")
            except (OSError, json.JSONDecodeError):
                pass
        return PruneResult(
            dry_run=dry_run,
            pruned_count=len(pruned_ids),
            pruned_run_ids=pruned_ids,
            bytes_freed=bytes_freed,
        )


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

manager = RunManager(RUNS_ROOT)


@contextlib.asynccontextmanager
async def _server_lifespan(_: MCPServer[Any]):
    try:
        yield
    finally:
        await manager.shutdown()


server = MCPServer(
    "kevlar",
    instructions=(
        "KEVLAR MCP: run_driver to emulate a .sys, read_run_log / wait_run / search_run_log "
        "for results, inspect_driver for static PE analysis, get_coverage_summary for edge "
        "coverage, diff_runs for regression detection. All paths must be inside the project "
        "root or C:\\Program Files\\{Alea,FACEIT AC}. Call inspect_driver before run_driver."
    ),
    lifespan=_server_lifespan,
)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@server.tool(structured_output=True)
async def inspect_driver(request: InspectDriverRequest) -> DriverInspection:
    """Inspect an allowlisted driver: PE header, sections, imports, exports, PDB path, decoded flags."""
    staged, original, root = await asyncio.to_thread(
        _stage_allowed_file, request.path, suffix=".sys"
    )
    inspection = await asyncio.to_thread(_parse_driver, staged, root)
    return inspection.model_copy(update={"path": str(original)})


@server.tool(structured_output=True)
async def build_kevlar(request: BuildRequest) -> RunSummary:
    """Start a bounded Debug or Release build and return its persistent run record."""
    argv = [
        "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", str(PROJECT_ROOT / "build.ps1"),
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
    """Run one staged driver with full option surface. Returns immediately; use wait_run to block."""
    driver, original_driver, allowed_root = await asyncio.to_thread(
        _stage_allowed_file, request.driver_path, suffix=".sys"
    )
    executable = _require_executable(request.configuration)
    run_id_preview = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ-") + "preview"
    run_dir = RUNS_ROOT / run_id_preview
    # Build argv
    argv = [str(executable), str(driver), "--no-pause", "--max-insns", str(request.max_insns)]
    switches = (
        (request.diagnostics,       "--diag"),
        (request.module_reads,      "--modreads"),
        (request.disable_seh,       "--no-seh"),
        (request.vgk_override,      "--vgk-override"),
        (request.devirtualize,      "--devirt"),
        (request.strict_exports,    "--strict-exports"),
        (request.provenance,        "--provenance"),
        (request.workers_deep,      "--workers-deep"),
        (request.eac_service_emu,   "--eac-service-emu"),
        (request.eos_pipe,          "--eos-pipe"),
        (request.inject_hypervideo, "--inject-hypervideo"),
        (request.target_compat,     "--target-compat"),
    )
    argv.extend(flag for enabled, flag in switches if enabled)
    if not request.target_compat:
        argv.append("--no-target-compat")
    if request.profile is not None:
        argv.extend(("--profile", request.profile))
    if request.seed is not None:
        argv.extend(("--seed", str(request.seed)))
    for entry in request.pid_map:
        argv.extend(("--pid-map", entry))
    for entry in request.override_status:
        argv.extend(("--override-status", entry))
    if request.trace_path is not None:
        trace = _server_output_path(request.trace_path, "traces", ".trace")
        argv.extend(("--trace", str(trace)))
    if request.check_trace_path is not None:
        # Validate that check_trace_path is a server-owned trace file
        check_path = Path(request.check_trace_path)
        if not check_path.is_absolute():
            check_path = RUNS_ROOT / "traces" / check_path
        check_path = check_path.resolve()
        if not _inside(check_path, RUNS_ROOT):
            raise ValueError("check_trace_path must reference a server-owned trace file under builds/mcp-runs/")
        if not check_path.is_file():
            raise ValueError(f"check_trace_path does not exist: {check_path}")
        argv.extend(("--check", str(check_path)))
    details: dict[str, Any] = {
        "configuration":     request.configuration,
        "driver_path":       str(original_driver),
        "staged_driver_path": str(driver),
        "allowed_root":      str(allowed_root),
        "max_insns":         request.max_insns,
        "analysis_only":     request.target_compat,
        "target_compat":     request.target_compat,
        "emulation_complete": False,
        "eos_pipe":          request.eos_pipe,
        "pid_map":           list(request.pid_map),
        "override_status":   list(request.override_status),
    }
    # AFL bitmap / coverage outputs (server-owned paths, injected after run_id is known)
    # We store the *intended* file names; the actual paths are resolved inside start()
    if request.afl_bitmap is not None:
        details["afl_bitmap_name"] = request.afl_bitmap
    if request.coverage_out is not None:
        details["coverage_out_name"] = request.coverage_out
    if request.coverage_base is not None:
        details["coverage_base"] = request.coverage_base
    if request.json_out:
        details["json_out_requested"] = True

    # Start — then patch argv with resolved per-run paths for bitmap/coverage/json
    summary = manager.start(
        kind="driver",
        argv=argv,
        cwd=executable.parent,
        timeout_seconds=request.timeout_seconds,
        output_limit_bytes=request.output_limit_bytes,
        details=details,
    )
    # Now that the run_id is known, build the real server-owned output paths and patch argv
    actual_run = manager.active.get(summary.run_id)
    if actual_run:
        run_dir_real = manager._run_dir(summary.run_id)
        run_dir_real.mkdir(parents=True, exist_ok=True)
        extra: list[str] = []
        if request.afl_bitmap is not None:
            bm = run_dir_real / Path(request.afl_bitmap).name
            extra.extend(("--afl-bitmap", str(bm)))
            actual_run.metadata["details"]["afl_bitmap_path"] = str(bm)
        if request.coverage_out is not None:
            co = run_dir_real / Path(request.coverage_out).name
            extra.extend(("--coverage-out", str(co)))
            actual_run.metadata["details"]["coverage_out_path"] = str(co)
        if request.coverage_base is not None:
            cb_path, _, _ = await asyncio.to_thread(
                _stage_allowed_file, request.coverage_base, maximum_bytes=MAX_OUTPUT_BYTES
            )
            extra.extend(("--coverage-base", str(cb_path)))
            actual_run.metadata["details"]["coverage_base_path"] = str(cb_path)
        if request.json_out:
            jo = run_dir_real / "report.json"
            extra.extend(("--json-out", str(jo)))
            actual_run.metadata["details"]["json_out_path"] = str(jo)
        if extra:
            actual_run.metadata["command"].extend(extra)
            manager._persist(actual_run.metadata)
    return summary


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
    if output.exists() and not request.overwrite:
        raise ValueError(f"output already exists and overwrite is false: {output}")
    generator = PROJECT_ROOT / "tests" / "make_test_driver.py"
    if not generator.is_file():
        raise ValueError(f"test driver generator does not exist: {generator}")
    if request.with_import and request.manual_map_only:
        raise ValueError("with_import and manual_map_only are mutually exclusive")
    argv = [sys.executable, str(generator), str(output)]
    switches = (
        (request.verify,          "--verify"),
        (request.with_import,     "--with-import"),
        (request.manual_map_only, "--manual-map-only"),
        (request.infinite_loop,   "--infinite-loop"),
    )
    argv.extend(flag for enabled, flag in switches if enabled)
    return manager.start(
        kind="generate_test_driver",
        argv=argv,
        cwd=PROJECT_ROOT,
        timeout_seconds=request.timeout_seconds,
        output_limit_bytes=request.output_limit_bytes,
        details={"output_path": str(output), "allowed_root": str(RUNS_ROOT)},
    )


@server.tool(structured_output=True)
async def read_run_log(request: ReadLogRequest) -> LogChunk:
    """Read one bounded UTF-8 chunk from a persistent run log. KEVLAR color tags stripped by default."""
    return await asyncio.to_thread(
        manager.read_log, request.run_id, request.offset, request.max_bytes, request.strip_tags
    )


@server.tool(structured_output=True)
async def list_runs(request: ListRunsRequest) -> RunList:
    """List recent runs using the O(1) JSONL index. Returns total count alongside the page."""
    runs, total = await asyncio.to_thread(manager.list, request.limit, request.status)
    return RunList(runs=runs, total=total)


@server.tool(structured_output=True)
async def cancel_run(request: CancelRunRequest) -> CancelResult:
    """Cancel an active process tree by run ID; completed runs are left unchanged."""
    return await manager.cancel(request.run_id)


@server.tool(structured_output=True)
async def wait_run(request: WaitRunRequest) -> WaitResult:
    """Block until a run reaches a terminal status or the timeout elapses. Returns the final RunSummary."""
    return await manager.wait_for_run(request.run_id, request.timeout_seconds)


@server.tool(structured_output=True)
async def get_run(request: GetRunRequest) -> RunSummary:
    """Return the RunSummary for a single run by ID without listing all runs."""
    return await asyncio.to_thread(manager.get, request.run_id)


@server.tool(structured_output=True)
async def search_run_log(request: SearchLogRequest) -> SearchResult:
    """Search a run log for lines matching a Python regex pattern. Returns matching lines with byte offsets."""
    return await asyncio.to_thread(
        manager.search_log,
        request.run_id, request.pattern, request.max_matches, request.strip_tags,
    )


@server.tool(structured_output=True)
async def prune_runs(request: PruneRunsRequest) -> PruneResult:
    """Delete terminal runs older than N days from disk and the index. Use dry_run=true to preview."""
    if request.status is not None and request.status not in TERMINAL_STATUSES:
        raise ValueError(f"status must be a terminal status to prune; got {request.status!r}")
    return await asyncio.to_thread(
        manager.prune, request.older_than_days, request.status, request.dry_run
    )


@server.tool(structured_output=True)
async def diff_runs(request: DiffRunsRequest) -> RunDiff:
    """Compare two runs: status, NTSTATUS, lifecycle, SEH count, and new coverage edges."""
    if request.run_id_a == request.run_id_b:
        raise ValueError("run_id_a and run_id_b must be different")
    run_a = await asyncio.to_thread(manager.get, request.run_id_a)
    run_b = await asyncio.to_thread(manager.get, request.run_id_b)
    da, db = run_a.details, run_b.details

    # Coverage diff (optional — requires both runs to have coverage_out_path)
    new_edges: int | None = None
    cov_a = da.get("coverage_out_path")
    cov_b = db.get("coverage_out_path")
    if cov_a and cov_b and Path(cov_a).is_file() and Path(cov_b).is_file():
        edges_a = set(
            (m, ra, mt, rt)
            for m, ra, mt, rt, _ in await asyncio.to_thread(_parse_coverage_file, Path(cov_a))
        )
        edges_b = set(
            (m, ra, mt, rt)
            for m, ra, mt, rt, _ in await asyncio.to_thread(_parse_coverage_file, Path(cov_b))
        )
        new_edges = len(edges_b - edges_a)

    # Details delta: keys present in b but not a, or with different values
    delta: dict[str, Any] = {}
    all_keys = set(da) | set(db)
    for k in sorted(all_keys):
        va, vb = da.get(k), db.get(k)
        if va != vb:
            delta[k] = {"a": va, "b": vb}

    return RunDiff(
        run_id_a=request.run_id_a,
        run_id_b=request.run_id_b,
        status_changed=run_a.status != run_b.status,
        status_a=run_a.status,
        status_b=run_b.status,
        ntstatus_a=da.get("ntstatus"),
        ntstatus_b=db.get("ntstatus"),
        ntstatus_changed=da.get("ntstatus") != db.get("ntstatus"),
        entry_success_a=da.get("entry_success"),
        entry_success_b=db.get("entry_success"),
        emulation_complete_a=da.get("emulation_complete"),
        emulation_complete_b=db.get("emulation_complete"),
        lifecycle_nonempty_a=da.get("lifecycle_nonempty"),
        lifecycle_nonempty_b=db.get("lifecycle_nonempty"),
        seh_count_a=da.get("seh_count"),
        seh_count_b=db.get("seh_count"),
        new_edges=new_edges,
        details_delta=delta,
    )


@server.tool(structured_output=True)
async def list_staged_inputs(request: ListStagedRequest) -> StagedInputList:
    """List driver images currently in the server staging cache (SHA-256, name, size)."""
    staging = RUNS_ROOT / "staged-inputs"
    inputs: list[StagedInput] = []

    def _scan() -> list[StagedInput]:
        result: list[StagedInput] = []
        if not staging.is_dir():
            return result
        for sha_dir in staging.iterdir():
            if not sha_dir.is_dir() or len(sha_dir.name) != 64:
                continue
            for f in sha_dir.iterdir():
                if f.is_file():
                    result.append(StagedInput(
                        sha256=sha_dir.name,
                        name=f.name,
                        size_bytes=f.stat().st_size,
                        staged_path=str(f),
                    ))
        result.sort(key=lambda x: x.name)
        return result

    all_inputs = await asyncio.to_thread(_scan)
    return StagedInputList(inputs=all_inputs[:request.limit], total=len(all_inputs))


@server.tool(structured_output=True)
async def get_coverage_summary(request: CoverageSummaryRequest) -> CoverageSummary:
    """Summarize edge coverage for a run: total edges, total hits, top-N hottest edges."""
    run = await asyncio.to_thread(manager.get, request.run_id)
    cov_path_str = run.details.get("coverage_out_path")
    if not cov_path_str:
        raise ValueError(f"run {request.run_id} has no coverage_out_path; rerun with coverage_out set")
    cov_path = Path(cov_path_str)
    if not cov_path.is_file():
        raise ValueError(f"coverage file not found: {cov_path}")

    def _summarize() -> CoverageSummary:
        edges = _parse_coverage_file(cov_path)
        total_edges = len(edges)
        total_hits = sum(h for _, _, _, _, h in edges)
        top = sorted(edges, key=lambda e: e[4], reverse=True)[:request.top_n]
        return CoverageSummary(
            run_id=request.run_id,
            coverage_file=str(cov_path),
            total_edges=total_edges,
            total_hits=total_hits,
            top_edges=[
                EdgeSummary(from_module=m, from_rva=ra, to_module=mt, to_rva=rt, hits=h)
                for m, ra, mt, rt, h in top
            ],
        )

    return await asyncio.to_thread(_summarize)


# ---------------------------------------------------------------------------
# Strict protocol envelope enforcement
# ---------------------------------------------------------------------------

def _enforce_strict_tool_arguments() -> None:
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
