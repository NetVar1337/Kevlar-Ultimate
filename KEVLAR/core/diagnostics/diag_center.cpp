#include "core/diagnostics/diag_center.h"
#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include "core/memory/unicorn_memory.h"
#include "core/exception/seh_dispatch.h"
#include <Logger/Logger.h>
#include <cstdio>
#include <cstring>
#include <intrin.h>

DiagCenter& DiagCenter::Instance() {
    static DiagCenter Inst;
    return Inst;
}

DiagCenter::DiagCenter()
    : mSeq(0)
    , mEnabled(false)
    , mSehRingIdx(0), mSehCount(0)
    , mMemProbeRingIdx(0), mMemProbeCount(0)
    , mPeProbeRingIdx(0), mPeProbeCount(0)
    , mStackRejectIdx(0), mStackRejectCount(0)
    , mStackAcceptIdx(0), mStackAcceptCount(0)
    , mHvspRingIdx(0), mHvspCount(0)
    , mKusdRingIdx(0), mKusdCount(0)
    , mBootEnvIdx(0), mBootEnvCount(0)
    , mCiRingIdx(0), mCiCount(0)
    , mFwRingIdx(0), mFwCount(0)
    , mCpuidRingIdx(0), mCpuidCount(0)
    , mModQueryIdx(0), mModQueryCount(0)
    , mDrvSelfIdx(0), mDrvSelfCount(0)
    , mNtosRingIdx(0), mNtosCount(0)
    , mUnmappedIdx(0), mUnmappedCount(0)
    , mConsistencyIdx(0), mConsistencyCount(0)
{
    memset(mFmtBuf, 0, sizeof(mFmtBuf));
}

DiagCenter::~DiagCenter() {}

void DiagCenter::Initialize() {
    mEnabled = true;
    mSeq.store(0, std::memory_order_relaxed);
    mSehRingIdx.store(0, std::memory_order_relaxed); mSehCount.store(0, std::memory_order_relaxed);
    mMemProbeRingIdx.store(0, std::memory_order_relaxed); mMemProbeCount.store(0, std::memory_order_relaxed);
    mPeProbeRingIdx.store(0, std::memory_order_relaxed); mPeProbeCount.store(0, std::memory_order_relaxed);
    mStackRejectIdx.store(0, std::memory_order_relaxed); mStackRejectCount.store(0, std::memory_order_relaxed);
    mStackAcceptIdx.store(0, std::memory_order_relaxed); mStackAcceptCount.store(0, std::memory_order_relaxed);
    mHvspRingIdx.store(0, std::memory_order_relaxed); mHvspCount.store(0, std::memory_order_relaxed);
    mKusdRingIdx.store(0, std::memory_order_relaxed); mKusdCount.store(0, std::memory_order_relaxed);
    mBootEnvIdx.store(0, std::memory_order_relaxed); mBootEnvCount.store(0, std::memory_order_relaxed);
    mCiRingIdx.store(0, std::memory_order_relaxed); mCiCount.store(0, std::memory_order_relaxed);
    mFwRingIdx.store(0, std::memory_order_relaxed); mFwCount.store(0, std::memory_order_relaxed);
    mCpuidRingIdx.store(0, std::memory_order_relaxed); mCpuidCount.store(0, std::memory_order_relaxed);
    mModQueryIdx.store(0, std::memory_order_relaxed); mModQueryCount.store(0, std::memory_order_relaxed);
    mDrvSelfIdx.store(0, std::memory_order_relaxed); mDrvSelfCount.store(0, std::memory_order_relaxed);
    mNtosRingIdx.store(0, std::memory_order_relaxed); mNtosCount.store(0, std::memory_order_relaxed);
    mUnmappedIdx.store(0, std::memory_order_relaxed); mUnmappedCount.store(0, std::memory_order_relaxed);
    mConsistencyIdx.store(0, std::memory_order_relaxed); mConsistencyCount.store(0, std::memory_order_relaxed);
    Logger::Log("{GRN}DiagCenter initialized{RESET}\n");
}

void DiagCenter::Shutdown() {
    mEnabled = false;
    Logger::Log("{CYN}DiagCenter shut down (total seq=%llu){RESET}\n", (unsigned long long)mSeq.load(std::memory_order_relaxed));
}

uint64_t DiagCenter::NextSeq() {
    return mSeq.fetch_add(1, std::memory_order_relaxed) + 1;
}

bool DiagCenter::IsEnabled() const {
    return mEnabled;
}

void DiagCenter::RecordSeh(const SehEvent& E) {
    uint32_t Idx = mSehRingIdx.fetch_add(1, std::memory_order_relaxed) % SEH_RING_SIZE;
    mSehRing[Idx] = E;
    mSehCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordMemProbe(const MemProbeEvent& E) {
    uint32_t Idx = mMemProbeRingIdx.fetch_add(1, std::memory_order_relaxed) % MEMPROBE_RING_SIZE;
    mMemProbeRing[Idx] = E;
    mMemProbeCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordPeProbe(const PeProbeEvent& E) {
    uint32_t Idx = mPeProbeRingIdx.fetch_add(1, std::memory_order_relaxed) % PEPROBE_RING_SIZE;
    mPeProbeRing[Idx] = E;
    mPeProbeCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordStackReject(const StackRejectEvent& E) {
    uint32_t Idx = mStackRejectIdx.fetch_add(1, std::memory_order_relaxed) % STACK_REJECT_RING_SIZE;
    mStackRejectRing[Idx] = E;
    mStackRejectCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordStackAccept(const StackAcceptEvent& E) {
    uint32_t Idx = mStackAcceptIdx.fetch_add(1, std::memory_order_relaxed) % STACK_ACCEPT_RING_SIZE;
    mStackAcceptRing[Idx] = E;
    mStackAcceptCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordHvspRead(const HvspReadEvent& E) {
    uint32_t Idx = mHvspRingIdx.fetch_add(1, std::memory_order_relaxed) % HVSP_RING_SIZE;
    mHvspRing[Idx] = E;
    mHvspCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordKusdRead(const KusdReadEvent& E) {
    uint32_t Idx = mKusdRingIdx.fetch_add(1, std::memory_order_relaxed) % KUSD_RING_SIZE;
    mKusdRing[Idx] = E;
    mKusdCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordBootEnvRead(const BootEnvReadEvent& E) {
    uint32_t Idx = mBootEnvIdx.fetch_add(1, std::memory_order_relaxed) % BOOTENV_RING_SIZE;
    mBootEnvRing[Idx] = E;
    mBootEnvCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordCiRead(const CiReadEvent& E) {
    uint32_t Idx = mCiRingIdx.fetch_add(1, std::memory_order_relaxed) % CI_RING_SIZE;
    mCiRing[Idx] = E;
    mCiCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordFirmwareQuery(const FirmwareQueryEvent& E) {
    uint32_t Idx = mFwRingIdx.fetch_add(1, std::memory_order_relaxed) % FW_RING_SIZE;
    mFwRing[Idx] = E;
    mFwCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordCpuid(const CpuidEvent& E) {
    uint32_t Idx = mCpuidRingIdx.fetch_add(1, std::memory_order_relaxed) % CPUID_RING_SIZE;
    mCpuidRing[Idx] = E;
    mCpuidCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordModuleQuery(const ModuleQueryEvent& E) {
    uint32_t Idx = mModQueryIdx.fetch_add(1, std::memory_order_relaxed) % MODULE_QUERY_RING_SIZE;
    mModQueryRing[Idx] = E;
    mModQueryCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordDrvSelfRead(const DrvSelfReadEvent& E) {
    uint32_t Idx = mDrvSelfIdx.fetch_add(1, std::memory_order_relaxed) % DRV_SELF_RING_SIZE;
    mDrvSelfRing[Idx] = E;
    mDrvSelfCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordNtosRead(const NtosReadEvent& E) {
    uint32_t Idx = mNtosRingIdx.fetch_add(1, std::memory_order_relaxed) % NTOS_RING_SIZE;
    mNtosRing[Idx] = E;
    mNtosCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordUnmappedRead(const UnmappedReadEvent& E) {
    uint32_t Idx = mUnmappedIdx.fetch_add(1, std::memory_order_relaxed) % UNMAPPED_RING_SIZE;
    mUnmappedRing[Idx] = E;
    mUnmappedCount.fetch_add(1, std::memory_order_relaxed);
}

void DiagCenter::RecordConsistency(const ConsistencyEvent& E) {
    uint32_t Idx = mConsistencyIdx.fetch_add(1, std::memory_order_relaxed) % CONSISTENCY_RING_SIZE;
    mConsistencyRing[Idx] = E;
    mConsistencyCount.fetch_add(1, std::memory_order_relaxed);
}

static const char* AccessTypeName(DiagAccessType T) {
    switch (T) {
    case ACCESS_READ: return "READ";
    case ACCESS_WRITE: return "WRITE";
    case ACCESS_EXECUTE: return "EXEC";
    case ACCESS_API: return "API";
    case ACCESS_EXCEPTION: return "EXCEPT";
    case ACCESS_UNKNOWN: return "???";
    default: return "???";
    }
}

static const char* RejectReasonStr(DiagRejectReason R) {
    switch (R) {
    case REJECT_KUSER_SHARED_DATA: return "KUSER_SHARED_DATA";
    case REJECT_HYPERVISOR_SHARED_PAGE: return "HV_SHARED_PAGE";
    case REJECT_POOL: return "POOL";
    case REJECT_STACK: return "STACK";
    case REJECT_SENTINEL: return "SENTINEL";
    case REJECT_STRING_LIKE: return "STRING_LIKE";
    case REJECT_UNMAPPED: return "UNMAPPED";
    case REJECT_NON_CANONICAL: return "NON_CANONICAL";
    case REJECT_NO_MODULE: return "NO_MODULE";
    case REJECT_NON_EXEC_SECTION: return "NON_EXEC_SECTION";
    case REJECT_UNLIKELY_CODE: return "UNLIKELY_CODE";
    case REJECT_FAR_FROM_MODULES: return "FAR_FROM_MODULES";
    case REJECT_SMALL_INT: return "SMALL_INT";
    case REJECT_OK: return "OK";
    default: return "???";
    }
}

static const char* ProbeTypeName(DiagProbeType T) {
    switch (T) {
    case PROBE_MZ: return "MZ";
    case PROBE_E_LFANEW: return "e_lfanew";
    case PROBE_PE_SIGNATURE: return "PE_SIG";
    case PROBE_SECTION_TABLE: return "SECTION_TBL";
    case PROBE_EXPORT_DIR: return "EXPORT_DIR";
    case PROBE_IMPORT_DIR: return "IMPORT_DIR";
    case PROBE_RSRC_DIR: return "RSRC_DIR";
    case PROBE_RELOC_DIR: return "RELOC_DIR";
    case PROBE_TLS_DIR: return "TLS_DIR";
    case PROBE_SIZE_OF_IMAGE: return "SIZE_OF_IMAGE";
    case PROBE_ADDRESS_OF_ENTRY_POINT: return "ENTRY_POINT";
    case PROBE_DOS_HEADER_SCAN: return "DOS_HDR_SCAN";
    case PROBE_UNKNOWN: return "???";
    default: return "???";
    }
}

static const char* SourceProvName(DiagSourceProv P) {
    switch (P) {
    case SRC_SYS_MODULE_INFO: return "SYS_MODULE_INFO";
    case SRC_PS_LOADED_MODULE_LIST: return "PS_LOADED_MODULE_LIST";
    case SRC_STACK: return "STACK";
    case SRC_DRIVER_OBJECT: return "DRIVER_OBJECT";
    case SRC_PHYSICAL_MAPPING: return "PHYSICAL_MAPPING";
    case SRC_SCAN_RANGE: return "SCAN_RANGE";
    case SRC_HARDCODE: return "HARDCODE";
    case SRC_REGISTRY: return "REGISTRY";
    case SRC_BCD: return "BCD";
    case SRC_UNKNOWN: return "???";
    default: return "???";
    }
}

static const char* SeverityName(DiagSeverity S) {
    switch (S) {
    case SEV_INFO: return "INFO";
    case SEV_WARN: return "WARN";
    case SEV_ERROR: return "ERROR";
    default: return "???";
    }
}

static const char* CpuidLeafName(uint32_t Leaf) {
    if (Leaf == 0x00000000) return "MaxStdLeaf+Vendor";
    if (Leaf == 0x00000001) return "FeatureBits";
    if (Leaf == 0x00000002) return "CacheTlb";
    if (Leaf == 0x00000004) return "DeterministicCache";
    if (Leaf == 0x00000007) return "ExtendedFeatures";
    if (Leaf == 0x0000000B) return "Topology";
    if (Leaf == 0x0000000D) return "XSave";
    if (Leaf == 0x0000000F) return "RDTMonitoring";
    if (Leaf == 0x00000010) return "RDTAllocation";
    if (Leaf == 0x00000015) return "TSCCoreFreq";
    if (Leaf == 0x80000000) return "MaxExtLeaf";
    if (Leaf == 0x80000001) return "ExtFeatures";
    if (Leaf == 0x80000002) return "ProcessorName1";
    if (Leaf == 0x80000003) return "ProcessorName2";
    if (Leaf == 0x80000004) return "ProcessorName3";
    if (Leaf == 0x80000006) return "CacheL2";
    if (Leaf == 0x80000008) return "PhysAddrSize";
    if (Leaf >= 0x40000000 && Leaf <= 0x40000006) return "HV_Leaf";
    if (Leaf == 0x40000000) return "HV_MaxLeaf+Vendor";
    if (Leaf == 0x40000001) return "HV_Interface";
    if (Leaf == 0x40000002) return "HV_Version";
    if (Leaf == 0x40000003) return "HV_Features";
    if (Leaf == 0x40000004) return "HV_Recommendations";
    if (Leaf == 0x40000005) return "HV_Limits";
    if (Leaf == 0x40000006) return "HV_ImplLimits";
    return "Unknown";
}

void DiagCenter::DumpSehEvents() {
    uint32_t CurCount = mSehCount.load(std::memory_order_relaxed);
    uint32_t CurIdx   = mSehRingIdx.load(std::memory_order_relaxed);
    Logger::Log("{MAG}=== SEH Events (%u total, ring %u) ==={RESET}\n", CurCount, CurIdx);
    uint32_t Count = (CurCount < SEH_RING_SIZE) ? CurCount : SEH_RING_SIZE;
    uint32_t Start = (CurCount < SEH_RING_SIZE) ? 0 : (CurIdx % SEH_RING_SIZE);
    for (uint32_t I = 0; I < Count; I++) {
        uint32_t Idx = (Start + I) % SEH_RING_SIZE;
        auto& E = mSehRing[Idx];
        Logger::Log("  [{WHT}%04u{RESET}] seq=%llu rip=0x%llx mod=%s+0x%x code=0x%08x fault=0x%llx handler=0x%llx disp=%u\n",
            I, (unsigned long long)E.Base.Sequence, (unsigned long long)E.Base.Rip,
            E.ModuleName, E.Base.ModuleRva, E.ExceptionCode,
            (unsigned long long)E.FaultAddress, (unsigned long long)E.HandlerRip, E.Disposition);
        Logger::Log("         first=%u resume=0x%llx stack=0x%llx hints=0x%02x\n",
            E.FirstChance, (unsigned long long)E.ResumeRip, (unsigned long long)E.StackSlot, E.Hints);
        Logger::Log("         AX=%016llx BX=%016llx CX=%016llx DX=%016llx\n",
            (unsigned long long)E.GprAX, (unsigned long long)E.GprBX,
            (unsigned long long)E.GprCX, (unsigned long long)E.GprDX);
        Logger::Log("         SI=%016llx DI=%016llx SP=%016llx BP=%016llx\n",
            (unsigned long long)E.GprSI, (unsigned long long)E.GprDI,
            (unsigned long long)E.GprSP, (unsigned long long)E.GprBP);
        Logger::Log("         R8=%016llx R9=%016llx R10=%016llx R11=%016llx\n",
            (unsigned long long)E.GprR8, (unsigned long long)E.GprR9,
            (unsigned long long)E.GprR10, (unsigned long long)E.GprR11);
        Logger::Log("         R12=%016llx R13=%016llx R14=%016llx R15=%016llx\n",
            (unsigned long long)E.GprR12, (unsigned long long)E.GprR13,
            (unsigned long long)E.GprR14, (unsigned long long)E.GprR15);
        Logger::Log("         eflags=0x%08x reason=%s\n", E.Eflags, E.Reason);
    }
}

void DiagCenter::DumpStackRejectEvents() {
    uint32_t CurCount = mStackRejectCount.load(std::memory_order_relaxed);
    uint32_t CurIdx   = mStackRejectIdx.load(std::memory_order_relaxed);
    Logger::Log("{YEL}=== Stack Reject Events (%u total) ==={RESET}\n", CurCount);
    uint32_t Count = (CurCount < STACK_REJECT_RING_SIZE) ? CurCount : STACK_REJECT_RING_SIZE;
    uint32_t Start = (CurCount < STACK_REJECT_RING_SIZE) ? 0 : (CurIdx % STACK_REJECT_RING_SIZE);
    for (uint32_t I = 0; I < Count; I++) {
        uint32_t Idx = (Start + I) % STACK_REJECT_RING_SIZE;
        auto& E = mStackRejectRing[Idx];
        Logger::Log("  [{WHT}%04u{RESET}] seq=%llu val=0x%llx stack=0x%llx rip=0x%llx (%s+0x%x) reason=%s (%s)\n",
            I, (unsigned long long)E.Sequence, (unsigned long long)E.Value,
            (unsigned long long)E.StackSlot, (unsigned long long)E.Rip,
            E.ModuleName, E.ModuleRva, RejectReasonStr(E.Reason), E.ReasonStr);
    }
}

void DiagCenter::DumpStackAcceptEvents() {
    uint32_t CurCount = mStackAcceptCount.load(std::memory_order_relaxed);
    uint32_t CurIdx   = mStackAcceptIdx.load(std::memory_order_relaxed);
    Logger::Log("{GRN}=== Stack Accept Events (%u total) ==={RESET}\n", CurCount);
    uint32_t Count = (CurCount < STACK_ACCEPT_RING_SIZE) ? CurCount : STACK_ACCEPT_RING_SIZE;
    uint32_t Start = (CurCount < STACK_ACCEPT_RING_SIZE) ? 0 : (CurIdx % STACK_ACCEPT_RING_SIZE);
    for (uint32_t I = 0; I < Count; I++) {
        uint32_t Idx = (Start + I) % STACK_ACCEPT_RING_SIZE;
        auto& E = mStackAcceptRing[Idx];
        Logger::Log("  [{WHT}%04u{RESET}] seq=%llu val=0x%llx stack=0x%llx rip=0x%llx (%s+0x%x) section=%s conf=%u\n",
            I, (unsigned long long)E.Sequence, (unsigned long long)E.Value,
            (unsigned long long)E.StackSlot, (unsigned long long)E.Rip,
            E.ModuleName, E.ModuleRva, E.Section, E.Confidence);
    }
}

void DiagCenter::DumpHvspReads() {
    uint32_t CurCount = mHvspCount.load(std::memory_order_relaxed);
    uint32_t CurIdx   = mHvspRingIdx.load(std::memory_order_relaxed);
    Logger::Log("{CYN}=== HV Shared Page Reads (%u total) ==={RESET}\n", CurCount);
    uint32_t Count = (CurCount < HVSP_RING_SIZE) ? CurCount : HVSP_RING_SIZE;
    uint32_t Start = (CurCount < HVSP_RING_SIZE) ? 0 : (CurIdx % HVSP_RING_SIZE);
    for (uint32_t I = 0; I < Count; I++) {
        uint32_t Idx = (Start + I) % HVSP_RING_SIZE;
        auto& E = mHvspRing[Idx];
        Logger::Log("  [{WHT}%04u{RESET}] seq=%llu rip=0x%llx addr=0x%llx off=0x%x sz=%u val=0x%llx field=%s dyn=%u\n",
            I, (unsigned long long)E.Base.Sequence, (unsigned long long)E.Base.Rip,
            (unsigned long long)E.Address, E.Offset, E.Size,
            (unsigned long long)E.Value, E.FieldName, E.DynamicUpdate);
    }
}

void DiagCenter::DumpBootEnvReads() {
    uint32_t CurCount = mBootEnvCount.load(std::memory_order_relaxed);
    uint32_t CurIdx   = mBootEnvIdx.load(std::memory_order_relaxed);
    Logger::Log("{CYN}=== Boot Env Reads (%u total) ==={RESET}\n", CurCount);
    uint32_t Count = (CurCount < BOOTENV_RING_SIZE) ? CurCount : BOOTENV_RING_SIZE;
    uint32_t Start = (CurCount < BOOTENV_RING_SIZE) ? 0 : (CurIdx % BOOTENV_RING_SIZE);
    for (uint32_t I = 0; I < Count; I++) {
        uint32_t Idx = (Start + I) % BOOTENV_RING_SIZE;
        auto& E = mBootEnvRing[Idx];
        Logger::Log("  [{WHT}%04u{RESET}] seq=%llu rip=0x%llx buf=0x%llx len=%u status=0x%x fwtype=%u bootflags=0x%llx\n",
            I, (unsigned long long)E.Base.Sequence, (unsigned long long)E.Base.Rip,
            (unsigned long long)E.BufferAddr, E.BufferLen, E.Status,
            E.FirmwareType, (unsigned long long)E.BootFlags);
    }
}

void DiagCenter::DumpCiReads() {
    uint32_t CurCount = mCiCount.load(std::memory_order_relaxed);
    uint32_t CurIdx   = mCiRingIdx.load(std::memory_order_relaxed);
    Logger::Log("{CYN}=== Code Integrity Reads (%u total) ==={RESET}\n", CurCount);
    uint32_t Count = (CurCount < CI_RING_SIZE) ? CurCount : CI_RING_SIZE;
    uint32_t Start = (CurCount < CI_RING_SIZE) ? 0 : (CurIdx % CI_RING_SIZE);
    for (uint32_t I = 0; I < Count; I++) {
        uint32_t Idx = (Start + I) % CI_RING_SIZE;
        auto& E = mCiRing[Idx];
        Logger::Log("  [{WHT}%04u{RESET}] seq=%llu rip=0x%llx buf=0x%llx len=%u status=0x%x opts=0x%x hvci=0x%x ver=0x%llx\n",
            I, (unsigned long long)E.Base.Sequence, (unsigned long long)E.Base.Rip,
            (unsigned long long)E.BufferAddr, E.BufferLen, E.Status,
            E.Options, E.HVCIOptions, (unsigned long long)E.Version);
    }
}

void DiagCenter::DumpFirmwareQueries() {
    uint32_t CurCount = mFwCount.load(std::memory_order_relaxed);
    uint32_t CurIdx   = mFwRingIdx.load(std::memory_order_relaxed);
    Logger::Log("{CYN}=== Firmware Queries (%u total) ==={RESET}\n", CurCount);
    uint32_t Count = (CurCount < FW_RING_SIZE) ? CurCount : FW_RING_SIZE;
    uint32_t Start = (CurCount < FW_RING_SIZE) ? 0 : (CurIdx % FW_RING_SIZE);
    for (uint32_t I = 0; I < Count; I++) {
        uint32_t Idx = (Start + I) % FW_RING_SIZE;
        auto& E = mFwRing[Idx];
        Logger::Log("  [{WHT}%04u{RESET}] seq=%llu rip=0x%llx buf=0x%llx inlen=%u outlen=%u status=0x%x prov=%s action=%u tbl=%u inst=%llu fake=%u\n",
            I, (unsigned long long)E.Base.Sequence, (unsigned long long)E.Base.Rip,
            (unsigned long long)E.BufferAddr, E.InputLen, E.OutputLen,
            E.Status, E.ProviderName, E.Action, E.TableId,
            (unsigned long long)E.Instance, E.IsFake);
        Logger::Log("         first32=[%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x ...]\n",
            E.First32Bytes[0], E.First32Bytes[1], E.First32Bytes[2], E.First32Bytes[3],
            E.First32Bytes[4], E.First32Bytes[5], E.First32Bytes[6], E.First32Bytes[7],
            E.First32Bytes[8], E.First32Bytes[9], E.First32Bytes[10], E.First32Bytes[11],
            E.First32Bytes[12], E.First32Bytes[13], E.First32Bytes[14], E.First32Bytes[15]);
    }
}

void DiagCenter::DumpCpuidEvents() {
    uint32_t CurCount = mCpuidCount.load(std::memory_order_relaxed);
    uint32_t CurIdx   = mCpuidRingIdx.load(std::memory_order_relaxed);
    Logger::Log("{CYN}=== CPUID Events (%u total) ==={RESET}\n", CurCount);
    uint32_t Count = (CurCount < CPUID_RING_SIZE) ? CurCount : CPUID_RING_SIZE;
    uint32_t Start = (CurCount < CPUID_RING_SIZE) ? 0 : (CurIdx % CPUID_RING_SIZE);
    for (uint32_t I = 0; I < Count; I++) {
        uint32_t Idx = (Start + I) % CPUID_RING_SIZE;
        auto& E = mCpuidRing[Idx];
        Logger::Log("  [{WHT}%04u{RESET}] seq=%llu rip=0x%llx leaf=0x%08x sub=0x%x (%s) hv=%u selfmod=%u\n",
            I, (unsigned long long)E.Base.Sequence, (unsigned long long)E.Base.Rip,
            E.Leaf, E.SubLeaf, E.LeafName, E.HypervisorPresent, E.SelfModify);
        Logger::Log("         pre:  AX=%08x BX=%08x CX=%08x DX=%08x\n",
            E.PreEax, E.PreEbx, E.PreEcx, E.PreEdx);
        Logger::Log("         post: AX=%08x BX=%08x CX=%08x DX=%08x\n",
            E.PostEax, E.PostEbx, E.PostEcx, E.PostEdx);
        Logger::Log("         changed: [%d,%d,%d,%d] vendor=%s\n",
            E.ChangedBits[0], E.ChangedBits[1], E.ChangedBits[2], E.ChangedBits[3],
            E.VendorStr);
    }
}

void DiagCenter::DumpModuleQueryEvents() {
    uint32_t CurCount = mModQueryCount.load(std::memory_order_relaxed);
    uint32_t CurIdx   = mModQueryIdx.load(std::memory_order_relaxed);
    Logger::Log("{CYN}=== Module Query Events (%u total) ==={RESET}\n", CurCount);
    uint32_t Count = (CurCount < MODULE_QUERY_RING_SIZE) ? CurCount : MODULE_QUERY_RING_SIZE;
    uint32_t Start = (CurCount < MODULE_QUERY_RING_SIZE) ? 0 : (CurIdx % MODULE_QUERY_RING_SIZE);
    for (uint32_t I = 0; I < Count; I++) {
        uint32_t Idx = (Start + I) % MODULE_QUERY_RING_SIZE;
        auto& E = mModQueryRing[Idx];
        Logger::Log("  [{WHT}%04u{RESET}] seq=%llu rip=0x%llx buf=0x%llx len=%u reqlen=%u init=0x%x final=0x%x mods=[%u->%u] injected=%u\n",
            I, (unsigned long long)E.Base.Sequence, (unsigned long long)E.Base.Rip,
            (unsigned long long)E.BufferAddr, E.BufferLen, E.RequiredLen,
            E.InitiaStatus, E.FinalStatus, E.ModuleCountBefore, E.ModuleCountAfter,
            E.ModuleCountInjected);
        if (E.ModuleCountInjected > 0) {
            Logger::Log("         injected: %s base=0x%llx\n",
                E.InjectedModuleName, (unsigned long long)E.InjectedModuleBase);
        }
    }
}

void DiagCenter::DumpDrvSelfReads() {
    uint32_t CurCount = mDrvSelfCount.load(std::memory_order_relaxed);
    uint32_t CurIdx   = mDrvSelfIdx.load(std::memory_order_relaxed);
    Logger::Log("{CYN}=== Driver Self-Reads (%u total) ==={RESET}\n", CurCount);
    uint32_t Count = (CurCount < DRV_SELF_RING_SIZE) ? CurCount : DRV_SELF_RING_SIZE;
    uint32_t Start = (CurCount < DRV_SELF_RING_SIZE) ? 0 : (CurIdx % DRV_SELF_RING_SIZE);
    for (uint32_t I = 0; I < Count; I++) {
        uint32_t Idx = (Start + I) % DRV_SELF_RING_SIZE;
        auto& E = mDrvSelfRing[Idx];
        Logger::Log("  [{WHT}%04u{RESET}] seq=%llu rip=0x%llx target=0x%llx rva=0x%x sz=%u val=0x%llx section=%s hot=%u integrity=%s\n",
            I, (unsigned long long)E.Base.Sequence, (unsigned long long)E.Base.Rip,
            (unsigned long long)E.TargetVa, E.TargetRva, E.Size,
            (unsigned long long)E.Value, E.Section, E.IsHot, E.IntegrityReason);
    }
}

void DiagCenter::DumpNtosReads() {
    uint32_t CurCount = mNtosCount.load(std::memory_order_relaxed);
    uint32_t CurIdx   = mNtosRingIdx.load(std::memory_order_relaxed);
    Logger::Log("{CYN}=== NTOSKRNL Reads (%u total) ==={RESET}\n", CurCount);
    uint32_t Count = (CurCount < NTOS_RING_SIZE) ? CurCount : NTOS_RING_SIZE;
    uint32_t Start = (CurCount < NTOS_RING_SIZE) ? 0 : (CurIdx % NTOS_RING_SIZE);
    for (uint32_t I = 0; I < Count; I++) {
        uint32_t Idx = (Start + I) % NTOS_RING_SIZE;
        auto& E = mNtosRing[Idx];
        Logger::Log("  [{WHT}%04u{RESET}] seq=%llu rip=0x%llx target=0x%llx rva=0x%x sz=%u val=0x%llx section=%s sym=%s patched=%u sus=%u reason=%s\n",
            I, (unsigned long long)E.Base.Sequence, (unsigned long long)E.Base.Rip,
            (unsigned long long)E.TargetVa, E.TargetRva, E.Size,
            (unsigned long long)E.Value, E.Section, E.Symbol,
            E.IsPatched, E.Suspicious, E.SuspiciousReason);
    }
}

void DiagCenter::DumpUnmappedReads() {
    uint32_t CurCount = mUnmappedCount.load(std::memory_order_relaxed);
    uint32_t CurIdx   = mUnmappedIdx.load(std::memory_order_relaxed);
    Logger::Log("{RED}=== Unmapped Reads (%u total) ==={RESET}\n", CurCount);
    uint32_t Count = (CurCount < UNMAPPED_RING_SIZE) ? CurCount : UNMAPPED_RING_SIZE;
    uint32_t Start = (CurCount < UNMAPPED_RING_SIZE) ? 0 : (CurIdx % UNMAPPED_RING_SIZE);
    for (uint32_t I = 0; I < Count; I++) {
        uint32_t Idx = (Start + I) % UNMAPPED_RING_SIZE;
        auto& E = mUnmappedRing[Idx];
        Logger::Log("  [{WHT}%04u{RESET}] seq=%llu rip=0x%llx fault=0x%llx sz=%u cands=[4k:0x%llx+0x%x 64k:0x%llx+0x%x] hint=%s lazy=%u handler=%u region=%s\n",
            I, (unsigned long long)E.Base.Sequence, (unsigned long long)E.Base.Rip,
            (unsigned long long)E.FaultAddress, E.Size,
            (unsigned long long)E.CandidateBase4k, E.Offset4k,
            (unsigned long long)E.CandidateBase64k, E.Offset64k,
            ProbeTypeName(E.Hint), E.LazyMapped, E.HasHandler, E.RegionName);
        Logger::Log("         recent_rip=[");
        for (int J = 0; J < 8; J++) {
            if (E.RecentRipRing[J]) Logger::Log("%s0x%llx", (J > 0) ? " " : "", (unsigned long long)E.RecentRipRing[J]);
        }
        Logger::Log("] recent_evt=[");
        for (int J = 0; J < 8; J++) {
            if (E.RecentEventRing[J]) Logger::Log("%s%u", (J > 0) ? " " : "", E.RecentEventRing[J]);
        }
        Logger::Log("]\n");
    }
}

void DiagCenter::DumpConsistencyReport() {
    uint32_t CurCount = mConsistencyCount.load(std::memory_order_relaxed);
    uint32_t CurIdx   = mConsistencyIdx.load(std::memory_order_relaxed);
    Logger::Log("{MAG}=== Consistency Report (%u total) ==={RESET}\n", CurCount);
    uint32_t Count = (CurCount < CONSISTENCY_RING_SIZE) ? CurCount : CONSISTENCY_RING_SIZE;
    uint32_t Start = (CurCount < CONSISTENCY_RING_SIZE) ? 0 : (CurIdx % CONSISTENCY_RING_SIZE);
    for (uint32_t I = 0; I < Count; I++) {
        uint32_t Idx = (Start + I) % CONSISTENCY_RING_SIZE;
        auto& E = mConsistencyRing[Idx];
        Logger::Log("  [{WHT}%04u{RESET}] seq=%llu sev=%s check=%s msg=%s\n",
            I, (unsigned long long)E.Sequence, SeverityName(E.Severity),
            E.CheckName, E.Message);
        if (E.Va1 || E.Va2) {
            Logger::Log("         va1=0x%llx rva1=0x%x va2=0x%llx rva2=0x%x\n",
                (unsigned long long)E.Va1, E.Rva1,
                (unsigned long long)E.Va2, E.Rva2);
        }
    }
}

void DiagCenter::DumpJson(const std::string& Path) const {
    FILE* F = nullptr;
    if (fopen_s(&F, Path.c_str(), "wb") != 0 || !F) {
        Logger::Log("{RED}DumpJson: cannot open %s{RESET}\n", Path.c_str());
        return;
    }

    char Buf[512];
    bool FirstSection = true;
    fputs("{\n", F);

    // SEH events
    {
        uint32_t CurCount = mSehCount.load(std::memory_order_relaxed);
        if (CurCount > 0) {
            uint32_t CurIdx = mSehRingIdx.load(std::memory_order_relaxed);
            uint32_t Count = (CurCount < SEH_RING_SIZE) ? CurCount : SEH_RING_SIZE;
            uint32_t Start = (CurCount < SEH_RING_SIZE) ? 0 : (CurIdx % SEH_RING_SIZE);
            if (!FirstSection) fputs(",\n", F);
            FirstSection = false;
            fputs("  \"seh\": [\n", F);
            for (uint32_t I = 0; I < Count; I++) {
                const auto& E = mSehRing[(Start + I) % SEH_RING_SIZE];
                snprintf(Buf, sizeof(Buf),
                    "    {\"seq\":%llu,\"rip\":\"0x%llx\",\"exception_code\":\"0x%08x\",\"fault_address\":\"0x%llx\"}%s\n",
                    (unsigned long long)E.Base.Sequence,
                    (unsigned long long)E.Base.Rip,
                    E.ExceptionCode,
                    (unsigned long long)E.FaultAddress,
                    (I + 1 < Count) ? "," : "");
                fputs(Buf, F);
            }
            fputs("  ]", F);
        }
    }

    // mem_probes
    {
        uint32_t CurCount = mMemProbeCount.load(std::memory_order_relaxed);
        if (CurCount > 0) {
            uint32_t CurIdx = mMemProbeRingIdx.load(std::memory_order_relaxed);
            uint32_t Count = (CurCount < MEMPROBE_RING_SIZE) ? CurCount : MEMPROBE_RING_SIZE;
            uint32_t Start = (CurCount < MEMPROBE_RING_SIZE) ? 0 : (CurIdx % MEMPROBE_RING_SIZE);
            if (!FirstSection) fputs(",\n", F);
            FirstSection = false;
            fputs("  \"mem_probes\": [\n", F);
            for (uint32_t I = 0; I < Count; I++) {
                const auto& E = mMemProbeRing[(Start + I) % MEMPROBE_RING_SIZE];
                snprintf(Buf, sizeof(Buf),
                    "    {\"seq\":%llu,\"address\":\"0x%llx\",\"probe_type\":\"%s\",\"value\":\"0x%llx\"}%s\n",
                    (unsigned long long)E.Base.Sequence,
                    (unsigned long long)E.Address,
                    ProbeTypeName(E.ProbeType),
                    (unsigned long long)E.Value,
                    (I + 1 < Count) ? "," : "");
                fputs(Buf, F);
            }
            fputs("  ]", F);
        }
    }

    // cpuid
    {
        uint32_t CurCount = mCpuidCount.load(std::memory_order_relaxed);
        if (CurCount > 0) {
            uint32_t CurIdx = mCpuidRingIdx.load(std::memory_order_relaxed);
            uint32_t Count = (CurCount < CPUID_RING_SIZE) ? CurCount : CPUID_RING_SIZE;
            uint32_t Start = (CurCount < CPUID_RING_SIZE) ? 0 : (CurIdx % CPUID_RING_SIZE);
            if (!FirstSection) fputs(",\n", F);
            FirstSection = false;
            fputs("  \"cpuid\": [\n", F);
            for (uint32_t I = 0; I < Count; I++) {
                const auto& E = mCpuidRing[(Start + I) % CPUID_RING_SIZE];
                snprintf(Buf, sizeof(Buf),
                    "    {\"seq\":%llu,\"leaf\":\"0x%x\",\"leaf_name\":\"%s\","
                    "\"eax\":\"0x%x\",\"ebx\":\"0x%x\",\"ecx\":\"0x%x\",\"edx\":\"0x%x\"}%s\n",
                    (unsigned long long)E.Base.Sequence,
                    E.Leaf,
                    E.LeafName,
                    E.PostEax, E.PostEbx, E.PostEcx, E.PostEdx,
                    (I + 1 < Count) ? "," : "");
                fputs(Buf, F);
            }
            fputs("  ]", F);
        }
    }

    // unmapped_reads
    {
        uint32_t CurCount = mUnmappedCount.load(std::memory_order_relaxed);
        if (CurCount > 0) {
            uint32_t CurIdx = mUnmappedIdx.load(std::memory_order_relaxed);
            uint32_t Count = (CurCount < UNMAPPED_RING_SIZE) ? CurCount : UNMAPPED_RING_SIZE;
            uint32_t Start = (CurCount < UNMAPPED_RING_SIZE) ? 0 : (CurIdx % UNMAPPED_RING_SIZE);
            if (!FirstSection) fputs(",\n", F);
            FirstSection = false;
            fputs("  \"unmapped_reads\": [\n", F);
            for (uint32_t I = 0; I < Count; I++) {
                const auto& E = mUnmappedRing[(Start + I) % UNMAPPED_RING_SIZE];
                snprintf(Buf, sizeof(Buf),
                    "    {\"seq\":%llu,\"fault_address\":\"0x%llx\"}%s\n",
                    (unsigned long long)E.Base.Sequence,
                    (unsigned long long)E.FaultAddress,
                    (I + 1 < Count) ? "," : "");
                fputs(Buf, F);
            }
            fputs("  ]", F);
        }
    }

    // consistency
    {
        uint32_t CurCount = mConsistencyCount.load(std::memory_order_relaxed);
        if (CurCount > 0) {
            uint32_t CurIdx = mConsistencyIdx.load(std::memory_order_relaxed);
            uint32_t Count = (CurCount < CONSISTENCY_RING_SIZE) ? CurCount : CONSISTENCY_RING_SIZE;
            uint32_t Start = (CurCount < CONSISTENCY_RING_SIZE) ? 0 : (CurIdx % CONSISTENCY_RING_SIZE);
            if (!FirstSection) fputs(",\n", F);
            FirstSection = false;
            fputs("  \"consistency\": [\n", F);
            for (uint32_t I = 0; I < Count; I++) {
                const auto& E = mConsistencyRing[(Start + I) % CONSISTENCY_RING_SIZE];
                // Escape CheckName and Message minimally (no quotes or backslashes expected, but be safe)
                snprintf(Buf, sizeof(Buf),
                    "    {\"seq\":%llu,\"severity\":\"%s\",\"check\":\"%s\",\"message\":\"%s\"}%s\n",
                    (unsigned long long)E.Sequence,
                    SeverityName(E.Severity),
                    E.CheckName,
                    E.Message,
                    (I + 1 < Count) ? "," : "");
                fputs(Buf, F);
            }
            fputs("  ]", F);
        }
    }

    if (!FirstSection)
        fputs("\n", F);
    fputs("}\n", F);
    fclose(F);
    Logger::Log("{GRN}DumpJson written to %s{RESET}\n", Path.c_str());
}

void DiagCenter::EmitPeProbeHint(uint64_t FaultAddr, uint32_t Offset64k, char* OutBuf, size_t BufSize) {
    DiagProbeType Hint = (DiagProbeType)ComputePeProbeHint(FaultAddr);
    const char* Name = ProbeTypeName(Hint);
    snprintf(OutBuf, BufSize, "PE_PROBE[%s] off64k=0x%x", Name, Offset64k);
}

void DiagCenter::EmitRejectReason(DiagRejectReason R, char* OutBuf, size_t BufSize) {
    snprintf(OutBuf, BufSize, "%s", RejectReasonStr(R));
}

const char* DiagCenter::FormatVa(uint64_t Va) {
    snprintf(mFmtBuf, sizeof(mFmtBuf), "0x%016llx", (unsigned long long)Va);
    return mFmtBuf;
}

const char* DiagCenter::FormatModuleRva(uint64_t Va) {
    uint64_t Base = 0;
    uint32_t Rva = 0;
    char ModName[32] = {};
    if (ResolveVaToModule(Va, Base, Rva, ModName, sizeof(ModName))) {
        snprintf(mFmtBuf, sizeof(mFmtBuf), "%s+0x%x", ModName, Rva);
    } else {
        snprintf(mFmtBuf, sizeof(mFmtBuf), "0x%016llx", (unsigned long long)Va);
    }
    return mFmtBuf;
}

bool DiagCenter::IsPlausibleReturnAddress(uint64_t Va) {
    if (Va == 0 || Va == SENTINEL_RET_ADDR) return false;
    if (Va < 0xFFFFF00000000000ULL) return false;
    if (IsKuserSharedDataVa(Va)) return false;
    if (IsHypervisorSharedPageVa(Va)) return false;
    if (IsPoolVa(Va)) return false;
    if (IsStackVa(Va)) return false;
    if (IsEmulatorSentinelVa(Va)) return false;
    if (IsStringLikeData(Va)) return false;
    if (!IsCanonicalKernelVa(Va)) return false;
    if (!IsMappedExecutable(Va)) return false;
    return true;
}

bool DiagCenter::IsCanonicalKernelVa(uint64_t Va) {
    return (Va >= 0xFFFF800000000000ULL && Va <= 0xFFFFFFFFFFFFFFFULL);
}

bool DiagCenter::IsKuserSharedDataVa(uint64_t Va) {
    return (Va >= KUSD_BASE_UC && Va < KUSD_BASE_UC + 0x1000);
}

bool DiagCenter::IsHypervisorSharedPageVa(uint64_t Va) {
    return (Va >= HYPERVISOR_SHARED_PAGE_BASE_UC && Va < HYPERVISOR_SHARED_PAGE_BASE_UC + 0x1000);
}

bool DiagCenter::IsPoolVa(uint64_t Va) {
    return (Va >= POOL_BASE_UC && Va < POOL_BASE_UC + 0x200000000ULL);
}

bool DiagCenter::IsStackVa(uint64_t Va) {
    return (Va >= STACK_BASE_UC && Va < STACK_BASE_UC + STACK_SIZE_UC);
}

bool DiagCenter::IsEmulatorSentinelVa(uint64_t Va) {
    return (Va >= SENTINEL_BASE_UC && Va < SENTINEL_BASE_UC + SENTINEL_RANGE_SIZE);
}

bool DiagCenter::IsStringLikeData(uint64_t Va) {
    if (Va == 0) return false;
    uint8_t Lo = (uint8_t)(Va & 0xFF);
    uint8_t Hi = (uint8_t)((Va >> 8) & 0xFF);
    if (Lo >= 0x20 && Lo <= 0x7E && Hi >= 0x20 && Hi <= 0x7E) return true;
    uint8_t B3 = (uint8_t)((Va >> 16) & 0xFF);
    uint8_t B4 = (uint8_t)((Va >> 24) & 0xFF);
    if (Lo >= 0x20 && Lo <= 0x7E && Hi == 0 && B3 == 0 && B4 == 0) return true;
    return false;
}

bool DiagCenter::IsMappedExecutable(uint64_t Va) {
    std::shared_lock<std::shared_mutex> Guard(UnicornEmu::RegionsLock);
    for (auto& Region : UnicornEmu::MappedRegions) {
        if (Va >= Region.UcBase && Va < Region.UcBase + Region.Size) {
            return (Region.Perms & UC_PROT_EXEC) != 0;
        }
    }
    for (auto& Mod : UnicornEmu::MappedSysMods) {
        if (Va >= Mod.UcBase && Va < Mod.UcBase + Mod.Size) {
            return true;
        }
    }
    return false;
}

bool DiagCenter::ResolveVaToModule(uint64_t Va, uint64_t& OutBase, uint32_t& OutRva, char* OutModName, size_t NameSize) {
    std::shared_lock<std::shared_mutex> Guard(UnicornEmu::RegionsLock);
    for (auto& Region : UnicornEmu::MappedRegions) {
        if (Va >= Region.UcBase && Va < Region.UcBase + Region.Size) {
            OutBase = Region.UcBase;
            OutRva = (uint32_t)(Va - Region.UcBase);
            strncpy(OutModName, Region.Name.c_str(), NameSize - 1);
            OutModName[NameSize - 1] = '\0';
            return true;
        }
    }
    for (auto& Mod : UnicornEmu::MappedSysMods) {
        if (Va >= Mod.UcBase && Va < Mod.UcBase + Mod.Size) {
            OutBase = Mod.UcBase;
            OutRva = (uint32_t)(Va - Mod.UcBase);
            strncpy(OutModName, Mod.Name.c_str(), NameSize - 1);
            OutModName[NameSize - 1] = '\0';
            return true;
        }
    }
    OutBase = 0;
    OutRva = 0;
    OutModName[0] = '\0';
    return false;
}

bool DiagCenter::ResolveVaToRegionName(uint64_t Va, char* OutName, size_t NameSize) {
    std::shared_lock<std::shared_mutex> Guard(UnicornEmu::RegionsLock);
    for (auto& Region : UnicornEmu::MappedRegions) {
        if (Va >= Region.UcBase && Va < Region.UcBase + Region.Size) {
            strncpy(OutName, Region.Name.c_str(), NameSize - 1);
            OutName[NameSize - 1] = '\0';
            return true;
        }
    }
    if (Va >= KUSD_BASE_UC && Va < KUSD_BASE_UC + 0x1000) {
        strncpy(OutName, "KUSER_SHARED_DATA", NameSize - 1);
        OutName[NameSize - 1] = '\0';
        return true;
    }
    if (Va >= HYPERVISOR_SHARED_PAGE_BASE_UC && Va < HYPERVISOR_SHARED_PAGE_BASE_UC + 0x1000) {
        strncpy(OutName, "HV_SHARED_PAGE", NameSize - 1);
        OutName[NameSize - 1] = '\0';
        return true;
    }
    if (Va >= POOL_BASE_UC && Va < POOL_BASE_UC + 0x200000000ULL) {
        strncpy(OutName, "Pool", NameSize - 1);
        OutName[NameSize - 1] = '\0';
        return true;
    }
    if (Va >= STACK_BASE_UC && Va < STACK_BASE_UC + STACK_SIZE_UC) {
        strncpy(OutName, "Stack", NameSize - 1);
        OutName[NameSize - 1] = '\0';
        return true;
    }
    if (Va >= SENTINEL_BASE_UC && Va < SENTINEL_BASE_UC + SENTINEL_RANGE_SIZE) {
        strncpy(OutName, "Sentinel", NameSize - 1);
        OutName[NameSize - 1] = '\0';
        return true;
    }
    OutName[0] = '\0';
    return false;
}

bool DiagCenter::ResolveVaToPeSection(uint64_t Va, char* OutSection, size_t SecSize) {
    uint64_t Base = 0;
    uint32_t Rva = 0;
    char ModName[32] = {};
    if (!ResolveVaToModule(Va, Base, Rva, ModName, sizeof(ModName))) {
        OutSection[0] = '\0';
        return false;
    }

    void* HostPtr = UnicornMem::UcToHost(Base);
    if (!HostPtr) {
        OutSection[0] = '\0';
        return false;
    }

    auto Dos = (PIMAGE_DOS_HEADER)HostPtr;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) {
        OutSection[0] = '\0';
        return false;
    }

    auto Nt = (PIMAGE_NT_HEADERS)((uint8_t*)HostPtr + Dos->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE) {
        OutSection[0] = '\0';
        return false;
    }

    auto SectionHdr = IMAGE_FIRST_SECTION(Nt);
    for (int I = 0; I < Nt->FileHeader.NumberOfSections; I++) {
        uint32_t SecVa = SectionHdr[I].VirtualAddress;
        uint32_t SecSize = SectionHdr[I].Misc.VirtualSize;
        if (Rva >= SecVa && Rva < SecVa + SecSize) {
            strncpy(OutSection, (const char*)SectionHdr[I].Name, SecSize - 1);
            OutSection[SecSize - 1] = '\0';
            return true;
        }
    }

    strncpy(OutSection, "???", SecSize - 1);
    OutSection[SecSize - 1] = '\0';
    return false;
}

bool DiagCenter::ResolveVaToSymbol(uint64_t Va, char* OutSym, size_t SymSize) {
    uint64_t Base = 0;
    uint32_t Rva = 0;
    char ModName[32] = {};
    if (!ResolveVaToModule(Va, Base, Rva, ModName, sizeof(ModName))) {
        OutSym[0] = '\0';
        return false;
    }

    void* HostPtr = UnicornMem::UcToHost(Base);
    if (!HostPtr) {
        OutSym[0] = '\0';
        return false;
    }

    auto Dos = (PIMAGE_DOS_HEADER)HostPtr;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) {
        OutSym[0] = '\0';
        return false;
    }

    auto Nt = (PIMAGE_NT_HEADERS)((uint8_t*)HostPtr + Dos->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE) {
        OutSym[0] = '\0';
        return false;
    }

    auto& ExportDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ExportDir.VirtualAddress || !ExportDir.Size) {
        snprintf(OutSym, SymSize, "%s+0x%x", ModName, Rva);
        return true;
    }

    uint32_t ExportRva = ExportDir.VirtualAddress;
    auto ExportDirHdr = (PIMAGE_EXPORT_DIRECTORY)((uint8_t*)HostPtr + ExportRva);
    auto Names = (uint32_t*)((uint8_t*)HostPtr + ExportDirHdr->AddressOfNames);
    auto Ordinals = (uint16_t*)((uint8_t*)HostPtr + ExportDirHdr->AddressOfNameOrdinals);
    auto Functions = (uint32_t*)((uint8_t*)HostPtr + ExportDirHdr->AddressOfFunctions);

    for (DWORD I = 0; I < ExportDirHdr->NumberOfNames; I++) {
        uint32_t FuncRva = Functions[Ordinals[I]];
        if (FuncRva == Rva) {
            const char* FuncName = (const char*)((uint8_t*)HostPtr + Names[I]);
            snprintf(OutSym, SymSize, "%s!%s", ModName, FuncName);
            return true;
        }
    }

    uint32_t BestRva = 0;
    const char* BestName = nullptr;
    for (DWORD I = 0; I < ExportDirHdr->NumberOfNames; I++) {
        uint32_t FuncRva = Functions[Ordinals[I]];
        if (FuncRva <= Rva && FuncRva > BestRva) {
            BestRva = FuncRva;
            BestName = (const char*)((uint8_t*)HostPtr + Names[I]);
        }
    }

    if (BestName) {
        snprintf(OutSym, SymSize, "%s!%s+0x%x", ModName, BestName, Rva - BestRva);
        return true;
    }

    snprintf(OutSym, SymSize, "%s+0x%x", ModName, Rva);
    return true;
}

uint32_t DiagCenter::ComputePeProbeHint(uint64_t FaultAddr) {
    uint64_t Base = 0;
    uint32_t Rva = 0;
    char ModName[32] = {};
    if (!ResolveVaToModule(FaultAddr, Base, Rva, ModName, sizeof(ModName))) {
        return PROBE_UNKNOWN;
    }

    uint64_t Offset4k = FaultAddr & 0xFFF;
    uint64_t Offset64k = FaultAddr & 0xFFFF;

    if (Offset4k == 0x00) return PROBE_MZ;
    if (Offset4k == 0x3C) return PROBE_E_LFANEW;
    if (Offset64k <= 0x200) {
        void* HostPtr = UnicornMem::UcToHost(Base);
        if (HostPtr) {
            auto Dos = (PIMAGE_DOS_HEADER)HostPtr;
            if (Dos->e_magic == IMAGE_DOS_SIGNATURE && Dos->e_lfanew < 0x1000) {
                uint64_t PeSigAddr = Base + Dos->e_lfanew;
                if (FaultAddr == PeSigAddr) return PROBE_PE_SIGNATURE;
                if (FaultAddr == PeSigAddr + 4) return PROBE_PE_SIGNATURE;
                if (FaultAddr >= PeSigAddr + 0x18 && FaultAddr < PeSigAddr + 0x28) return PROBE_SIZE_OF_IMAGE;
                if (FaultAddr >= PeSigAddr + 0x10 && FaultAddr < PeSigAddr + 0x18) return PROBE_ADDRESS_OF_ENTRY_POINT;
                auto Nt = (PIMAGE_NT_HEADERS)((uint8_t*)HostPtr + Dos->e_lfanew);
                if (FaultAddr >= PeSigAddr + 0x18 + Nt->FileHeader.SizeOfOptionalHeader) return PROBE_SECTION_TABLE;
            }
        }
    }

    void* HostPtr = UnicornMem::UcToHost(Base);
    if (HostPtr) {
        auto Dos = (PIMAGE_DOS_HEADER)HostPtr;
        if (Dos->e_magic == IMAGE_DOS_SIGNATURE) {
            auto Nt = (PIMAGE_NT_HEADERS)((uint8_t*)HostPtr + Dos->e_lfanew);
            if (Nt->Signature == IMAGE_NT_SIGNATURE) {
                auto& ExportDataDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (ExportDataDir.VirtualAddress && FaultAddr >= Base + ExportDataDir.VirtualAddress &&
                    FaultAddr < Base + ExportDataDir.VirtualAddress + ExportDataDir.Size)
                    return PROBE_EXPORT_DIR;
                auto& ImportDataDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (ImportDataDir.VirtualAddress && FaultAddr >= Base + ImportDataDir.VirtualAddress &&
                    FaultAddr < Base + ImportDataDir.VirtualAddress + ImportDataDir.Size)
                    return PROBE_IMPORT_DIR;
                auto& RsrcDataDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
                if (RsrcDataDir.VirtualAddress && FaultAddr >= Base + RsrcDataDir.VirtualAddress &&
                    FaultAddr < Base + RsrcDataDir.VirtualAddress + RsrcDataDir.Size)
                    return PROBE_RSRC_DIR;
                auto& RelocDataDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
                if (RelocDataDir.VirtualAddress && FaultAddr >= Base + RelocDataDir.VirtualAddress &&
                    FaultAddr < Base + RelocDataDir.VirtualAddress + RelocDataDir.Size)
                    return PROBE_RELOC_DIR;
                auto& TlsDataDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
                if (TlsDataDir.VirtualAddress && FaultAddr >= Base + TlsDataDir.VirtualAddress &&
                    FaultAddr < Base + TlsDataDir.VirtualAddress + TlsDataDir.Size)
                    return PROBE_TLS_DIR;
            }
        }
    }

    if (Rva >= 0x1000 && (Offset4k == 0 || Offset4k == 0x3C || Offset4k == 0x80 || Offset4k == 0x40))
        return PROBE_DOS_HEADER_SCAN;

    return PROBE_UNKNOWN;
}

void DiagCenter::LogFormatted(const char* Prefix, const char* Msg) {
    Logger::Log("%s %s\n", Prefix, Msg);
}

void DiagCenter::RunConsistencyChecks() {
    ConsistencyEvent Ev = {};

    auto Check = [&](DiagSeverity Sev, const char* CheckName, const char* Msg, uint64_t Va1 = 0, uint64_t Va2 = 0, uint32_t Rva1 = 0, uint32_t Rva2 = 0) {
        Ev.Sequence = NextSeq();
        Ev.Severity = Sev;
        strncpy(Ev.CheckName, CheckName, sizeof(Ev.CheckName) - 1);
        strncpy(Ev.Message, Msg, sizeof(Ev.Message) - 1);
        Ev.Va1 = Va1;
        Ev.Va2 = Va2;
        Ev.Rva1 = Rva1;
        Ev.Rva2 = Rva2;
        RecordConsistency(Ev);
    };

    if (KusdBlock == nullptr) {
        Check(SEV_ERROR, "KUSD_Mapped", "KUSER_SHARED_DATA block is not allocated");
    }

    if (HypervisorSharedPageBlock == nullptr) {
        Check(SEV_WARN, "HVSP_Mapped", "Hypervisor shared page block is not allocated");
    }

    {
        bool FoundNtos = false;
        bool FoundDriver = false;
        std::shared_lock<std::shared_mutex> Guard(UnicornEmu::RegionsLock);
        for (auto& Region : UnicornEmu::MappedRegions) {
            if (Region.Name.find("Driver") != std::string::npos) FoundDriver = true;
        }
        for (auto& Mod : UnicornEmu::MappedSysMods) {
            std::string NameLower = Mod.Name;
            for (auto& C : NameLower) C = (char)tolower(C);
            if (NameLower.find("ntoskrnl") != std::string::npos) FoundNtos = true;
        }
        if (!FoundNtos) Check(SEV_ERROR, "NTOS_Mapped", "ntoskrnl.exe not found in system modules");
        if (!FoundDriver) Check(SEV_WARN, "Driver_Mapped", "Driver image not found in mapped regions");
    }

    const uint32_t CpuidTotal = mCpuidCount.load(std::memory_order_relaxed);
    const uint32_t CpuidIndex = mCpuidRingIdx.load(std::memory_order_relaxed);

    if (CpuidTotal > 0) {
        bool AnyHvLeaf = false;
        uint32_t CpuidCount = (CpuidTotal < CPUID_RING_SIZE) ? CpuidTotal : (uint32_t)CPUID_RING_SIZE;
        uint32_t Start = (CpuidTotal < CPUID_RING_SIZE) ? 0 : (CpuidIndex % CPUID_RING_SIZE);
        for (uint32_t I = 0; I < CpuidCount; I++) {
            uint32_t Idx = (Start + I) % CPUID_RING_SIZE;
            if (mCpuidRing[Idx].Leaf >= 0x40000000 && mCpuidRing[Idx].Leaf <= 0x4FFFFFFF) {
                AnyHvLeaf = true;
                break;
            }
        }
        if (AnyHvLeaf && HypervisorSharedPageBlock == nullptr) {
            Check(SEV_WARN, "HV_Consistency", "CPUID HV leaves queried but HV shared page not mapped");
        }
        if (!AnyHvLeaf && HypervisorSharedPageBlock != nullptr) {
            Check(SEV_INFO, "HV_Consistency", "HV shared page mapped but no CPUID HV leaf queries observed");
        }
    }

    if (mHvspCount > 0 && CpuidTotal > 0) {
        bool HasCpuidHvBit = false;
        uint32_t CpuidCount = (CpuidTotal < CPUID_RING_SIZE) ? CpuidTotal : (uint32_t)CPUID_RING_SIZE;
        uint32_t Start = (CpuidTotal < CPUID_RING_SIZE) ? 0 : (CpuidIndex % CPUID_RING_SIZE);
        for (uint32_t I = 0; I < CpuidCount; I++) {
            uint32_t Idx = (Start + I) % CPUID_RING_SIZE;
            if (mCpuidRing[Idx].Leaf == 1 && (mCpuidRing[Idx].PostEcx & (1 << 31))) {
                HasCpuidHvBit = true;
                break;
            }
        }
        if (mHvspCount > 0 && !HasCpuidHvBit) {
            Check(SEV_WARN, "HV_Bit_Consistency", "HV shared page read but CPUID.01.ECX hypervisor bit not observed in CPUID events");
        }
    }

    if (mModQueryCount > 0 && mSehCount > 0) {
        Check(SEV_INFO, "Query_SEH_Correlation", "Module queries and SEH events both observed, driver appears active");
    }

    uint32_t TotalReject = mStackRejectCount;
    uint32_t TotalAccept = mStackAcceptCount;
    if (TotalReject > 10 * TotalAccept && TotalReject > 100) {
        Check(SEV_WARN, "Stack_Reject_Ratio", "Stack rejection ratio very high, possible stack corruption or incorrect stack base");
    }

    const uint32_t ConsistencyTotal = mConsistencyCount.load(std::memory_order_relaxed);
    Logger::Log("{GRN}Consistency checks completed: %u checks recorded{RESET}\n", ConsistencyTotal);
}