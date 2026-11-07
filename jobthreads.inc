// ------------------------------------------------------- job thread count ---
// Profiling showed the engine's main thread spending ~27% of its time in
// NtSetEvent at FC64+0x1d8e9ed: a loop that wakes every sleeping job worker,
// one SetEvent syscall each, every time it dispatches a job batch. The engine
// creates one worker per logical CPU it sees (12 on a 6c/12t CPU). We make it
// see fewer CPUs (default: one per physical core) so it creates fewer workers
// and the main thread pays for far fewer wake-ups. Only the game's own queries
// about its process are changed; our code reads the real values.
static DWORD_PTR g_fakeMask, g_realSysMask;
static int g_fakeCount;
static SYSTEM_INFO g_siReal;
static volatile LONG g_cpuQueryLogged;

typedef struct { LONG ExitStatus; PVOID Peb; ULONG_PTR AffinityMask; LONG BasePriority;
                 ULONG_PTR Pid; ULONG_PTR Parent; } PROCESS_BASIC_INFORMATION_;
typedef LONG (NTAPI *NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static NtQIP_t pNtQueryInformationProcess;

static DWORD_PTR RealProcessMask(HANDLE h) {
    PROCESS_BASIC_INFORMATION_ pbi;
    if (pNtQueryInformationProcess && pNtQueryInformationProcess(h, 0, &pbi, sizeof pbi, NULL) >= 0)
        return pbi.AffinityMask;
    return 0;
}

static void LogCpuQuery(const char *api, void *ret) {
    if (InterlockedIncrement(&g_cpuQueryLogged) > 24) return;
    HMODULE hm = NULL; char path[MAX_PATH] = "?"; const char *base = path;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)ret, &hm)) {
        GetModuleFileNameA(hm, path, MAX_PATH);
        const char *s = strrchr(path, '\\'); if (s) base = s + 1;
    }
    Log("cpu query %-24s from %s+0x%llx -> reports %d CPUs", api, base,
        (unsigned long long)((BYTE *)ret - (BYTE *)hm), g_fakeCount);
}

static BOOL WINAPI Hk_GetProcessAffinityMask(HANDLE h, PDWORD_PTR pm, PDWORD_PTR sm) {
    if (!pm || !sm) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    DWORD_PTR r = RealProcessMask(h);
    if (!r) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    BOOL self = h == GetCurrentProcess() || GetProcessId(h) == GetCurrentProcessId();
    if (self) {
        *pm = (r & g_fakeMask) ? (r & g_fakeMask) : r;
        *sm = g_fakeMask;
        LogCpuQuery("GetProcessAffinityMask", _ReturnAddress());
    } else { *pm = r; *sm = g_realSysMask; }
    return TRUE;
}

static void FakeSI(LPSYSTEM_INFO p) {
    *p = g_siReal;
    p->dwNumberOfProcessors = (DWORD)g_fakeCount;
    p->dwActiveProcessorMask = g_fakeMask;
}
static void WINAPI Hk_GetSystemInfo(LPSYSTEM_INFO p) {
    if (!p) return;
    FakeSI(p); LogCpuQuery("GetSystemInfo", _ReturnAddress());
}
static void WINAPI Hk_GetNativeSystemInfo(LPSYSTEM_INFO p) {
    if (!p) return;
    FakeSI(p); LogCpuQuery("GetNativeSystemInfo", _ReturnAddress());
}
static DWORD WINAPI Hk_GetActiveProcessorCount(WORD group) {
    LogCpuQuery("GetActiveProcessorCount", _ReturnAddress());
    return (DWORD)g_fakeCount;
}

static void InstallJobThreadLimit(void) {
    pNtQueryInformationProcess = (NtQIP_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    GetSystemInfo(&g_siReal);                     // real values, captured before hooking
    g_realSysMask = g_siReal.dwActiveProcessorMask;
    // pick the first logical CPU of each physical core, up to the requested count
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION info[256]; DWORD len = sizeof info;
    if (!pNtQueryInformationProcess || !GetLogicalProcessorInformation(info, &len)) { Log("job threads: topology query failed"); return; }
    int want = cfg.jobCpus, cores = 0;
    for (DWORD i = 0; i < len / sizeof info[0]; i++) {
        if (info[i].Relationship != RelationProcessorCore) continue;
        cores++;
        if (g_fakeCount < want) {
            DWORD_PTR m = info[i].ProcessorMask;
            g_fakeMask |= m & (~m + 1);
            g_fakeCount++;
        }
    }
    if (g_fakeCount < 2 || g_fakeCount >= (int)g_siReal.dwNumberOfProcessors) {
        Log("job threads: nothing to do (%d of %lu CPUs)", g_fakeCount, g_siReal.dwNumberOfProcessors);
        g_fakeMask = 0; g_fakeCount = 0; return;
    }
    Log("job threads: engine will see %d CPUs (mask 0x%04llx) instead of %lu  [%d physical cores]",
        g_fakeCount, (unsigned long long)g_fakeMask, g_siReal.dwNumberOfProcessors, cores);
    Hook("GetProcessAffinityMask", Hk_GetProcessAffinityMask);
    Hook("GetSystemInfo", Hk_GetSystemInfo);
    Hook("GetNativeSystemInfo", Hk_GetNativeSystemInfo);
    Hook("GetActiveProcessorCount", Hk_GetActiveProcessorCount);
}

