// ---------------------------------------------------------- wait profiler ---
// Samples the two heaviest game threads ~1000x/s (suspend, read RIP + a copy of
// the stack top, resume) and reports where they spend time: engine code, the
// GPU driver, or blocked in a system wait - and, for waits, which engine code
// made the call (with code bytes around the call site for offline disassembly).
// Nothing is called while a thread is suspended except GetThreadContext/memcpy.
static volatile DWORD g_heavy[2];

typedef struct { BYTE *base; SIZE_T size; char name[40]; int sys; } ModInfo;
static ModInfo g_mods[512]; static int g_nmods;
typedef struct { DWORD rva; const char *name; } Exp;
static Exp g_ntExp[4096]; static int g_nNtExp; static BYTE *g_ntBase;

static int CmpExp(const void *a, const void *b) {
    DWORD x = ((const Exp *)a)->rva, y = ((const Exp *)b)->rva; return (x > y) - (x < y);
}

static void LoadNtExports(void) {
    g_ntBase = (BYTE *)GetModuleHandleW(L"ntdll.dll");
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(g_ntBase + ((IMAGE_DOS_HEADER *)g_ntBase)->e_lfanew);
    IMAGE_DATA_DIRECTORY dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *ed = (IMAGE_EXPORT_DIRECTORY *)(g_ntBase + dd.VirtualAddress);
    DWORD *names = (DWORD *)(g_ntBase + ed->AddressOfNames), *funcs = (DWORD *)(g_ntBase + ed->AddressOfFunctions);
    WORD *ords = (WORD *)(g_ntBase + ed->AddressOfNameOrdinals);
    for (DWORD i = 0; i < ed->NumberOfNames && g_nNtExp < 4096; i++) {
        g_ntExp[g_nNtExp].rva = funcs[ords[i]];
        g_ntExp[g_nNtExp].name = (const char *)(g_ntBase + names[i]);
        g_nNtExp++;
    }
    qsort(g_ntExp, g_nNtExp, sizeof(Exp), CmpExp);
}

static const char *NtName(ULONG_PTR a) {
    DWORD rva = (DWORD)(a - (ULONG_PTR)g_ntBase); const char *best = "ntdll?";
    for (int i = 0; i < g_nNtExp && g_ntExp[i].rva <= rva; i++) best = g_ntExp[i].name;
    return best;
}

static void RefreshMods(void) {
    HMODULE hm[512]; DWORD need = 0;
    if (!K32EnumProcessModules(GetCurrentProcess(), hm, sizeof hm, &need)) return;
    int n = (int)(need / sizeof(HMODULE)); if (n > 512) n = 512;
    static const char *sysm[] = { "ntdll.dll", "kernelbase.dll", "kernel32.dll", "win32u.dll", "user32.dll",
                                  "gdi32.dll", "gdi32full.dll", "msvcr100.dll", "ucrtbase.dll", "combase.dll", NULL };
    for (int i = 0; i < n; i++) {
        MODULEINFO mi; ModInfo *m = &g_mods[i];
        K32GetModuleInformation(GetCurrentProcess(), hm[i], &mi, sizeof mi);
        m->base = (BYTE *)mi.lpBaseOfDll; m->size = mi.SizeOfImage;
        K32GetModuleBaseNameA(GetCurrentProcess(), hm[i], m->name, sizeof m->name);
        for (char *c = m->name; *c; c++) if (*c >= 'A' && *c <= 'Z') *c += 32;
        m->sys = 0;
        for (int k = 0; sysm[k]; k++) if (!strcmp(m->name, sysm[k])) m->sys = 1;
    }
    g_nmods = n;
}

static int ModOf(ULONG_PTR a) {
    for (int i = 0; i < g_nmods; i++)
        if (a >= (ULONG_PTR)g_mods[i].base && a < (ULONG_PTR)g_mods[i].base + g_mods[i].size) return i;
    return -1;
}

static BOOL LooksLikeReturn(ULONG_PTR a) {          // a call instruction ends right before a?
    __try {
        BYTE *p = (BYTE *)a;
        if (p[-5] == 0xE8) return TRUE;                                   // call rel32
        if (p[-6] == 0xFF && p[-5] == 0x15) return TRUE;                  // call [rip+x]
        if (p[-2] == 0xFF && (p[-1] & 0xF8) == 0xD0) return TRUE;         // call reg
        if (p[-3] == 0x41 && p[-2] == 0xFF && (p[-1] & 0xF8) == 0xD0) return TRUE;
        if (p[-3] == 0xFF && (p[-2] & 0x38) == 0x10) return TRUE;         // call [reg+d8]
        if (p[-6] == 0xFF && (p[-5] & 0x38) == 0x10) return TRUE;         // call [reg+d32]
    } __except (1) {}
    return FALSE;
}

typedef struct { const char *what; int callerMod; DWORD callerOff; int n; } Bucket;
typedef struct { Bucket b[512]; int nb; int total, inSys; int perMod[512]; } Prof;
static Prof g_prof[2];

static void Count(Prof *p, const char *what, int cm, DWORD co) {
    for (int i = 0; i < p->nb; i++)
        if (p->b[i].what == what && p->b[i].callerMod == cm && p->b[i].callerOff == co) { p->b[i].n++; return; }
    if (p->nb < 512) {
        p->b[p->nb].what = what; p->b[p->nb].callerMod = cm; p->b[p->nb].callerOff = co; p->b[p->nb].n = 1; p->nb++;
    }
}

static int CmpBucket(const void *a, const void *b) { return ((const Bucket *)b)->n - ((const Bucket *)a)->n; }

static void Report(int ti, DWORD tid, double secs) {
    Prof *p = &g_prof[ti];
    if (p->total < 500) return;
    char line[500]; int n = 0;
    n += _snprintf_s(line + n, sizeof line - n, _TRUNCATE, "PROFILE thread#%d tid=%lu %.0fs %d samples | running in:",
                     ti + 1, tid, secs, p->total);
    for (int i = 0; i < g_nmods; i++)
        if (!g_mods[i].sys && p->perMod[i] * 100 >= p->total * 2)
            n += _snprintf_s(line + n, sizeof line - n, _TRUNCATE, " %s %d%%", g_mods[i].name, p->perMod[i] * 100 / p->total);
    _snprintf_s(line + n, sizeof line - n, _TRUNCATE, " | in system calls/waits %d%%", p->inSys * 100 / p->total);
    Log("%s", line);
    qsort(p->b, p->nb, sizeof(Bucket), CmpBucket);
    for (int i = 0; i < p->nb && i < 8; i++) {
        Bucket *b = &p->b[i];
        if (b->n * 100 < p->total * 2) break;
        const char *cm = b->callerMod >= 0 ? g_mods[b->callerMod].name : "?";
        Log("   %3d%%  %-28s called from %s+0x%lx", b->n * 100 / p->total, b->what, cm, b->callerOff);
        if (b->callerMod >= 0 && i < 4) {      // code bytes around the call site
            BYTE *ra = g_mods[b->callerMod].base + b->callerOff; char hex[300]; int h = 0;
            hex[0] = 0;
            __try { for (int k = -64; k < 16; k++) h += _snprintf_s(hex + h, sizeof hex - h, _TRUNCATE, "%02x", ra[k]); }
            __except (1) { hex[h] = 0; }
            Log("         bytes[-64..+16]: %s", hex);
        }
    }
}

static DWORD WINAPI Profiler(LPVOID unused) {
    LoadNtExports();
    int openFail = 0, suspFail = 0, unfocused = 0, samples = 0;
    BOOL test = GetEnvironmentVariableW(L"FC4FIX_TEST", NULL, 0) > 0;
    DWORD windowMs = test ? 6000 : 30000;
    Sleep(test ? 1000 : 30000);
    HANDLE h[2] = { 0, 0 }; DWORD htid[2] = { 0, 0 };
    static ULONG_PTR stk[512];
    for (;;) {
        RefreshMods();
        ZeroMemory(g_prof, sizeof g_prof);
        DWORD reportTid[2] = { g_heavy[0], g_heavy[1] };
        ULONGLONG start = GetTickCount64(); int iter = 0; BOOL focus = TRUE;
        while (GetTickCount64() - start < windowMs) {
            if ((iter++ & 63) == 0) {
                DWORD pid = 0; GetWindowThreadProcessId(GetForegroundWindow(), &pid);
                focus = test || pid == GetCurrentProcessId();
                if (!focus) unfocused++;
            }
            for (int ti = 0; ti < 2 && focus; ti++) {
                DWORD tid = g_heavy[ti];
                if (tid != reportTid[ti]) {
                    Report(ti, reportTid[ti], (GetTickCount64() - start) / 1000.0);
                    ZeroMemory(&g_prof[ti], sizeof g_prof[ti]); reportTid[ti] = tid;
                }
                if (!tid) continue;
                if (tid != htid[ti]) {
                    if (h[ti]) CloseHandle(h[ti]);
                    h[ti] = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
                    htid[ti] = tid;
                }
                if (!h[ti]) { openFail++; continue; }
                if (SuspendThread(h[ti]) == (DWORD)-1) { suspFail++; CloseHandle(h[ti]); h[ti] = 0; htid[ti] = 0; continue; }
                CONTEXT c; c.ContextFlags = CONTEXT_CONTROL;
                BOOL ok = GetThreadContext(h[ti], &c);
                int ns = 0;
                if (ok) {
                    __try { memcpy(stk, (void *)c.Rsp, sizeof stk); ns = 512; }
                    __except (1) {
                        __try { memcpy(stk, (void *)c.Rsp, 64 * sizeof(ULONG_PTR)); ns = 64; } __except (1) { ns = 0; }
                    }
                }
                ResumeThread(h[ti]);
                if (!ok) continue;
                Prof *p = &g_prof[ti]; p->total++; samples++;
                int m = ModOf(c.Rip);
                if (m >= 0 && !g_mods[m].sys) { p->perMod[m]++; continue; }
                p->inSys++;
                const char *what = (m >= 0 && g_mods[m].base == g_ntBase) ? NtName(c.Rip)
                                 : (m >= 0 ? g_mods[m].name : "unknown");
                int cm = -1; DWORD co = 0;
                for (int k = 0; k < ns; k++) {
                    int mm = ModOf(stk[k]);
                    if (mm >= 0 && !g_mods[mm].sys && LooksLikeReturn(stk[k])) {
                        cm = mm; co = (DWORD)(stk[k] - (ULONG_PTR)g_mods[mm].base); break;
                    }
                }
                Count(p, what, cm, co);
            }
            Sleep(1);
        }
        double secs = (GetTickCount64() - start) / 1000.0;
        Report(0, reportTid[0], secs);
        Report(1, reportTid[1], secs);
        Log("profiler: %.0fs window, %d samples, heavy=%lu/%lu, openFail=%d suspendFail=%d unfocusedChecks=%d",
            secs, samples, g_heavy[0], g_heavy[1], openFail, suspFail, unfocused);
        samples = openFail = suspFail = unfocused = 0;
    }
    return 0;
}

