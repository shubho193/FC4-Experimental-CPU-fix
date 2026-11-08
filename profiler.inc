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

// ------------------------------------------------------- hotspot capture ---
// Profiler=2: press F10 in game to sample which engine code the two heaviest
// threads run for 20 s. Writes fc4corefix-hot.log with:
//   self  - FC64 code addresses where samples landed (16-byte buckets)
//   incl  - FC64 call sites found on the stack (which callers the time is spent under)
// The first capture also saves the unpacked FC64.dll image (fc64_dump.bin) for
// offline disassembly - the file on disk is DRM-packed.
#define HOT_N 65536
#define CAP_MS 20000
typedef struct { DWORD key, n; } HotE;
static HotE g_hotSelf[2][HOT_N], g_hotIncl[2][HOT_N];
static int g_hotTotal[2], g_hotFc[2], g_hotDrv[2], g_hotWait[2];
static DWORD g_hotTid[2];
static int g_fcMod = -1;
static int g_capNo;
static volatile BOOL g_capActive;
// full call chains: one record per sample, written to fc4corefix-stacks-N.bin
#define CHAIN 128
typedef struct { BYTE thread, kind, depth, pad; DWORD rip; DWORD ret[CHAIN]; } StackRec;  // kind 0 engine, 1 d3d/driver, 2 wait/system
#define MAXREC 24000
static StackRec *g_recs; static int g_nrec;

static void HotAdd(HotE *t, DWORD key) {
    DWORD h = (key * 2654435761u) >> 16;
    for (int i = 0; i < HOT_N; i++) {
        HotE *e = &t[(h + i) & (HOT_N - 1)];
        if (e->key == key) { e->n++; return; }
        if (!e->key) { e->key = key; e->n = 1; return; }
    }
}
static int CmpHot(const void *a, const void *b) { return (int)((const HotE *)b)->n - (int)((const HotE *)a)->n; }

static void HotWrite(HANDLE f, const char *fmt, ...) {
    char buf[512]; va_list ap; va_start(ap, fmt);
    int n = _vsnprintf_s(buf, sizeof buf - 2, _TRUNCATE, fmt, ap); va_end(ap);
    if (n < 0) n = (int)strlen(buf);
    buf[n++] = '\r'; buf[n++] = '\n';
    DWORD w; WriteFile(f, buf, n, &w, NULL);
}

static void HotTop(HANDLE f, HotE *t, int total, const char *title) {
    static HotE tmp[HOT_N]; int n = 0;
    for (int i = 0; i < HOT_N; i++) if (t[i].key) tmp[n++] = t[i];
    qsort(tmp, n, sizeof(HotE), CmpHot);
    HotWrite(f, "  %s (top 40 of %d):", title, n);
    for (int i = 0; i < n && i < 40; i++)
        HotWrite(f, "    %5.1f%%  fc64+0x%07lx", tmp[i].n * 100.0 / total, tmp[i].key);
}

static void DumpFc64(void) {
    wchar_t p[MAX_PATH]; swprintf(p, MAX_PATH, L"%sfc64_dump.bin", g_dir);
    if (GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES) return;
    HANDLE f = CreateFileW(p, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    BYTE *base = g_mods[g_fcMod].base; SIZE_T size = g_mods[g_fcMod].size, skipped = 0;
    static BYTE page[4096];
    for (SIZE_T off = 0; off < size; off += 4096) {
        MEMORY_BASIC_INFORMATION mbi; BOOL ok = FALSE;
        if (VirtualQuery(base + off, &mbi, sizeof mbi) && mbi.State == MEM_COMMIT &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            __try { memcpy(page, base + off, 4096); ok = TRUE; } __except (1) { ok = FALSE; }
        }
        if (!ok) { ZeroMemory(page, 4096); skipped++; }
        DWORD w; WriteFile(f, page, 4096, &w, NULL);
    }
    CloseHandle(f);
    Log("hotspots: saved unpacked FC64 image (%llu MB, %llu pages unreadable) to fc64_dump.bin",
        (unsigned long long)(size >> 20), (unsigned long long)skipped);
}

static void HotReport(void) {
    wchar_t p[MAX_PATH]; swprintf(p, MAX_PATH, L"%sfc4corefix-hot.log", g_dir);
    HANDLE f = CreateFileW(p, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st; GetLocalTime(&st);
    HotWrite(f, "=== capture %d at %02d:%02d:%02d (%d s) ===", g_capNo, st.wHour, st.wMinute, st.wSecond, CAP_MS / 1000);
    for (int ti = 0; ti < 2; ti++) {
        int t = g_hotTotal[ti];
        if (t < 200) { HotWrite(f, "thread#%d: too few samples (%d)", ti + 1, t); continue; }
        HotWrite(f, "thread#%d tid=%lu (%s): %d samples | engine %.0f%%  d3d/driver %.0f%%  waits %.0f%%",
                 ti + 1, g_hotTid[ti], g_hotDrv[ti] * 100 > t * 5 ? "render" : "main/game", t,
                 g_hotFc[ti] * 100.0 / t, g_hotDrv[ti] * 100.0 / t, g_hotWait[ti] * 100.0 / t);
        HotTop(f, g_hotSelf[ti], t, "self: engine code running");
        HotTop(f, g_hotIncl[ti], t, "incl: engine call sites on the stack");
    }
    CloseHandle(f);
    if (g_recs && g_nrec) {
        swprintf(p, MAX_PATH, L"%sfc4corefix-stacks-%d.bin", g_dir, g_capNo);
        HANDLE sf = CreateFileW(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (sf != INVALID_HANDLE_VALUE) {
            DWORD hdr[4] = { 0x4b545346 /*FSTK*/, 1, (DWORD)g_nrec, CHAIN }, w;
            WriteFile(sf, hdr, sizeof hdr, &w, NULL);
            WriteFile(sf, g_recs, (DWORD)(g_nrec * sizeof(StackRec)), &w, NULL);
            CloseHandle(sf);
        }
    }
    Log("hotspots: capture %d written (%d stack samples)", g_capNo, g_nrec);
}

static DWORD WINAPI Profiler(LPVOID unused) {
    LoadNtExports();
    int openFail = 0, suspFail = 0, unfocused = 0, samples = 0;
    BOOL test = GetEnvironmentVariableW(L"FC4FIX_TEST", NULL, 0) > 0;
    DWORD windowMs = test ? 6000 : 30000;
    Sleep(test ? 1000 : 30000);
    HANDLE h[2] = { 0, 0 }; DWORD htid[2] = { 0, 0 };
    ULONG_PTR stackBase[2] = { 0, 0 };
    static ULONG_PTR stk[8192];
    for (;;) {
        RefreshMods();
        for (int i = 0; i < g_nmods; i++) if (!strcmp(g_mods[i].name, "fc64.dll")) g_fcMod = i;
        ZeroMemory(g_prof, sizeof g_prof);
        DWORD reportTid[2] = { g_heavy[0], g_heavy[1] };
        ULONGLONG start = GetTickCount64(); int iter = 0; BOOL focus = TRUE;
        while (GetTickCount64() - start < windowMs) {
            if (cfg.profiler >= 2 && g_fcMod >= 0) {          // F10 hotspot capture
                static ULONGLONG capEnd; static BOOL wasDown;
                BOOL down = (GetAsyncKeyState(VK_F10) & 0x8000) != 0;   // edge-detect: the game's own polling eats the "pressed" bit
                BOOL pressed = down && !wasDown; wasDown = down;
                if (!g_recs) g_recs = (StackRec *)VirtualAlloc(NULL, MAXREC * sizeof(StackRec), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!capEnd && pressed && focus) {
                    g_nrec = 0;
                    ZeroMemory(g_hotSelf, sizeof g_hotSelf); ZeroMemory(g_hotIncl, sizeof g_hotIncl);
                    ZeroMemory(g_hotTotal, sizeof g_hotTotal); ZeroMemory(g_hotFc, sizeof g_hotFc);
                    ZeroMemory(g_hotDrv, sizeof g_hotDrv); ZeroMemory(g_hotWait, sizeof g_hotWait);
                    g_hotTid[0] = g_heavy[0]; g_hotTid[1] = g_heavy[1];
                    g_capNo++; capEnd = GetTickCount64() + CAP_MS;
                    Log("hotspots: capture %d started (heavy threads %lu / %lu)", g_capNo, g_heavy[0], g_heavy[1]);
                    Beep(880, 150);
                } else if (capEnd && GetTickCount64() >= capEnd) {
                    capEnd = 0;
                    HotReport();
                    Beep(660, 120); Beep(660, 120);
                    DumpFc64();
                }
                g_capActive = capEnd != 0;
            }
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
                    htid[ti] = tid; stackBase[ti] = 0;
                    THREAD_BASIC_INFORMATION_ tbi;            // TEB->NtTib.StackBase bounds the stack copy
                    if (h[ti] && pNtQueryInformationThread &&
                        pNtQueryInformationThread(h[ti], 0, &tbi, sizeof tbi, NULL) >= 0 && tbi.TebBaseAddress)
                        __try { stackBase[ti] = *(ULONG_PTR *)((BYTE *)tbi.TebBaseAddress + 8); } __except (1) {}
                }
                if (!h[ti]) { openFail++; continue; }
                if (SuspendThread(h[ti]) == (DWORD)-1) { suspFail++; CloseHandle(h[ti]); h[ti] = 0; htid[ti] = 0; continue; }
                CONTEXT c; c.ContextFlags = CONTEXT_CONTROL;
                BOOL ok = GetThreadContext(h[ti], &c);
                int ns = 0;
                if (ok && stackBase[ti] > c.Rsp) {
                    SIZE_T bytes = stackBase[ti] - c.Rsp; if (bytes > sizeof stk) bytes = sizeof stk;
                    __try { memcpy(stk, (void *)c.Rsp, bytes); ns = (int)(bytes / sizeof(ULONG_PTR)); } __except (1) { ns = 0; }
                } else if (ok) {
                    __try { memcpy(stk, (void *)c.Rsp, 512 * sizeof(ULONG_PTR)); ns = 512; }
                    __except (1) {
                        __try { memcpy(stk, (void *)c.Rsp, 64 * sizeof(ULONG_PTR)); ns = 64; } __except (1) { ns = 0; }
                    }
                }
                ResumeThread(h[ti]);
                if (!ok) continue;
                Prof *p = &g_prof[ti]; p->total++; samples++;
                int m = ModOf(c.Rip);
                if (g_capActive && tid == g_hotTid[ti]) {
                    ULONG_PTR fb = (ULONG_PTR)g_mods[g_fcMod].base, fs = g_mods[g_fcMod].size;
                    g_hotTotal[ti]++;
                    BYTE kind = 2;
                    if (m == g_fcMod) { kind = 0; g_hotFc[ti]++; HotAdd(g_hotSelf[ti], (DWORD)(c.Rip - fb) & ~0xFu); }
                    else if (m >= 0 && !g_mods[m].sys) { kind = 1; g_hotDrv[ti]++; }
                    else g_hotWait[ti]++;
                    if (g_recs && g_nrec < MAXREC) {
                        StackRec *r = &g_recs[g_nrec++]; ZeroMemory(r, sizeof *r);
                        r->thread = (BYTE)ti; r->kind = kind;
                        r->rip = m == g_fcMod ? (DWORD)(c.Rip - fb) : 0xFFFFFFFFu;
                        for (int k = 0; k < ns && r->depth < CHAIN; k++)
                            if (stk[k] - fb < fs && LooksLikeReturn(stk[k])) r->ret[r->depth++] = (DWORD)(stk[k] - fb);
                    }
                    DWORD seen[8]; int nseen = 0;
                    for (int k = 0; k < ns && nseen < 8; k++) {
                        if (stk[k] - fb >= fs || !LooksLikeReturn(stk[k])) continue;
                        DWORD r = (DWORD)(stk[k] - fb); int dup = 0;
                        for (int j = 0; j < nseen; j++) if (seen[j] == r) dup = 1;
                        if (!dup) { seen[nseen++] = r; HotAdd(g_hotIncl[ti], r); }
                    }
                }
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

