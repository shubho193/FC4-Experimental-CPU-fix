// FC4CoreFix - dinput8.dll proxy for Far Cry 4 (x64)
//
// Findings (from this mod's own logs): the engine pins 12 job workers one per
// logical CPU after a CPU-detection pass; this DLL lets them float. It also
// sets 1 ms timer resolution, opts out of power throttling, and converts the
// game's legacy blt-model swap chain to flip model (see presentation fix).
//
// FC64.dll is DRM-packed and resolves APIs at runtime, so IAT hooks are useless;
// we inline-patch the real implementations in kernelbase.dll instead. The
// replacements never call the originals, so no trampolines are needed.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <unknwn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <intrin.h>
#define COBJMACROS
#include <d3d11.h>
#include <dxgi1_5.h>

#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "dxguid.lib")
__declspec(dllimport) UINT WINAPI timeBeginPeriod(UINT);

// ---------------------------------------------------------------- config ---
static struct {
    int unpinThreads;      // neuter thread affinity / ideal-processor calls
    int blockProcessMask;  // ignore the game's SetProcessAffinityMask on itself
    int timerResolution;   // timeBeginPeriod(1)
    int noPowerThrottle;   // opt out of EcoQoS / timer-resolution throttling
    int priorityClass;     // 0 = leave, 1 = above normal, 2 = high
    int avoidCpu0;         // also exclude CPU0 (+ its SMT sibling) from process
    int log;               // write fc4corefix.log
    int forceFlip;         // convert the swap chain to flip model
    int allowTearing;      // allow tearing when the game presents uncapped (VSync off)
    int flipBuffers;       // back buffers for the flip swap chain (2-4)
    int dedicatedCores;    // give the 2 heaviest game threads their own physical cores
    int skipIntro;         // add the game's own -skipintro option to its command line
    int profiler;          // sample where the heaviest threads wait (writes to log)
    int jobCpus;           // CPUs the engine sees when sizing its job-worker pool (0 = real)
} cfg = { 1, 1, 1, 1, 0, 0, 1, 0, 1, 3, 1, 1, 1, 6 };

static wchar_t g_dir[MAX_PATH];

static void LoadConfig(void) {
    wchar_t ini[MAX_PATH];
    swprintf(ini, MAX_PATH, L"%sfc4corefix.ini", g_dir);
#define RD(k, f) cfg.f = GetPrivateProfileIntW(L"FC4CoreFix", L##k, cfg.f, ini)
    RD("UnpinThreads", unpinThreads);
    RD("BlockProcessAffinity", blockProcessMask);
    RD("TimerResolution", timerResolution);
    RD("DisablePowerThrottling", noPowerThrottle);
    RD("PriorityClass", priorityClass);
    RD("AvoidCPU0", avoidCpu0);
    RD("Log", log);
    RD("ForceFlipModel", forceFlip);
    RD("AllowTearing", allowTearing);
    RD("FlipBuffers", flipBuffers);
    RD("DedicatedCores", dedicatedCores);
    RD("SkipIntro", skipIntro);
    RD("Profiler", profiler);
    RD("JobThreadCPUs", jobCpus);
    if (cfg.flipBuffers < 2) cfg.flipBuffers = 2;
    if (cfg.flipBuffers > 4) cfg.flipBuffers = 4;
#undef RD
}

// --------------------------------------------------------------- logging ---
static CRITICAL_SECTION g_logCs;
static HANDLE g_log = INVALID_HANDLE_VALUE;
static volatile LONG g_logLines;

static void Log(const char *fmt, ...) {
    if (!cfg.log || g_log == INVALID_HANDLE_VALUE) return;
    if (InterlockedIncrement(&g_logLines) > 6000) return;
    char buf[512];
    SYSTEMTIME st; GetLocalTime(&st);
    int n = _snprintf_s(buf, sizeof buf, _TRUNCATE, "[%02d:%02d:%02d.%03d] ",
                        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap; va_start(ap, fmt);
    int m = _vsnprintf_s(buf + n, sizeof buf - n - 2, _TRUNCATE, fmt, ap);
    va_end(ap);
    if (m < 0) m = (int)strlen(buf + n);
    n += m; buf[n++] = '\r'; buf[n++] = '\n';
    DWORD w;
    EnterCriticalSection(&g_logCs);
    WriteFile(g_log, buf, n, &w, NULL);
    LeaveCriticalSection(&g_logCs);
}

static int Hook(const char *name, void *dst);
#include "jobthreads.inc"

// ------------------------------------------------------------- ntdll bits ---
typedef struct {
    LONG ExitStatus; PVOID TebBaseAddress;
    struct { HANDLE UniqueProcess, UniqueThread; } ClientId;
    KAFFINITY AffinityMask; LONG Priority, BasePriority;
} THREAD_BASIC_INFORMATION_;
typedef LONG (NTAPI *NtQIT_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
static NtQIT_t pNtQueryInformationThread;

static BOOL IsOwnThread(HANDLE h) {
    if (h == GetCurrentThread()) return TRUE;
    DWORD pid = GetProcessIdOfThread(h);
    return pid == 0 || pid == GetCurrentProcessId();
}

static DWORD_PTR CurrentThreadMask(HANDLE h) {
    THREAD_BASIC_INFORMATION_ tbi;
    if (pNtQueryInformationThread &&
        pNtQueryInformationThread(h, 0, &tbi, sizeof tbi, NULL) >= 0 && tbi.AffinityMask)
        return tbi.AffinityMask;
    DWORD_PTR pm, sm;
    DWORD_PTR r = RealProcessMask(GetCurrentProcess()); (void)pm; (void)sm;
    return r ? r : 1;
}

// ----------------------------------------------------------- replacements ---
static DWORD_PTR WINAPI Hk_SetThreadAffinityMask(HANDLE h, DWORD_PTR mask) {
    DWORD_PTR prev = CurrentThreadMask(h);
    Log("SetThreadAffinityMask  tid=%5lu  req=0x%04llx  -> ignored (stays 0x%04llx)",
        GetThreadId(h), (unsigned long long)mask, (unsigned long long)prev);
    return prev;  // non-zero = success, previous mask
}

static DWORD WINAPI Hk_SetThreadIdealProcessor(HANDLE h, DWORD ideal) {
    Log("SetThreadIdealProcessor tid=%5lu  req=%lu -> ignored", GetThreadId(h), ideal);
    return 0;     // "previous ideal processor" = 0, success
}

static BOOL WINAPI Hk_SetThreadIdealProcessorEx(HANDLE h, PPROCESSOR_NUMBER ideal,
                                               PPROCESSOR_NUMBER prev) {
    Log("SetThreadIdealProcessorEx tid=%5lu req=%u:%u -> ignored", GetThreadId(h),
        ideal ? ideal->Group : 0, ideal ? ideal->Number : 0);
    if (prev) ZeroMemory(prev, sizeof *prev);
    return TRUE;
}

static BOOL WINAPI Hk_SetThreadGroupAffinity(HANDLE h, const GROUP_AFFINITY *ga,
                                            PGROUP_AFFINITY prev) {
    Log("SetThreadGroupAffinity tid=%5lu  req=%u:0x%04llx -> ignored", GetThreadId(h),
        ga ? ga->Group : 0, ga ? (unsigned long long)ga->Mask : 0ull);
    if (prev) { ZeroMemory(prev, sizeof *prev); prev->Mask = CurrentThreadMask(h); }
    return TRUE;
}

static BOOL WINAPI Hk_SetProcessAffinityMask(HANDLE hp, DWORD_PTR mask) {
    Log("SetProcessAffinityMask req=0x%04llx -> ignored", (unsigned long long)mask);
    return TRUE;
}

// Thread-handle checks: when the target is another process, we can't call the
// original (no trampoline). The game never does this; fall back to NtSet via
// SetThreadGroupAffinity-free path is not needed - just report success.
// (Kept simple on purpose.)

// ------------------------------------------------------------ inline hook ---
static BYTE *FollowJumps(BYTE *p) {
    for (int i = 0; i < 6 && p; i++) {
        if (p[0] == 0xFF && p[1] == 0x25)                          // jmp [rip+x]
            p = *(BYTE **)(p + 6 + *(INT32 *)(p + 2));
        else if (p[0] == 0x48 && p[1] == 0xFF && p[2] == 0x25)     // rex jmp [rip+x]
            p = *(BYTE **)(p + 7 + *(INT32 *)(p + 3));
        else if (p[0] == 0xE9)                                     // jmp rel32
            p = p + 5 + *(INT32 *)(p + 1);
        else if (p[0] == 0xEB)                                     // jmp rel8
            p = p + 2 + *(INT8 *)(p + 1);
        else break;
    }
    return p;
}

static int Hook(const char *name, void *dst) {
    HMODULE kb = GetModuleHandleW(L"kernelbase.dll");
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    BYTE *p = kb ? (BYTE *)GetProcAddress(kb, name) : NULL;
    if (!p && k32) p = (BYTE *)GetProcAddress(k32, name);
    if (!p) { Log("hook %-26s : not found", name); return 0; }
    p = FollowJumps(p);
    // sanity: refuse if the first 12 bytes run into padding/ret (tiny stub)
    for (int i = 0; i < 12; i++)
        if (p[i] == 0xCC && p[i + 1] == 0xCC) { Log("hook %-26s : too short", name); return 0; }

    BYTE patch[12] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };  // mov rax,imm64; jmp rax
    *(void **)(patch + 2) = dst;
    DWORD old;
    if (!VirtualProtect(p, sizeof patch, PAGE_EXECUTE_READWRITE, &old)) {
        Log("hook %-26s : VirtualProtect failed (%lu)", name, GetLastError()); return 0;
    }
    memcpy(p, patch, sizeof patch);
    VirtualProtect(p, sizeof patch, old, &old);
    FlushInstructionCache(GetCurrentProcess(), p, sizeof patch);
    Log("hook %-26s : ok @ %p", name, p);
    return 1;
}

// ------------------------------------------------- presentation fix (DXGI) ---
// Measured problem: FC4 creates a legacy blt-model swap chain (DXGI_SWAP_EFFECT_
// DISCARD), which Windows presents as "Composed: Copy with GPU GDI" - an extra
// copy + DWM composition per frame (and a cross-adapter copy on Optimus laptops).
// GPU work was ~12 ms/frame but frames were delivered every ~17 ms.
// Fix: intercept swap-chain creation and convert it to FLIP_DISCARD (+ tearing
// when uncapped), the modern path that allows independent flip. If the game's
// description can't be converted safely, or creation fails, we fall back to the
// original description untouched.

typedef HRESULT (WINAPI *CreateFactory_t)(REFIID, void **);
typedef HRESULT (WINAPI *CreateFactory2_t)(UINT, REFIID, void **);
typedef HRESULT (STDMETHODCALLTYPE *CreateSwapChain_t)(IDXGIFactory *, IUnknown *, DXGI_SWAP_CHAIN_DESC *, IDXGISwapChain **);
typedef HRESULT (STDMETHODCALLTYPE *Present_t)(IDXGISwapChain *, UINT, UINT);
typedef HRESULT (STDMETHODCALLTYPE *ResizeBuffers_t)(IDXGISwapChain *, UINT, UINT, UINT, DXGI_FORMAT, UINT);

static CreateSwapChain_t oCreateSwapChain;
static Present_t oPresent;
static ResizeBuffers_t oResizeBuffers;
static CRITICAL_SECTION g_dxgiCs;
static IDXGISwapChain *g_flipSc;      // the game swap chain we converted
static BOOL g_tearing;                // tearing flag set on g_flipSc
static BOOL g_srgb;                   // game asked for an sRGB back buffer
static void *g_backBuffer;            // raw (unreferenced) back buffer of g_flipSc

// flip model forbids *_SRGB swap-chain formats but allows sRGB views of them
static DXGI_FORMAT StripSrgb(DXGI_FORMAT f) {
    if (f == DXGI_FORMAT_R8G8B8A8_UNORM_SRGB) return DXGI_FORMAT_R8G8B8A8_UNORM;
    if (f == DXGI_FORMAT_B8G8R8A8_UNORM_SRGB) return DXGI_FORMAT_B8G8R8A8_UNORM;
    return f;
}
static DXGI_FORMAT AddSrgb(DXGI_FORMAT f) {
    if (f == DXGI_FORMAT_R8G8B8A8_UNORM) return DXGI_FORMAT_R8G8B8A8_UNORM_SRGB;
    if (f == DXGI_FORMAT_B8G8R8A8_UNORM) return DXGI_FORMAT_B8G8R8A8_UNORM_SRGB;
    return f;
}

typedef HRESULT (STDMETHODCALLTYPE *CreateRTV_t)(ID3D11Device *, ID3D11Resource *,
                                                 const D3D11_RENDER_TARGET_VIEW_DESC *, ID3D11RenderTargetView **);
static CreateRTV_t oCreateRTV;

static void RefreshBackBuffer(IDXGISwapChain *sc) {
    ID3D11Texture2D *bb = NULL;
    g_backBuffer = NULL;
    if (SUCCEEDED(IDXGISwapChain_GetBuffer(sc, 0, &IID_ID3D11Texture2D, (void **)&bb)) && bb) {
        g_backBuffer = bb;
        ID3D11Texture2D_Release(bb);
    }
}

static HRESULT STDMETHODCALLTYPE Hk_CreateRTV(ID3D11Device *dev, ID3D11Resource *res,
                                              const D3D11_RENDER_TARGET_VIEW_DESC *desc,
                                              ID3D11RenderTargetView **out) {
    if (g_srgb && res && (void *)res == g_backBuffer) {
        D3D11_RENDER_TARGET_VIEW_DESC d;
        ID3D11Texture2D *t = (ID3D11Texture2D *)res;
        D3D11_TEXTURE2D_DESC td; ID3D11Texture2D_GetDesc(t, &td);
        if (desc) d = *desc;
        else { ZeroMemory(&d, sizeof d); d.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D; d.Format = td.Format; }
        d.Format = AddSrgb(d.Format == DXGI_FORMAT_UNKNOWN ? td.Format : d.Format);
        return oCreateRTV(dev, res, &d, out);
    }
    return oCreateRTV(dev, res, desc, out);
}

// --- export hook that temporarily restores the original bytes to call it ---
typedef struct { BYTE *addr; BYTE orig[12]; BYTE patch[12]; } ExportHook;
static ExportHook hkCF, hkCF1, hkCF2;

static int PatchExport(ExportHook *h, HMODULE mod, const char *name, void *dst) {
    BYTE *p = (BYTE *)GetProcAddress(mod, name);
    if (!p) return 0;
    p = FollowJumps(p);
    BYTE patch[12] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };
    *(void **)(patch + 2) = dst;
    DWORD old;
    if (!VirtualProtect(p, 12, PAGE_EXECUTE_READWRITE, &old)) return 0;  // stays RWX
    memcpy(h->orig, p, 12); memcpy(h->patch, patch, 12);
    memcpy(p, patch, 12);
    FlushInstructionCache(GetCurrentProcess(), p, 12);
    h->addr = p;
    return 1;
}
static void Unpatch(ExportHook *h) { memcpy(h->addr, h->orig, 12); FlushInstructionCache(GetCurrentProcess(), h->addr, 12); }
static void Repatch(ExportHook *h) { memcpy(h->addr, h->patch, 12); FlushInstructionCache(GetCurrentProcess(), h->addr, 12); }

static void PatchVt(void **slot, void *dst, void **orig) {
    DWORD old;
    if (*slot == dst) return;
    if (VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &old)) {
        if (!*orig) *orig = *slot;
        *slot = dst;
        VirtualProtect(slot, sizeof(void *), old, &old);
    }
}

static BOOL FlipFormatOk(DXGI_FORMAT f) {
    return f == DXGI_FORMAT_R8G8B8A8_UNORM || f == DXGI_FORMAT_B8G8R8A8_UNORM ||
           f == DXGI_FORMAT_R10G10B10A2_UNORM || f == DXGI_FORMAT_R16G16B16A16_FLOAT;
}

static BOOL TearingSupported(IDXGIFactory *f) {
    IDXGIFactory5 *f5 = NULL; BOOL ok = FALSE;
    if (SUCCEEDED(IDXGIFactory_QueryInterface(f, &IID_IDXGIFactory5, (void **)&f5)) && f5) {
        if (FAILED(IDXGIFactory5_CheckFeatureSupport(f5, DXGI_FEATURE_PRESENT_ALLOW_TEARING, &ok, sizeof ok))) ok = FALSE;
        IDXGIFactory5_Release(f5);
    }
    return ok;
}

static HRESULT STDMETHODCALLTYPE Hk_Present(IDXGISwapChain *sc, UINT sync, UINT flags) {
    if (sc == g_flipSc && g_tearing && sync == 0 && !(flags & DXGI_PRESENT_TEST)) {
        BOOL fs = FALSE;
        IDXGISwapChain_GetFullscreenState(sc, &fs, NULL);
        if (!fs) flags |= DXGI_PRESENT_ALLOW_TEARING;   // not allowed in exclusive fullscreen
    }
    return oPresent(sc, sync, flags);
}

static HRESULT STDMETHODCALLTYPE Hk_ResizeBuffers(IDXGISwapChain *sc, UINT count, UINT w, UINT h,
                                                  DXGI_FORMAT fmt, UINT scFlags) {
    if (sc == g_flipSc) {
        if (count == 1) count = 2;
        scFlags &= ~DXGI_SWAP_CHAIN_FLAG_GDI_COMPATIBLE;
        if (g_tearing) scFlags |= DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING;
        if (fmt != DXGI_FORMAT_UNKNOWN) {
            if (StripSrgb(fmt) != fmt) { g_srgb = TRUE; fmt = StripSrgb(fmt); }
            if (!FlipFormatOk(fmt)) fmt = DXGI_FORMAT_UNKNOWN;  // keep current
        }
    }
    HRESULT hr = oResizeBuffers(sc, count, w, h, fmt, scFlags);
    if (sc == g_flipSc && SUCCEEDED(hr)) RefreshBackBuffer(sc);
    if (sc == g_flipSc) Log("ResizeBuffers %ux%u -> 0x%08lx", w, h, hr);
    return hr;
}

static HRESULT STDMETHODCALLTYPE Hk_CreateSwapChain(IDXGIFactory *f, IUnknown *dev,
                                                    DXGI_SWAP_CHAIN_DESC *desc, IDXGISwapChain **out) {
    if (!desc || !out) return oCreateSwapChain(f, dev, desc, out);
    DXGI_SWAP_CHAIN_DESC d = *desc;
    Log("game swap chain: %ux%u fmt=%d buffers=%u windowed=%d effect=%d msaa=%u flags=0x%x",
        d.BufferDesc.Width, d.BufferDesc.Height, d.BufferDesc.Format, d.BufferCount,
        d.Windowed, d.SwapEffect, d.SampleDesc.Count, d.Flags);

    const char *why = NULL;
    if (!cfg.forceFlip) why = "disabled in ini";
    else if (d.SwapEffect >= DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL) why = "already flip model";
    else if (!d.Windowed) why = "exclusive fullscreen (flip breaks alt-tab in this game)";
    else if (d.SampleDesc.Count > 1) why = "MSAA back buffer";
    else if (!FlipFormatOk(StripSrgb(d.BufferDesc.Format))) why = "back-buffer format not flip-compatible";

    if (!why) {
        BOOL tear = cfg.allowTearing && TearingSupported(f);
        BOOL srgb = StripSrgb(d.BufferDesc.Format) != d.BufferDesc.Format;
        d.BufferDesc.Format = StripSrgb(d.BufferDesc.Format);
        d.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
        if (d.BufferCount < 2) d.BufferCount = 2;
        if (d.BufferCount < 3 && cfg.flipBuffers >= 2) d.BufferCount = cfg.flipBuffers;
        d.Flags &= ~DXGI_SWAP_CHAIN_FLAG_GDI_COMPATIBLE;
        if (tear) d.Flags |= DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING;
        HRESULT hr = oCreateSwapChain(f, dev, &d, out);
        if (SUCCEEDED(hr) && *out) {
            void **vt = *(void ***)*out;
            PatchVt(&vt[8], (void *)Hk_Present, (void **)&oPresent);
            PatchVt(&vt[13], (void *)Hk_ResizeBuffers, (void **)&oResizeBuffers);
            g_flipSc = *out; g_tearing = tear; g_srgb = srgb;
            if (srgb) {
                ID3D11Device *d11 = NULL;
                if (SUCCEEDED(IDXGISwapChain_GetDevice(*out, &IID_ID3D11Device, (void **)&d11)) && d11) {
                    void **dvt = *(void ***)d11;
                    PatchVt(&dvt[9], (void *)Hk_CreateRTV, (void **)&oCreateRTV);
                    ID3D11Device_Release(d11);
                }
                RefreshBackBuffer(*out);
                Log("-> sRGB back buffer: created as UNORM, game gets sRGB views");
            }
            Log("-> converted to FLIP_DISCARD, %u buffers, tearing %s", d.BufferCount, tear ? "on" : "off");
            return hr;
        }
        Log("-> flip creation failed 0x%08lx, using original swap chain", hr);
    } else Log("-> left as is (%s)", why);
    HRESULT hr = oCreateSwapChain(f, dev, desc, out);
    // The game re-creates its swap chain on mode changes by copying the desc of
    // the old (already converted) one - adopt it so Present/Resize keep tearing.
    if (SUCCEEDED(hr) && *out && cfg.forceFlip && d.Windowed && d.SwapEffect >= DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL) {
        g_flipSc = *out;
        g_tearing = (d.Flags & DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING) != 0;
        if (g_srgb) RefreshBackBuffer(*out);
        Log("-> adopted as current game swap chain (tearing %s)", g_tearing ? "on" : "off");
    }
    return hr;
}

static void HookFactory(void *obj) {
    if (!obj) return;
    IDXGIFactory *f = NULL;
    if (FAILED(((IUnknown *)obj)->lpVtbl->QueryInterface((IUnknown *)obj, &IID_IDXGIFactory, (void **)&f)) || !f) return;
    void **vt = *(void ***)f;
    if (vt[10] != (void *)Hk_CreateSwapChain) {
        PatchVt(&vt[10], (void *)Hk_CreateSwapChain, (void **)&oCreateSwapChain);
        Log("DXGI factory hooked (vtable %p)", vt);
    }
    IDXGIFactory_Release(f);
}

static HRESULT WINAPI Hk_CreateDXGIFactory(REFIID riid, void **pp) {
    EnterCriticalSection(&g_dxgiCs);
    Unpatch(&hkCF);
    HRESULT hr = ((CreateFactory_t)hkCF.addr)(riid, pp);
    Repatch(&hkCF);
    if (SUCCEEDED(hr) && pp) HookFactory(*pp);
    LeaveCriticalSection(&g_dxgiCs);
    return hr;
}
static HRESULT WINAPI Hk_CreateDXGIFactory1(REFIID riid, void **pp) {
    EnterCriticalSection(&g_dxgiCs);
    Unpatch(&hkCF1);
    HRESULT hr = ((CreateFactory_t)hkCF1.addr)(riid, pp);
    Repatch(&hkCF1);
    if (SUCCEEDED(hr) && pp) HookFactory(*pp);
    LeaveCriticalSection(&g_dxgiCs);
    return hr;
}
static HRESULT WINAPI Hk_CreateDXGIFactory2(UINT fl, REFIID riid, void **pp) {
    EnterCriticalSection(&g_dxgiCs);
    Unpatch(&hkCF2);
    HRESULT hr = ((CreateFactory2_t)hkCF2.addr)(fl, riid, pp);
    Repatch(&hkCF2);
    if (SUCCEEDED(hr) && pp) HookFactory(*pp);
    LeaveCriticalSection(&g_dxgiCs);
    return hr;
}

// D3D11CreateDeviceAndSwapChain = D3D11CreateDevice + IDXGIFactory::CreateSwapChain
static ExportHook hkD3D;
static HRESULT WINAPI Hk_D3D11CreateDeviceAndSwapChain(IDXGIAdapter *ad, D3D_DRIVER_TYPE dt, HMODULE sw, UINT fl,
        const D3D_FEATURE_LEVEL *fls, UINT nfl, UINT sdk, const DXGI_SWAP_CHAIN_DESC *scd,
        IDXGISwapChain **psc, ID3D11Device **pdev, D3D_FEATURE_LEVEL *pfl, ID3D11DeviceContext **pctx) {
    EnterCriticalSection(&g_dxgiCs);
    Unpatch(&hkD3D);
    PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN orig = (PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN)hkD3D.addr;
    HRESULT hr;
    if (!scd || !psc) {
        hr = orig(ad, dt, sw, fl, fls, nfl, sdk, scd, psc, pdev, pfl, pctx);
    } else {
        ID3D11Device *dev = NULL; ID3D11DeviceContext *ctx = NULL;
        hr = orig(ad, dt, sw, fl, fls, nfl, sdk, NULL, NULL, &dev, pfl, &ctx);
        if (SUCCEEDED(hr)) {
            IDXGIDevice *xd = NULL; IDXGIAdapter *xa = NULL; IDXGIFactory *xf = NULL;
            hr = ID3D11Device_QueryInterface(dev, &IID_IDXGIDevice, (void **)&xd);
            if (SUCCEEDED(hr)) hr = IDXGIDevice_GetAdapter(xd, &xa);
            if (SUCCEEDED(hr)) hr = IDXGIAdapter_GetParent(xa, &IID_IDXGIFactory, (void **)&xf);
            if (SUCCEEDED(hr)) {
                HookFactory(xf);
                DXGI_SWAP_CHAIN_DESC d = *scd;
                hr = Hk_CreateSwapChain(xf, (IUnknown *)dev, &d, psc);
            }
            if (xf) IDXGIFactory_Release(xf);
            if (xa) IDXGIAdapter_Release(xa);
            if (xd) IDXGIDevice_Release(xd);
            if (SUCCEEDED(hr)) {
                if (pdev) *pdev = dev; else ID3D11Device_Release(dev);
                if (pctx) *pctx = ctx; else ID3D11DeviceContext_Release(ctx);
            } else {
                ID3D11DeviceContext_Release(ctx); ID3D11Device_Release(dev);
                hr = orig(ad, dt, sw, fl, fls, nfl, sdk, scd, psc, pdev, pfl, pctx);  // plain fallback
            }
        }
    }
    Repatch(&hkD3D);
    LeaveCriticalSection(&g_dxgiCs);
    return hr;
}

static void InstallDxgiHooks(void) {
    InitializeCriticalSection(&g_dxgiCs);
    HMODULE dxgi = GetModuleHandleW(L"dxgi.dll");   // mapped already as an FC64 dependency
    if (!dxgi) { Log("dxgi.dll not mapped yet - presentation fix not installed"); return; }
    int a = PatchExport(&hkCF,  dxgi, "CreateDXGIFactory",  Hk_CreateDXGIFactory);
    int b = PatchExport(&hkCF1, dxgi, "CreateDXGIFactory1", Hk_CreateDXGIFactory1);
    int c = PatchExport(&hkCF2, dxgi, "CreateDXGIFactory2", Hk_CreateDXGIFactory2);
    HMODULE d3d = GetModuleHandleW(L"d3d11.dll");
    int e = d3d ? PatchExport(&hkD3D, d3d, "D3D11CreateDeviceAndSwapChain", Hk_D3D11CreateDeviceAndSwapChain) : 0;
    Log("DXGI hooks: Factory=%d Factory1=%d Factory2=%d D3D11CreateDeviceAndSwapChain=%d", a, b, c, e);
}

// --------------------------------------------- dedicated cores for heavy threads ---
// In CPU-bound scenes (villages) the engine's main thread is the limit while the
// GPU idles. With SMT, Windows often runs a busy job worker on the same physical
// core as the main thread, and both slow down. Every 2 s we find the game's two
// heaviest threads and give them physical cores 1 and 2 exclusively (first logical
// CPU of each); all other game threads are kept off those two cores. Core 0 is
// avoided because it services most interrupts/DPCs.
typedef LONG (NTAPI *NtSIT_t)(HANDLE, ULONG, PVOID, ULONG);

#define MAXT 2048
static struct { DWORD tid; ULONGLONG cpu; BYTE cls; } g_th[MAXT];   // cls: 0 none, 1 heavy, 2 other

static int ThSlot(DWORD tid) {
    for (int i = 0; i < MAXT; i++) if (g_th[i].tid == tid) return i;
    for (int i = 0; i < MAXT; i++) if (!g_th[i].tid) { g_th[i].tid = tid; g_th[i].cpu = 0; g_th[i].cls = 0; return i; }
    return -1;
}

#include "profiler.inc"

static DWORD WINAPI CoreScheduler(LPVOID unused) {
    NtSIT_t ntSet = (NtSIT_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread");
    // physical core masks
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION info[256]; DWORD len = sizeof info;
    if (!ntSet || !GetLogicalProcessorInformation(info, &len)) { Log("cores: topology query failed"); return 0; }
    KAFFINITY core[64]; int nc = 0;
    for (DWORD i = 0; i < len / sizeof info[0] && nc < 64; i++)
        if (info[i].Relationship == RelationProcessorCore) core[nc++] = info[i].ProcessorMask;
    if (nc < 4) { Log("cores: only %d physical cores - dedicated cores disabled", nc); return 0; }
    DWORD_PTR pm = RealProcessMask(GetCurrentProcess()), sm = g_realSysMask;
    KAFFINITY reserved = core[1] | core[2];
    KAFFINITY heavyMask = (core[1] & (~core[1] + 1)) | (core[2] & (~core[2] + 1));  // lowest bit of each
    KAFFINITY otherMask = (KAFFINITY)pm & ~reserved;
    Log("cores: %d physical; heavy threads -> 0x%04llx, others -> 0x%04llx",
        nc, (unsigned long long)heavyMask, (unsigned long long)otherMask);

    DWORD pid = GetCurrentProcessId(), me = GetCurrentThreadId();
    DWORD lastTop[2] = { 0, 0 };
    // Thread load is measured in exact CPU cycles (QueryThreadCycleTime). The
    // tick-based GetThreadTimes badly under-reports bursty threads like a game
    // main thread. Cycle counts are in TSC units, so calibrate the TSC rate.
    LARGE_INTEGER qf, q0; QueryPerformanceFrequency(&qf); QueryPerformanceCounter(&q0);
    ULONGLONG tsc0 = __rdtsc();
    for (;;) {
        Sleep(2000);
        LARGE_INTEGER q1; QueryPerformanceCounter(&q1); ULONGLONG tsc1 = __rdtsc();
        double intervalMs = (q1.QuadPart - q0.QuadPart) * 1000.0 / qf.QuadPart;
        double cyclesPerMs = (tsc1 - tsc0) / intervalMs;
        q0 = q1; tsc0 = tsc1;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;
        THREADENTRY32 te; te.dwSize = sizeof te;
        DWORD top[2] = { 0, 0 }; double topPct[2] = { 0, 0 };
        static DWORD alive[MAXT]; int nAlive = 0;
        for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == me) continue;
            HANDLE h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
            if (!h) continue;
            ULONG64 t;
            if (QueryThreadCycleTime(h, &t)) {
                int s = ThSlot(te.th32ThreadID);
                if (s >= 0) {
                    double pct = g_th[s].cpu ? (t - g_th[s].cpu) * 100.0 / (cyclesPerMs * intervalMs) : 0;  // % of a core
                    g_th[s].cpu = t;
                    if (nAlive < MAXT) alive[nAlive++] = te.th32ThreadID;
                    if (pct > topPct[0]) { top[1] = top[0]; topPct[1] = topPct[0]; top[0] = te.th32ThreadID; topPct[0] = pct; }
                    else if (pct > topPct[1]) { top[1] = te.th32ThreadID; topPct[1] = pct; }
                }
            }
            CloseHandle(h);
        }
        CloseHandle(snap);
        // forget exited threads
        for (int i = 0; i < MAXT; i++) if (g_th[i].tid) {
            int found = 0; for (int j = 0; j < nAlive; j++) if (alive[j] == g_th[i].tid) { found = 1; break; }
            if (!found) g_th[i].tid = 0;
        }
        // only act when something is genuinely heavy (in-game, not menus/loading)
        if (topPct[0] < 35.0) continue;
        if (topPct[1] < 20.0) top[1] = 0;
        g_heavy[0] = top[0]; g_heavy[1] = top[1];

        for (int i = 0; i < MAXT; i++) {
            if (!g_th[i].tid) continue;
            BYTE want = (g_th[i].tid == top[0] || g_th[i].tid == top[1]) ? 1 : 2;
            if (g_th[i].cls == want) continue;
            HANDLE h = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, g_th[i].tid);
            if (!h) continue;
            KAFFINITY m = want == 1 ? heavyMask : otherMask;
            if (ntSet(h, 4 /*ThreadAffinityMask*/, &m, sizeof m) >= 0) g_th[i].cls = want;
            CloseHandle(h);
        }
        if (top[0] != lastTop[0] || top[1] != lastTop[1]) {
            Log("cores: heavy threads %lu (%.0f%%) and %lu (%.0f%%) on dedicated cores",
                top[0], topPct[0], top[1], topPct[1]);
            lastTop[0] = top[0]; lastTop[1] = top[1];
        }
    }
}

// ------------------------------------------------------- process tweaks ---
#ifndef ProcessPowerThrottling
#define ProcessPowerThrottling 4
#endif
typedef struct { ULONG Version, ControlMask, StateMask; } PPTS_;
typedef BOOL (WINAPI *SetProcInfo_t)(HANDLE, int, LPVOID, DWORD);

static DWORD WINAPI DeferredInit(LPVOID unused) {
    HANDLE self = GetCurrentProcess();
    if (cfg.timerResolution)
        Log("timeBeginPeriod(1) = %u", timeBeginPeriod(1));

    if (cfg.noPowerThrottle) {
        SetProcInfo_t spi = (SetProcInfo_t)GetProcAddress(
            GetModuleHandleW(L"kernel32.dll"), "SetProcessInformation");
        // 1 = EXECUTION_SPEED, 4 = IGNORE_TIMER_RESOLUTION; StateMask 0 = never throttle
        PPTS_ s = { 1, 0x1 | 0x4, 0 };
        BOOL ok = spi && spi(self, ProcessPowerThrottling, &s, sizeof s);
        if (!ok) { s.ControlMask = 0x1; ok = spi && spi(self, ProcessPowerThrottling, &s, sizeof s); }
        Log("power throttling opt-out: %s", ok ? "ok" : "failed");
    }

    if (cfg.priorityClass == 1) SetPriorityClass(self, ABOVE_NORMAL_PRIORITY_CLASS);
    if (cfg.priorityClass == 2) SetPriorityClass(self, HIGH_PRIORITY_CLASS);

    DWORD_PTR pm, sm;
    pm = RealProcessMask(self); sm = g_realSysMask ? g_realSysMask : pm;
    if (pm) {
        Log("process affinity 0x%04llx, system 0x%04llx", (unsigned long long)pm, (unsigned long long)sm);
        if (cfg.avoidCpu0 && sm > 0xF) {
            DWORD_PTR m = sm & ~(DWORD_PTR)0x3;   // drop CPU0 and its SMT sibling
            typedef BOOL (WINAPI *SPAM)(HANDLE, DWORD_PTR);
            // our hook blocks SetProcessAffinityMask, so go through NtSetInformationProcess
            typedef LONG (NTAPI *NtSIP_t)(HANDLE, ULONG, PVOID, ULONG);
            NtSIP_t nsip = (NtSIP_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess");
            LONG st = nsip ? nsip(self, 21 /*ProcessAffinityMask*/, &m, sizeof m) : -1;
            Log("AvoidCPU0: process affinity -> 0x%04llx (status 0x%08lx)", (unsigned long long)m, st);
        }
    }
    if (cfg.profiler && cfg.log) { HANDLE t = CreateThread(NULL, 0, Profiler, NULL, 0, NULL); if (t) CloseHandle(t); }
    if (cfg.dedicatedCores) CoreScheduler(NULL);   // runs for the life of the game
    return 0;
}

// ------------------------------------------------------------- skip intros ---
// Far Cry 4 understands "-skipintro" (skips the logo / splash videos). We append
// it to the process command line before the game reads it, so it works however
// the game is started (Steam, Ubisoft Connect relaunch, shortcut).
// kernelbase's GetCommandLineA/W just return a cached global pointer
// (mov rax,[rip+x]; ret), and msvcr100 keeps its own copies in _acmdln/_wcmdln;
// we repoint all of them at our extended strings.
static wchar_t g_cmdW[8192];
static char g_cmdA[8192];

static int RepointCached(const char *fn, void *newPtr) {
    HMODULE kb = GetModuleHandleW(L"kernelbase.dll");
    BYTE *p = kb ? (BYTE *)GetProcAddress(kb, fn) : NULL;
    if (!p) return 0;
    p = FollowJumps(p);
    if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x05) {        // mov rax, [rip+rel32]
        void **slot = (void **)(p + 7 + *(INT32 *)(p + 3));
        DWORD old;
        if (VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &old)) {
            *slot = newPtr;
            VirtualProtect(slot, sizeof(void *), old, &old);
            return 1;
        }
    }
    return 0;
}

static void ApplySkipIntro(void) {
    const wchar_t *w = GetCommandLineW();
    if (wcsstr(w, L"-skipintro")) { Log("skipintro: already on command line"); return; }
    if (wcslen(w) + 16 >= _countof(g_cmdW)) return;
    swprintf(g_cmdW, _countof(g_cmdW), L"%s -skipintro", w);
    WideCharToMultiByte(CP_ACP, 0, g_cmdW, -1, g_cmdA, sizeof g_cmdA, NULL, NULL);
    int a = RepointCached("GetCommandLineW", g_cmdW);
    int b = RepointCached("GetCommandLineA", g_cmdA);
    int c = 0, d = 0;
    HMODULE crt = GetModuleHandleW(L"msvcr100.dll");
    if (crt) {
        char **acmd = (char **)GetProcAddress(crt, "_acmdln");
        wchar_t **wcmd = (wchar_t **)GetProcAddress(crt, "_wcmdln");
        if (acmd) { *acmd = g_cmdA; c = 1; }
        if (wcmd) { *wcmd = g_cmdW; d = 1; }
    }
    Log("skipintro: GetCommandLineW=%d GetCommandLineA=%d crt _acmdln=%d _wcmdln=%d -> %s",
        a, b, c, d, wcsstr(GetCommandLineW(), L"-skipintro") ? "active" : "NOT applied");
}

static void Init(HMODULE self) {
    GetModuleFileNameW(self, g_dir, MAX_PATH);
    wchar_t *s = wcsrchr(g_dir, L'\\'); if (s) s[1] = 0;
    LoadConfig();
    InitializeCriticalSection(&g_logCs);
    if (cfg.log) {
        wchar_t lp[MAX_PATH];
        swprintf(lp, MAX_PATH, L"%sfc4corefix.log", g_dir);
        g_log = CreateFileW(lp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    }
    Log("FC4CoreFix loaded. Unpin=%d BlockProc=%d Timer=%d NoThrottle=%d Prio=%d AvoidCPU0=%d",
        cfg.unpinThreads, cfg.blockProcessMask, cfg.timerResolution, cfg.noPowerThrottle,
        cfg.priorityClass, cfg.avoidCpu0);

    pNtQueryInformationThread = (NtQIT_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                        "NtQueryInformationThread");
    if (cfg.jobCpus > 0)
        InstallJobThreadLimit();
    else {
        pNtQueryInformationProcess = (NtQIP_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
        SYSTEM_INFO si; GetSystemInfo(&si); g_realSysMask = si.dwActiveProcessorMask;
    }
    if (cfg.unpinThreads) {
        Hook("SetThreadAffinityMask", Hk_SetThreadAffinityMask);
        Hook("SetThreadIdealProcessor", Hk_SetThreadIdealProcessor);
        Hook("SetThreadIdealProcessorEx", Hk_SetThreadIdealProcessorEx);
        Hook("SetThreadGroupAffinity", Hk_SetThreadGroupAffinity);
    }
    if (cfg.blockProcessMask)
        Hook("SetProcessAffinityMask", Hk_SetProcessAffinityMask);
    if (cfg.forceFlip)
        InstallDxgiHooks();
    if (cfg.skipIntro)
        ApplySkipIntro();

    HANDLE t = CreateThread(NULL, 0, DeferredInit, NULL, 0, NULL);  // runs after loader lock
    if (t) CloseHandle(t);
}

// ------------------------------------------------------ dinput8 forwarding ---
static HMODULE g_real;
static FARPROC Real(const char *name) {
    if (!g_real) {
        wchar_t p[MAX_PATH];
        GetSystemDirectoryW(p, MAX_PATH);
        wcscat_s(p, MAX_PATH, L"\\dinput8.dll");
        g_real = LoadLibraryW(p);
    }
    return g_real ? GetProcAddress(g_real, name) : NULL;
}

HRESULT WINAPI Proxy_DirectInput8Create(HINSTANCE a, DWORD b, REFIID c, LPVOID *d, IUnknown *e) {
    typedef HRESULT (WINAPI *F)(HINSTANCE, DWORD, REFIID, LPVOID *, IUnknown *);
    F f = (F)Real("DirectInput8Create");
    return f ? f(a, b, c, d, e) : E_FAIL;
}
HRESULT WINAPI Proxy_DllCanUnloadNow(void) {
    typedef HRESULT (WINAPI *F)(void); F f = (F)Real("DllCanUnloadNow");
    return f ? f() : S_FALSE;
}
HRESULT WINAPI Proxy_DllGetClassObject(REFCLSID a, REFIID b, LPVOID *c) {
    typedef HRESULT (WINAPI *F)(REFCLSID, REFIID, LPVOID *); F f = (F)Real("DllGetClassObject");
    return f ? f(a, b, c) : E_FAIL;
}
HRESULT WINAPI Proxy_DllRegisterServer(void) {
    typedef HRESULT (WINAPI *F)(void); F f = (F)Real("DllRegisterServer");
    return f ? f() : E_FAIL;
}
HRESULT WINAPI Proxy_DllUnregisterServer(void) {
    typedef HRESULT (WINAPI *F)(void); F f = (F)Real("DllUnregisterServer");
    return f ? f() : E_FAIL;
}
LPCVOID WINAPI Proxy_GetdfDIJoystick(void) {
    typedef LPCVOID (WINAPI *F)(void); F f = (F)Real("GetdfDIJoystick");
    return f ? f() : NULL;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        Init(h);
    }
    return TRUE;
}
