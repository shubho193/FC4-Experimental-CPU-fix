# FC4 Experimental CPU Fix

An experimental `dinput8.dll` proxy mod for **Far Cry 4 (PC, x64)** that targets CPU-bound
frame drops (e.g. FPS dipping into the 40s in crowded areas while the GPU is underused).

> ⚠️ Experimental. Tested on one PC and one copy of the game. Back up your `bin` folder first.

## What it does
- **Unpins job threads** – the engine hard-pins its job workers to fixed CPUs; this lets Windows schedule them freely.
- **Caps the job-worker pool** (`JobThreadCPUs`) – fewer workers means less time the main thread spends waking them each job batch.
- **Dedicated cores** – gives the main and render threads physical cores of their own (CPU topology is detected at runtime).
- **Blocks self-affinity restriction** – ignores the game's attempts to limit its own process affinity.
- **1 ms timer resolution** and **opt-out of Windows power throttling (EcoQoS)**.
- **Skip intro videos** (optional).
- Optional flip-model swap chain conversion (**off by default** – crashes in borderless mode).
- Optional built-in profiler that logs where the main/render threads wait (`Profiler=1`).
- Optional hotspot capture (`Profiler=2`): press **F10** in game to sample which engine code the main and
  render threads run for 20 s. Results go to `fc4corefix-hot.log`, plus full call chains in
  `fc4corefix-stacks-N.bin`. The first capture also saves the unpacked engine image (`fc64_dump.bin`,
  ~110 MB) for offline disassembly. This is for personal analysis only; don't redistribute it.

## Install
1. Download the zip from [Releases](../../releases).
2. Copy `dinput8.dll` and `fc4corefix.ini` into `Far Cry 4\bin\` (next to `FarCry4.exe`).
3. Launch the game. A `fc4corefix.log` is written to the same folder.

**Uninstall:** delete `dinput8.dll` (and `fc4corefix.ini`) from `bin`.

## Configuration
All options are documented in `fc4corefix.ini`. The most useful one to tune:

| Setting | Notes |
|---|---|
| `JobThreadCPUs=6` | Number of CPUs the engine sizes its worker pool for. Try `4`, `6`, or your physical core count. `0` = off (game default). Compare in the same crowded spot. |
| `DedicatedCores=1` | Reserve physical cores for the main/render threads. Set `0` if you see stutter on low-core CPUs. |
| `ForceFlipModel=0` | Keep off – crashes in borderless mode. |

## Tips
- Disable the Steam overlay for Far Cry 4 (Properties → General) – it costs main-thread time.
- RivaTuner / Afterburner overlays also hook the game; close them if you don't need them.
- If the GPU still has headroom in crowds, raise GPU-heavy settings (AA, HBAO+) and lower CPU-heavy ones (Vegetation, Geometry).

## Compatibility
- Cannot be combined with other mods that also use `dinput8.dll` (e.g. some ASI loaders).
- Single-player game; no anti-cheat involved, but use at your own risk.

## Building from source
Requires Visual Studio with the C++ (x64) toolset. Edit the `vcvars64.bat` path in `build.bat` if your VS version differs, then run:
```
build.bat
```
Output: `dinput8.dll`.

| File | Purpose |
|---|---|
| `fc4corefix.c` | Main source (proxy exports, config, hooks) |
| `jobthreads.inc` | Job-worker cap |
| `profiler.inc` | Optional wait profiler and F10 hotspot capture |
| `dinput8.def` | Export definitions |
| `build.bat` | MSVC build script |
| `fc4corefix.ini` | Default configuration |
