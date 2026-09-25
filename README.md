# MeshCentral Screen Diagnostic (MeshScreenDiag)

A Windows diagnostic tool that runs **alongside MeshCentral** and works out why the MeshCentral
remote desktop turns **black while mouse control still works** after the client opens a particular
application.

It tells you whether the cause is:

| Cause | How it is detected |
|---|---|
| **The application protects its own window** (`SetWindowDisplayAffinity`: banking, exam, Citrix/Horizon, Teams, Zoom, Signal, password managers…) | Reads `GetWindowDisplayAffinity` for every visible window (`WDA_MONITOR` = captured as black, `WDA_EXCLUDEFROMCAPTURE` = invisible) |
| **Secure / alternate desktop** (UAC prompt, lock screen, Safe Exam Browser, Bitdefender Safepay, KeePass secure desktop) | `OpenInputDesktop` name / access error, `consent.exe`, `LogonUI.exe`, session lock state |
| **DRM / protected video** | `mfpmp.exe` (Protected Media Path), PlayReady / Widevine modules in the foreground process |
| **GPU / display** (exclusive full-screen DirectX, driver resets, resolution/monitor changes, hybrid GPU, DisplayLink / virtual displays) | `SHQueryUserNotificationState`, Display 4101 events, display topology diff, adapter inventory, MPO/HAGS settings |
| **Security software** (AV/EDR/DLP flagging or blocking MeshAgent, protection drivers) | Security Center, Defender status and events, AppLocker / Code Integrity blocks, new kernel drivers |
| **Firewall / network** | Every TCP/UDP endpoint with owning process and purpose, MeshAgent connections to the server from its `.msh`, firewall profiles and rules, rule changes, WFP drop events |
| **MeshCentral agent** | Service state, main agent + per-session KVM (remote desktop) process, CPU and I/O rate, restarts/crashes, connection to the server |
| **Windows session** | RDP session vs console, fast user switching, locked/disconnected session |

and — most importantly — whether it is a **connection problem or a capture/visibility problem**.
The tool itself captures the screen the same way the MeshAgent KVM does (GDI `BitBlt` from the
desktop DC). If *its* capture is black while the agent is connected, the problem is on the capture side;
mouse control keeps working because input is injected with `SendInput`, which does not depend on
screen capture.

## Features

* **Live dashboard** – verdict, "connection vs capture" line, status tiles for MeshCentral, capture test,
  input desktop, protected windows, baseline and markers.
* **Timeline** – every change second by second: processes started/exited, windows gaining capture
  protection, desktop switches, capture turning black, MeshAgent KVM restarts, driver loads, service and
  firewall changes, display changes, session lock/RDP events, and relevant event-log entries.
* **Before / after comparison** – a baseline is taken at start-up; press **Take 'after' snapshot** or
  **SCREEN WENT BLACK NOW** to compare processes, services, drivers, connections, firewall rules,
  security products, display and capture state.
* **Automatic black-screen detection** – when the capture test turns black a marker is placed, an
  "after" snapshot is taken and a report is saved automatically.
* **Network & ports** – all TCP/UDP endpoints (IPv4 + IPv6) with process, executable, state and a
  description of each port's purpose; MeshCentral traffic highlighted.
* **Reports** – self-contained HTML (share with your team or the client), JSON (full data) and a short
  text summary for tickets. Window titles can be redacted.
* **Remote-friendly** – when the remote screen is black you cannot see the tool either, so it also:
  * writes `C:\ProgramData\MeshScreenDiag\status.txt` (live status) and reports under
    `C:\ProgramData\MeshScreenDiag\Reports` — reachable from MeshCentral's **Files** / **Terminal** tabs;
  * accepts markers from the terminal: `MeshScreenDiag.exe --mark "client opened X"`;
  * can serve a read-only live dashboard on `http://127.0.0.1:<port>/` (Settings → web port) that you can
    open through MeshCentral's port mapping / Web-HTTP relay.
* **Non-intrusive** – read-only. No hooks, no injection, no drivers, no setting changes; runs at
  below-normal priority, captures only a down-scaled image in memory for statistics (never saved or sent).

## Quick start

1. Get `MeshScreenDiag.exe` (see *Building*) and copy it to the client PC, e.g. with MeshCentral's Files tab.
2. Start it **in the client's user session** (double-click as the client, or run it from a user-session
   terminal). Accept the UAC prompt via *Restart as administrator* for complete data (Security log,
   SYSTEM process details, loaded drivers).
3. A baseline is taken automatically. Retake it with **① Take baseline** right before the client opens the
   problematic application.
4. Ask the client to open the application while you watch MeshCentral.
5. The moment the remote screen turns black press **② SCREEN WENT BLACK NOW** (or run
   `MeshScreenDiag.exe --mark` from the MeshCentral terminal, or use the web dashboard). Black captures are
   also detected automatically.
6. Read the verdict and findings; the **Timeline** tab shows exactly what happened at that moment.
7. **Save report…** and share the HTML file.

## Command line (headless)

```
MeshScreenDiag.exe --snapshot [--out <folder>]           one full snapshot + report, then exit
MeshScreenDiag.exe --monitor [--duration 600] [--web 8765] baseline now, monitor, report at the end
MeshScreenDiag.exe --mark ["note"]                        place a marker in the running instance
MeshScreenDiag.exe --help
```

From a `cmd` terminal use `start /wait MeshScreenDiag.exe --monitor ...` so the console waits for output.
Stop a headless monitor with Ctrl+C or by creating `C:\ProgramData\MeshScreenDiag\stop.request`.

> **Run it in the user's session, not as SYSTEM in session 0.** MeshCentral's default Terminal runs as
> SYSTEM in session 0, where window, desktop and capture checks cannot see the user's screen (the tool
> warns about this). Use MeshCentral's user-session terminal / "run as user", or let the client start it.

## Building

Requirements: .NET 8 SDK. The app targets Windows 10 / 11 / Server 2016+ (x64, ARM64).

```powershell
.\build.ps1                     # tests + single-file self-contained exe in dist\win-x64
.\build.ps1 -Runtime win-arm64
```

or manually:

```
dotnet test tests/MeshScreenDiag.Core.Tests
dotnet publish src/MeshScreenDiag/MeshScreenDiag.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o dist/win-x64
```

The GitHub Actions workflow (`.github/workflows/build.yml`) builds and uploads the exe as an artifact on
every push. The project also builds on Linux/macOS (`EnableWindowsTargeting`), but only runs on Windows.

## Project layout

```
src/MeshScreenDiag.Core/        platform-neutral: data model, analysis rules, before/after diff,
                                software & port catalogs, HTML/JSON/text reports (unit tested)
src/MeshScreenDiag/             Windows app
  Native/                       Win32 P/Invoke declarations (read-only APIs)
  Collectors/                   processes, windows & display affinity, GDI capture test, desktop/session,
                                network tables, services/drivers, firewall, Security Center, event logs,
                                MeshAgent
  Engine/                       snapshot collector, monitoring loop, web dashboard, command line
  UI/                           WinForms dashboard
tests/MeshScreenDiag.Core.Tests xUnit tests for the analysis, diff, catalogs and reports
docs/TROUBLESHOOTING.md         what each cause means and how to fix it
```

## Limitations

* Capture protection set by an application cannot be bypassed by MeshCentral or by this tool — the fix is
  on the application/policy side (see `docs/TROUBLESHOOTING.md`).
* Processes that start and exit between two samples (default every 2 s) only show up through the Security
  log (event 4688), when process-creation auditing is enabled.
* The "known software" list is a heuristic hint; the verdict relies on live evidence (display affinity,
  desktop, capture test, timing).
* On Windows Server, Security Center (antivirus/firewall product list) is not available.
