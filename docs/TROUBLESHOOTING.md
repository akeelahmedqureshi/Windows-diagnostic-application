# Black MeshCentral screen, mouse still works — causes and fixes

MeshCentral's remote desktop has two independent paths:

* **Input** – the MeshAgent injects mouse/keyboard events (`SendInput`). This works as long as the agent
  is connected, which is why the client still sees the cursor move.
* **Image** – the MeshAgent KVM process (started in the user's session when you open the Desktop tab)
  captures the screen through GDI, encodes it and sends it to the server.

A black screen with working mouse therefore almost always means the **image path** is blocked, not the
connection. MeshScreenDiag's verdict line says which side it is. Below is what each finding means.

## 1. Application screen-capture protection (most common)

**Finding:** *"X blocks screen capture of its window (WDA_MONITOR)"* or *"… hides its window (WDA_EXCLUDEFROMCAPTURE)"*.

The application called `SetWindowDisplayAffinity`. Windows' compositor (DWM) then replaces the window's
pixels with black (`WDA_MONITOR`) or removes the window (`WDA_EXCLUDEFROMCAPTURE`) in **every** capture API
— GDI, DXGI Desktop Duplication, Windows.Graphics.Capture — while the physical screen shows it normally.
No remote tool can bypass this.

Typical sources: banking / payment apps and secure browsers, exam software (Respondus, Examplify),
Citrix Workspace App Protection, VMware/Omnissa Horizon screen-capture blocking, Microsoft Teams
"prevent screen capture" / watermark meetings, Zoom, Signal "Screen security", password managers,
DLP-protected apps.

**Fix:** turn off the protection in the application or in the policy that enforces it (Citrix App
Protection policy, Horizon `Enable screen-capture blocking`, Teams meeting options, Signal
Settings → Privacy → Screen security…), ask the vendor / client admin for an exception for support
sessions, or support that application by other means.

## 2. Secure or alternate desktop

**Finding:** *"Input switched to the secure (Winlogon) desktop"*, *"A UAC prompt is showing…"*,
*"Input switched to a different desktop ('…')"*.

Windows can have several desktops; only one is shown. UAC prompts, the lock screen and Ctrl+Alt+Del run on
the Winlogon desktop. Some applications create their own desktop (Safe Exam Browser, Bitdefender Safepay,
Avast Bank Mode, KeePass "secure desktop"). A capturer attached to the normal desktop gets black.

**Fix:** answer/close the UAC prompt or unlock; make sure the Mesh Agent runs as a service (LocalSystem) so
its KVM can follow the Winlogon desktop; close the application that created the private desktop or disable
its secure-desktop option.

## 3. DRM / protected video

**Finding:** *"Protected (DRM) media playback is active"*.

Protected video (PlayReady/Widevine hardware DRM, HDCP) is presented through the Protected Media Path and
captured as black. **Fix:** pause the video; in browsers disabling hardware acceleration removes the
protected overlay (if policy allows).

## 4. GPU / display

* *Exclusive full-screen Direct3D* – the app bypasses the compositor; run it windowed / borderless.
* *Driver reset (event 4101) / GPU errors* – update or roll back the GPU driver; reconnect the Desktop tab.
* *Display configuration changed* – the app changed resolution or monitors; reconnect the Desktop tab and
  select the right display in the viewer.
* *Hybrid graphics* – set the app to "Power saving" GPU in Windows Graphics settings as a test.
* *Virtual / DisplayLink / indirect display* – test with the app on a monitor attached to the main GPU;
  remove leftover virtual display drivers of other remote tools.
* *Unexplained black capture* – as tests: disable Multi-Plane Overlay
  (`HKLM\SOFTWARE\Microsoft\Windows\Dwm` `OverlayTestMode`=5, reboot, revert afterwards), disable hardware
  acceleration in the app, update the GPU driver.

## 5. Security software

* *Security software recorded events about the MeshCentral agent* – AV/EDR flagged MeshAgent (often as
  RemoteAccess / HackTool / PUA) and may kill the KVM process. Add an allow rule/exclusion and restore
  from quarantine.
* *Kernel driver(s) loaded around the black-screen moment* – protection products (anti-screenshot,
  anti-cheat, DLP, banking protection) often load a driver when the protected app starts. Look up the
  driver publisher.
* Kaspersky Safe Money, Webroot Identity Shield, Trusteer Rapport and DLP agents can block capture of
  protected applications.

## 6. Firewall / network

Only relevant when the verdict says **CONNECTION problem** (agent disconnected). Check block rules for
MeshAgent, default-block outbound profiles, WFP drop events (5152/5157), proxies, and the server address in
the agent's `.msh` file.

## 7. MeshCentral agent

* *KVM process restarted / exited* – the capture process crashed; check the Application log, update the
  agent, reconnect.
* *Local capture works while MeshCentral shows black* – this tool captured a normal image at the moment
  you marked the black screen: the KVM is capturing another session/desktop, is stalled, or frames are
  lost between agent and viewer. Reconnect, check the session/display selector, update agent and server.

## 8. Windows session

* *User is working in an RDP session* – the console session is locked/black; MeshCentral shows the
  console.
* *Session is locked / not the console session / user "not present"* – unlock, or connect MeshCentral to
  the session the user is actually using.
