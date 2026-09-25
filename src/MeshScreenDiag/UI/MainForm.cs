using System.Diagnostics;
using System.Text;
using MeshScreenDiag.Core.Analysis;
using MeshScreenDiag.Core.Models;
using MeshScreenDiag.Core.Reporting;
using MeshScreenDiag.Engine;

namespace MeshScreenDiag.UI;

/// <summary>The diagnostic dashboard.</summary>
internal sealed class MainForm : Form
{
    private static readonly Color CritBack = Color.FromArgb(255, 205, 210);
    private static readonly Color HighBack = Color.FromArgb(255, 224, 178);
    private static readonly Color MedBack = Color.FromArgb(255, 249, 196);
    private static readonly Color LowBack = Color.FromArgb(227, 242, 253);
    private static readonly Color OkBack = Color.FromArgb(200, 230, 201);
    private static readonly Color BadBack = Color.FromArgb(255, 205, 210);
    private static readonly Color NeutralBack = Color.FromArgb(236, 239, 241);
    private static readonly Color MeshBack = Color.FromArgb(225, 239, 254);

    private readonly MonitorEngine _engine;
    private WebDashboard? _web;
    private volatile bool _dirty = true;
    private readonly System.Windows.Forms.Timer _uiTimer = new() { Interval = 1000 };
    private readonly StringBuilder _pendingLog = new();

    // toolbar
    private readonly ToolStripButton _btnStartStop = new() { Text = "■ Stop monitoring", DisplayStyle = ToolStripItemDisplayStyle.Text };
    private readonly ToolStripButton _btnBaseline = new() { Text = "① Take baseline", ToolTipText = "Capture the system state BEFORE the client launches the application" };
    private readonly ToolStripButton _btnBlack = new() { Text = "② SCREEN WENT BLACK NOW", ToolTipText = "Press the moment MeshCentral shows black. Marks the timeline and captures an 'after' snapshot." };
    private readonly ToolStripButton _btnAfter = new() { Text = "③ Take 'after' snapshot" };
    private readonly ToolStripButton _btnReport = new() { Text = "Save report…" };
    private readonly ToolStripButton _btnCopy = new() { Text = "Copy summary" };
    private readonly ToolStripButton _btnFolder = new() { Text = "Open report folder" };
    private readonly ToolStripButton _btnSettings = new() { Text = "Settings" };
    private readonly ToolStripButton _btnElevate = new() { Text = "Restart as administrator" };

    // header
    private readonly Label _verdict = new() { Dock = DockStyle.Fill, Font = new Font("Segoe UI", 11f, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(8, 0, 8, 0), AutoEllipsis = true };
    private readonly Label _connVsCap = new() { Dock = DockStyle.Fill, Font = new Font("Segoe UI", 9f), TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(8, 0, 8, 0), AutoEllipsis = true };
    private readonly Label _tileMesh = Tile();
    private readonly Label _tileCapture = Tile();
    private readonly Label _tileDesktop = Tile();
    private readonly Label _tileProtected = Tile();
    private readonly Label _tileBaseline = Tile();
    private readonly Label _tileMarkers = Tile();

    // tabs
    private readonly TabControl _tabs = new() { Dock = DockStyle.Fill };
    private readonly VirtualList _findings = new(("Severity", 80), ("Cause category", 230), ("Finding", 700));
    private readonly RichTextBox _findingDetail = new() { Dock = DockStyle.Fill, ReadOnly = true, BackColor = SystemColors.Window, Font = new Font("Segoe UI", 9.5f) };
    private readonly Label _scores = new() { Dock = DockStyle.Top, Height = 44, Padding = new Padding(6), AutoEllipsis = true };

    private readonly VirtualList _timeline = new(("Time", 75), ("Severity", 70), ("Category", 100), ("Source", 75), ("Event", 900));
    private readonly ComboBox _timelineLevel = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 170 };
    private readonly TextBox _timelineFilter = new() { Width = 260, PlaceholderText = "Filter text…" };
    private readonly CheckBox _timelineFollow = new() { Text = "Follow newest", Checked = true, AutoSize = true };

    private readonly VirtualList _capture = new(("Region", 260), ("Bounds", 150), ("Result", 330), ("Black px", 80), ("Luminance", 80), ("Colours", 70));
    private readonly TextBox _displayInfo = ReadOnlyBox();
    private readonly VirtualList _windows = new(("Process", 150), ("PID", 60), ("Title", 300), ("Display affinity", 280), ("Screen coverage", 90), ("Monitor", 110), ("Flags", 200), ("Class", 180));

    private readonly TextBox _meshInfo = ReadOnlyBox();
    private readonly VirtualList _meshProcs = new(("Role", 70), ("PID", 60), ("Name", 140), ("Session", 60), ("CPU", 60), ("I/O rate", 90), ("Started", 80), ("Command line", 600));
    private readonly VirtualList _meshConns = new(("Proto", 55), ("Local", 190), ("Remote", 220), ("State", 100), ("PID", 60), ("Purpose", 520));

    private readonly VirtualList _network = new(("Proto", 55), ("Local", 190), ("Remote", 220), ("State", 100), ("PID", 60), ("Process", 150), ("Purpose", 420), ("Executable", 380));
    private readonly CheckBox _netMeshOnly = new() { Text = "MeshCentral only", AutoSize = true };
    private readonly CheckBox _netListenOnly = new() { Text = "Listening ports only", AutoSize = true };
    private readonly CheckBox _netHideLoopback = new() { Text = "Hide loopback", AutoSize = true, Checked = true };
    private readonly TextBox _netFilter = new() { Width = 240, PlaceholderText = "Filter (process, port, IP)…" };

    private readonly VirtualList _processes = new(("PID", 60), ("Name", 180), ("Session", 60), ("Started", 130), ("Company", 190), ("Signer", 190), ("Integrity", 70), ("Rendering / DRM", 170), ("Path", 420));
    private readonly TextBox _procFilter = new() { Width = 240, PlaceholderText = "Filter…" };

    private readonly VirtualList _services = new(("Type", 60), ("Name", 180), ("Display name", 260), ("State", 80), ("Start", 80), ("PID", 60), ("Path", 500));
    private readonly VirtualList _drivers = new(("Loaded kernel module", 220), ("Path", 600));

    private readonly TextBox _securityInfo = ReadOnlyBox();
    private readonly VirtualList _rules = new(("Name", 280), ("Enabled", 60), ("Dir", 40), ("Action", 60), ("Protocol", 60), ("Local ports", 90), ("Remote ports", 90), ("Remote addresses", 150), ("Program / service", 380), ("Profiles", 110));
    private readonly ComboBox _ruleScope = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 280 };

    private readonly VirtualList _events = new(("Time", 130), ("Log", 230), ("Source", 170), ("ID", 50), ("Level", 80), ("Message", 900));
    private readonly VirtualList _diff = new(("Area", 110), ("Change", 70), ("Severity", 70), ("Description", 1000));
    private readonly Label _diffInfo = new() { Dock = DockStyle.Top, Height = 36, Padding = new Padding(6), AutoEllipsis = true };
    private readonly TextBox _log = ReadOnlyBox();

    private readonly ToolStripStatusLabel _statusState = new();
    private readonly ToolStripStatusLabel _statusElevation = new();
    private readonly ToolStripStatusLabel _statusWeb = new();
    private readonly ToolStripStatusLabel _statusFolder = new() { Spring = true, TextAlign = ContentAlignment.MiddleRight };

    public MainForm(MonitorEngine engine)
    {
        _engine = engine;
        Text = $"MeshCentral Screen Diagnostic v{MonitorEngine.Version} — {Environment.MachineName}";
        Icon = SystemIcons.Shield;
        Size = new Size(1400, 900);
        MinimumSize = new Size(900, 600);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9f);

        BuildLayout();
        WireEvents();
        _engine.Updated += () => _dirty = true;
        _engine.Log += line => { lock (_pendingLog) _pendingLog.AppendLine(line); _dirty = true; };
    }

    // ============================================================================ layout
    private static Label Tile() => new()
    {
        Dock = DockStyle.Fill,
        Margin = new Padding(3),
        TextAlign = ContentAlignment.MiddleCenter,
        Font = new Font("Segoe UI", 9f, FontStyle.Bold),
        BackColor = NeutralBack,
        AutoEllipsis = true,
    };

    private static TextBox ReadOnlyBox() => new()
    {
        Multiline = true, ReadOnly = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Both, WordWrap = false,
        Font = new Font("Consolas", 9f), BackColor = SystemColors.Window,
    };

    private void BuildLayout()
    {
        var tool = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, Padding = new Padding(4), ImageScalingSize = new Size(16, 16) };
        _btnBlack.BackColor = Color.FromArgb(198, 40, 40);
        _btnBlack.ForeColor = Color.White;
        _btnBlack.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
        _btnBaseline.Font = _btnAfter.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
        tool.Items.AddRange(new ToolStripItem[]
        {
            _btnStartStop, new ToolStripSeparator(), _btnBaseline, _btnBlack, _btnAfter, new ToolStripSeparator(),
            _btnReport, _btnCopy, _btnFolder, new ToolStripSeparator(), _btnSettings, _btnElevate,
        });
        _btnElevate.Visible = !_engine.IsElevated;

        var tiles = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 6, RowCount = 1 };
        for (var i = 0; i < 6; i++) tiles.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 6));
        tiles.Controls.AddRange(new Control[] { _tileMesh, _tileCapture, _tileDesktop, _tileProtected, _tileBaseline, _tileMarkers });

        var header = new TableLayoutPanel { Dock = DockStyle.Top, Height = 150, ColumnCount = 1, RowCount = 3, Padding = new Padding(4) };
        header.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        header.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
        header.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        header.Controls.Add(_verdict, 0, 0);
        header.Controls.Add(_connVsCap, 0, 1);
        header.Controls.Add(tiles, 0, 2);

        // Diagnosis tab
        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical, SplitterDistance = 700 };
        split.Panel1.Controls.Add(_findings);
        split.Panel2.Controls.Add(_findingDetail);
        var diagPage = Page("Diagnosis", split, _scores);

        // Timeline tab
        _timelineLevel.Items.AddRange(new object[] { "All events", "Low and above", "Medium and above", "High and above" });
        _timelineLevel.SelectedIndex = 1;
        var tlBar = Bar(new Label { Text = "Show:", AutoSize = true, Padding = new Padding(0, 6, 0, 0) }, _timelineLevel, _timelineFilter, _timelineFollow,
            new Label { Text = "Double-click an event for details. Markers (red) show when the screen went black.", AutoSize = true, Padding = new Padding(10, 6, 0, 0), ForeColor = Color.DimGray });
        var tlPage = Page("Timeline", _timeline, tlBar);

        // Screen & windows tab
        var scr = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3, ColumnCount = 1 };
        scr.RowStyles.Add(new RowStyle(SizeType.Percent, 22));
        scr.RowStyles.Add(new RowStyle(SizeType.Percent, 22));
        scr.RowStyles.Add(new RowStyle(SizeType.Percent, 56));
        scr.Controls.Add(Group("Capture test (GDI, like the MeshAgent KVM)", _capture), 0, 0);
        scr.Controls.Add(Group("Desktop, session and display", _displayInfo), 0, 1);
        scr.Controls.Add(Group("Visible windows — highlighted rows block or hide screen capture", _windows), 0, 2);
        var scrPage = Page("Screen & windows", scr);

        // MeshCentral tab
        var mesh = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3, ColumnCount = 1 };
        mesh.RowStyles.Add(new RowStyle(SizeType.Percent, 38));
        mesh.RowStyles.Add(new RowStyle(SizeType.Percent, 27));
        mesh.RowStyles.Add(new RowStyle(SizeType.Percent, 35));
        mesh.Controls.Add(Group("Agent status", _meshInfo), 0, 0);
        mesh.Controls.Add(Group("Agent processes (Service = main agent, KVM = remote-desktop capture process in the user session)", _meshProcs), 0, 1);
        mesh.Controls.Add(Group("Agent network endpoints", _meshConns), 0, 2);
        var meshPage = Page("MeshCentral", mesh);

        // Network tab
        var netBar = Bar(_netMeshOnly, _netListenOnly, _netHideLoopback, _netFilter);
        var netPage = Page("Network & ports", _network, netBar);

        // Processes
        var procPage = Page("Processes", _processes, Bar(_procFilter));

        // Services & drivers
        var svcSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 420 };
        svcSplit.Panel1.Controls.Add(Group("Services and registered drivers", _services));
        svcSplit.Panel2.Controls.Add(Group("Kernel modules loaded right now", _drivers));
        var svcPage = Page("Services & drivers", svcSplit);

        // Security & firewall
        _ruleScope.Items.AddRange(new object[] { "Rules mentioning the MeshCentral agent", "Enabled BLOCK rules", "All rules" });
        _ruleScope.SelectedIndex = 0;
        var secSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 230 };
        secSplit.Panel1.Controls.Add(Group("Security products, Defender and firewall profiles", _securityInfo));
        var rulesPanel = new Panel { Dock = DockStyle.Fill };
        rulesPanel.Controls.Add(_rules);
        rulesPanel.Controls.Add(Bar(new Label { Text = "Firewall rules:", AutoSize = true, Padding = new Padding(0, 6, 0, 0) }, _ruleScope));
        secSplit.Panel2.Controls.Add(rulesPanel);
        var secPage = Page("Security & firewall", secSplit);

        var evPage = Page("Event logs", _events,
            new Label { Text = "Relevant entries from System, Application, Security, Defender, Firewall, Terminal Services, Code Integrity and AppLocker logs. Double-click for the full message.", Dock = DockStyle.Top, Height = 24, Padding = new Padding(6, 4, 0, 0), ForeColor = Color.DimGray });
        var diffPage = Page("Before / after", _diff, _diffInfo);
        var logPage = Page("Log", _log);

        _tabs.TabPages.AddRange(new[] { diagPage, tlPage, scrPage, meshPage, netPage, procPage, svcPage, secPage, evPage, diffPage, logPage });

        var status = new StatusStrip();
        status.Items.AddRange(new ToolStripItem[] { _statusState, _statusElevation, _statusWeb, _statusFolder });

        Controls.Add(_tabs);
        Controls.Add(header);
        Controls.Add(tool);
        Controls.Add(status);
    }

    private static TabPage Page(string title, Control main, Control? top = null)
    {
        var p = new TabPage(title) { Padding = new Padding(3) };
        p.Controls.Add(main);
        if (top != null) p.Controls.Add(top);
        return p;
    }

    private static GroupBox Group(string title, Control inner)
    {
        var g = new GroupBox { Text = title, Dock = DockStyle.Fill, Padding = new Padding(4) };
        g.Controls.Add(inner);
        return g;
    }

    private static FlowLayoutPanel Bar(params Control[] controls)
    {
        var f = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, Padding = new Padding(3), WrapContents = false };
        f.Controls.AddRange(controls);
        return f;
    }

    // ============================================================================ events
    private void WireEvents()
    {
        _uiTimer.Tick += (_, _) => { if (_dirty) RefreshUi(); };
        _tabs.SelectedIndexChanged += (_, _) => RefreshUi();
        _timelineLevel.SelectedIndexChanged += (_, _) => RefreshUi();
        _timelineFilter.TextChanged += (_, _) => RefreshUi();
        _netMeshOnly.CheckedChanged += (_, _) => RefreshUi();
        _netListenOnly.CheckedChanged += (_, _) => RefreshUi();
        _netHideLoopback.CheckedChanged += (_, _) => RefreshUi();
        _netFilter.TextChanged += (_, _) => RefreshUi();
        _procFilter.TextChanged += (_, _) => RefreshUi();
        _ruleScope.SelectedIndexChanged += (_, _) => RefreshUi();

        _findings.SelectedIndexChanged += (_, _) => ShowFindingDetail();
        _timeline.RowActivated += r => { if (r.Tag is TimelineEvent e) Dialogs.ShowText(this, "Timeline event", $"{e.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}  [{e.Severity}] {e.Category} ({e.Source})\r\n\r\n{e.Title}\r\n\r\n{e.Details}"); };
        _events.RowActivated += r => { if (r.Tag is EventLogEntryInfo e) Dialogs.ShowText(this, "Event log entry", $"{e.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}  {e.Channel}\r\n{e.Provider}  Event ID {e.EventId}  {e.Level}\r\n\r\n{e.Message}"); };

        _btnStartStop.Click += (_, _) =>
        {
            if (_engine.IsRunning) _engine.Stop(); else _engine.Start();
            RefreshUi();
        };
        _btnBaseline.Click += async (_, _) => await RunBusy(_btnBaseline, "Taking baseline…", () => _engine.TakeBaselineAsync());
        _btnAfter.Click += async (_, _) => await RunBusy(_btnAfter, "Taking snapshot…", () => _engine.TakeAfterAsync());
        _btnBlack.Click += (_, _) =>
        {
            _engine.AddMarker("", automatic: false);
            _tabs.SelectedIndex = 0;
            RefreshUi();
        };
        _btnReport.Click += (_, _) => SaveReport();
        _btnCopy.Click += (_, _) =>
        {
            Clipboard.SetText(TextSummaryBuilder.Build(_engine.BuildReport()));
            _statusState.Text = "Summary copied to clipboard";
        };
        _btnFolder.Click += (_, _) =>
        {
            Directory.CreateDirectory(_engine.ReportsFolder);
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{_engine.ReportsFolder}\"") { UseShellExecute = true });
        };
        _btnSettings.Click += (_, _) =>
        {
            var oldPort = _engine.Settings.WebPort;
            if (!Dialogs.EditSettings(this, _engine.Settings)) return;
            if (oldPort != _engine.Settings.WebPort) StartWeb();
            RefreshUi();
        };
        _btnElevate.Click += (_, _) => RestartElevated();

        Load += async (_, _) =>
        {
            StartWeb();
            _uiTimer.Start();
            _engine.Start();
            // A baseline at start-up captures the state before the client launches the application.
            await RunBusy(_btnBaseline, "Taking baseline…", () => _engine.TakeBaselineAsync());
        };
        FormClosing += (_, _) =>
        {
            _uiTimer.Stop();
            _web?.Dispose();
            _engine.Dispose();
        };
    }

    private async Task RunBusy(ToolStripButton button, string text, Func<Task> action)
    {
        var old = button.Text;
        button.Enabled = false;
        button.Text = text;
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "MeshScreenDiag", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally
        {
            button.Text = old;
            button.Enabled = true;
            RefreshUi();
        }
    }

    private void StartWeb()
    {
        _web?.Dispose();
        _web = null;
        if (_engine.Settings.WebPort <= 0) return;
        try
        {
            _web = new WebDashboard(_engine, _engine.Settings.WebPort);
            _web.Start();
        }
        catch (Exception ex)
        {
            _web = null;
            AppendLog($"Web dashboard could not start on port {_engine.Settings.WebPort}: {ex.Message}");
        }
    }

    private void SaveReport()
    {
        var notes = Dialogs.Prompt(this, "Save diagnostic report",
            "Optional notes for the report (which application the client launched, what you saw in MeshCentral, …):");
        if (notes == null) return;
        try
        {
            Cursor = Cursors.WaitCursor;
            var paths = _engine.SaveReport(notes);
            Process.Start(new ProcessStartInfo(paths.Html) { UseShellExecute = true });
            _statusState.Text = "Report saved: " + paths.Html;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Could not save the report: " + ex.Message, "MeshScreenDiag", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            Cursor = Cursors.Default;
        }
    }

    private void RestartElevated()
    {
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" });
            Close();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // User cancelled the UAC prompt.
        }
    }

    // ============================================================================ refresh
    private void RefreshUi()
    {
        _dirty = false;
        var live = _engine.Live;
        var verdict = _engine.Verdict;

        _btnStartStop.Text = _engine.IsRunning ? "■ Stop monitoring" : "▶ Start monitoring";
        _statusState.Text = _engine.IsRunning
            ? $"Monitoring — last sample {live?.TimeUtc.ToLocalTime():HH:mm:ss}"
            : "Monitoring stopped";
        _statusElevation.Text = _engine.IsElevated ? "Administrator" : "Standard user (limited data)";
        _statusWeb.Text = _web != null ? "Web view: " + _web.Url : "Web view off";
        _statusFolder.Text = "Reports: " + _engine.ReportsFolder;
        FlushLog();

        if (live == null || verdict == null) return;
        RefreshHeader(live, verdict);

        switch (_tabs.SelectedIndex)
        {
            case 0: RefreshFindings(verdict); break;
            case 1: RefreshTimeline(); break;
            case 2: RefreshScreen(live); break;
            case 3: RefreshMesh(live); break;
            case 4: RefreshNetwork(live); break;
            case 5: RefreshProcesses(live); break;
            case 6: RefreshServices(live); break;
            case 7: RefreshSecurity(live); break;
            case 8: RefreshEvents(); break;
            case 9: RefreshDiff(live); break;
        }
    }

    private void RefreshHeader(SystemSnapshot live, DiagnosticVerdict v)
    {
        _verdict.Text = v.Headline;
        _verdict.BackColor = v.PrimaryCause != null || live.Capture?.AnyBlack == true ? BadBack : OkBack;
        _connVsCap.Text = v.ConnectionVsCapture + " — " + v.ConnectionVsCaptureDetail;

        var m = live.Mesh;
        SetTile(_tileMesh, "MeshCentral agent", m == null ? "?" : $"{m.Health}\n{m.EstablishedCount} conn · KVM {(m.KvmActive ? "running" : "idle")}", m?.Health == "CONNECTED" ? OkBack : BadBack);
        var cap = live.Capture;
        SetTile(_tileCapture, "Screen capture test", cap?.Summary ?? "?", cap == null ? NeutralBack : cap.AnyBlack || cap.AnyFailed ? BadBack : OkBack);
        var d = live.Display;
        SetTile(_tileDesktop, "Input desktop", d == null ? "?" : d.InputDesktopAccessible ? $"{d.InputDesktopName}\n{d.NotificationState}" : $"SECURE DESKTOP\n(error {d.InputDesktopError})", d?.IsOnAlternateDesktop == true ? BadBack : OkBack);
        var prot = live.Windows.Where(w => w.IsCaptureProtected && !w.IsMinimized).ToList();
        SetTile(_tileProtected, "Capture-protected windows", prot.Count == 0 ? "none" : $"{prot.Count}: {string.Join(", ", prot.Select(w => w.ProcessName).Distinct())}", prot.Count > 0 ? BadBack : OkBack);
        SetTile(_tileBaseline, "Baseline / after", $"{(_engine.Baseline != null ? _engine.Baseline.TimeUtc.ToLocalTime().ToString("HH:mm:ss") : "none")} / {(_engine.After != null ? _engine.After.TimeUtc.ToLocalTime().ToString("HH:mm:ss") : "none")}", _engine.Baseline != null ? NeutralBack : MedBack);
        var markers = _engine.GetMarkers();
        SetTile(_tileMarkers, "Black-screen markers", markers.Count == 0 ? "none" : $"{markers.Count} — last {markers[^1].TimeUtc.ToLocalTime():HH:mm:ss}", markers.Count > 0 ? MedBack : NeutralBack);
    }

    private static void SetTile(Label tile, string title, string value, Color back)
    {
        tile.Text = title.ToUpperInvariant() + "\n" + value;
        tile.BackColor = back;
    }

    private void RefreshFindings(DiagnosticVerdict v)
    {
        _scores.Text = "Cause likelihood:  " + string.Join("   ·   ", v.Scores.Where(s => s.Score > 0).Select(s => $"{s.Label}: {s.Score}")) +
                       (v.Scores.All(s => s.Score == 0) ? "no cause indicators yet" : "");
        _findings.SetRows(v.Findings.Select(f => new Row(
            new[] { f.Severity.ToString(), CategoryLabels.Of(f.Category), f.Title }, SeverityColor(f.Severity), f)).ToList());
        if (_findings.SelectedRow == null && _findingDetail.TextLength == 0) ShowSummaryDetail(v);
    }

    private void ShowFindingDetail()
    {
        if (_findings.SelectedRow?.Tag is not Finding f) return;
        _findingDetail.Clear();
        AppendRich(f.Title + "\n", 12f, FontStyle.Bold);
        AppendRich($"{f.Severity} · {CategoryLabels.Of(f.Category)}\n\n", 9f, FontStyle.Italic);
        AppendRich("What this means\n", 10f, FontStyle.Bold);
        AppendRich(f.Explanation + "\n\n", 9.5f, FontStyle.Regular);
        if (f.Evidence.Count > 0)
        {
            AppendRich("Evidence\n", 10f, FontStyle.Bold);
            foreach (var e in f.Evidence) AppendRich("  • " + e + "\n", 9f, FontStyle.Regular);
            AppendRich("\n", 9f, FontStyle.Regular);
        }
        if (!string.IsNullOrEmpty(f.Recommendation))
        {
            AppendRich("Recommendation\n", 10f, FontStyle.Bold);
            AppendRich(f.Recommendation + "\n", 9.5f, FontStyle.Regular);
        }
    }

    private void ShowSummaryDetail(DiagnosticVerdict v)
    {
        _findingDetail.Clear();
        AppendRich("How to use\n", 11f, FontStyle.Bold);
        AppendRich("1. A baseline is taken automatically at start-up (retake it with ① before the client opens the application).\n" +
                   "2. Ask the client to launch the application while you watch MeshCentral.\n" +
                   "3. The moment the remote screen turns black press ② SCREEN WENT BLACK NOW (black captures are also detected automatically).\n" +
                   "4. Read the verdict above and the findings on the left; the Timeline shows exactly what changed at that moment.\n" +
                   "5. Save the report and share it. Reports are also written to the report folder automatically when a black screen is detected.\n\n", 9.5f, FontStyle.Regular);
        AppendRich("Select a finding on the left to see its explanation, evidence and recommendation.\n\n", 9.5f, FontStyle.Italic);
        if (v.SuspectApplications.Count > 0)
        {
            AppendRich("Applications started around the black-screen moment\n", 10f, FontStyle.Bold);
            foreach (var s in v.SuspectApplications) AppendRich("  • " + s + "\n", 9f, FontStyle.Regular);
        }
    }

    private void AppendRich(string text, float size, FontStyle style)
    {
        _findingDetail.SelectionStart = _findingDetail.TextLength;
        _findingDetail.SelectionFont = new Font("Segoe UI", size, style);
        _findingDetail.AppendText(text);
    }

    private void RefreshTimeline()
    {
        var min = (Severity)Math.Max(0, _timelineLevel.SelectedIndex);
        var filter = _timelineFilter.Text.Trim();
        var rows = _engine.GetTimeline()
            .Where(e => e.Severity >= min || e.Category == "Marker")
            .Where(e => filter.Length == 0 || e.Title.Contains(filter, StringComparison.OrdinalIgnoreCase) || e.Category.Contains(filter, StringComparison.OrdinalIgnoreCase))
            .OrderBy(e => e.TimeUtc)
            .Select(e => new Row(
                new[] { e.TimeUtc.ToLocalTime().ToString("HH:mm:ss"), e.Severity.ToString(), e.Category, e.Source, e.Title },
                e.Category == "Marker" ? Color.FromArgb(239, 83, 80) : SeverityColor(e.Severity), e, e.Category == "Marker"))
            .ToList();
        _timeline.SetRows(rows, scrollToEnd: _timelineFollow.Checked);
    }

    private void RefreshScreen(SystemSnapshot live)
    {
        if (live.Capture is { } cap)
        {
            _capture.SetRows(cap.Monitors.Concat(cap.ProtectedWindows).Select(m => new Row(
                new[] { m.Name, m.Bounds.ToString(), m.StatusText, m.Succeeded ? m.BlackRatio.ToString("P1") : "", m.Succeeded ? m.MeanLuminance.ToString("F0") : "", m.Succeeded ? m.DistinctColors.ToString() : "" },
                m.IsBlack || !m.Succeeded ? CritBack : null)).ToList());
        }

        var d = live.Display;
        if (d != null)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Input desktop        : {(d.InputDesktopAccessible ? d.InputDesktopName : $"NOT ACCESSIBLE (Win32 error {d.InputDesktopError}) -> secure desktop / Winlogon / protected desktop")}");
            sb.AppendLine($"This tool's desktop  : {d.OwnDesktopName}");
            sb.AppendLine($"Notification state   : {d.NotificationState}");
            sb.AppendLine($"Session              : this {d.OwnSessionId} ({d.OwnSessionConnectState}), console {d.ActiveConsoleSessionId}, locked {d.SessionLocked?.ToString() ?? "?"}, RDP {d.IsRemoteSession}");
            sb.AppendLine($"Multi-plane overlay  : {(d.MpoDisabled == true ? "disabled (OverlayTestMode=5)" : "enabled (default)")};  HW GPU scheduling: {d.HagsMode switch { 2 => "on", 1 => "off", _ => "?" }}");
            foreach (var m in d.Monitors) sb.AppendLine($"Monitor              : {m} {m.BitsPerPixel}bpp — {m.AdapterName}");
            foreach (var a in d.Adapters) sb.AppendLine($"GPU                  : {a.Name} (driver {a.DriverVersion}, {a.DriverDate}, status {a.Status})");
            SetText(_displayInfo, sb.ToString());
        }

        _windows.SetRows(live.Windows
            .OrderByDescending(w => w.IsCaptureProtected).ThenByDescending(w => w.IsForeground).ThenByDescending(w => w.MaxMonitorCoverage)
            .Select(w => new Row(new[]
            {
                w.ProcessName, w.Pid.ToString(), w.Title, w.AffinityDisplay, w.MaxMonitorCoverage.ToString("P0"), w.MonitorDevice ?? "",
                string.Join(" ", new[] { w.IsForeground ? "FOREGROUND" : null, w.IsTopMost ? "topmost" : null, w.IsLayered ? "layered" : null, w.IsClickThrough ? "click-through" : null, w.IsMinimized ? "minimized" : null, w.IsHung ? "HUNG" : null }.Where(x => x != null)),
                w.ClassName,
            }, w.IsCaptureProtected ? CritBack : w.IsForeground ? LowBack : null, w)).ToList());
    }

    private void RefreshMesh(SystemSnapshot live)
    {
        var m = live.Mesh;
        if (m == null) return;
        var sb = new StringBuilder();
        sb.AppendLine($"Health            : {m.Health}");
        sb.AppendLine($"Service           : {m.ServiceName ?? "(not found)"} — {m.ServiceState} / {m.ServiceStartMode}");
        sb.AppendLine($"Install folder    : {m.InstallPath}");
        sb.AppendLine($"Server (.msh)     : {m.ServerUrl ?? "(unknown)"}  host {m.ServerHost} port {m.ServerPort}");
        sb.AppendLine($"Server addresses  : {string.Join(", ", m.ServerAddresses)}");
        sb.AppendLine($"Device group      : {m.MeshName}");
        sb.AppendLine($"Established conns : {m.EstablishedCount}   Remote desktop (KVM) process: {(m.KvmActive ? "RUNNING" : "not running")}");
        sb.AppendLine();
        sb.AppendLine("How to read this: if the agent is CONNECTED and a KVM process is running (with CPU/I-O activity) while the");
        sb.AppendLine("remote screen is black, the network path is fine and the image is being blocked at capture time.");
        foreach (var n in m.Notes) sb.AppendLine("Note: " + n);
        SetText(_meshInfo, sb.ToString());

        _meshProcs.SetRows(m.Processes.Select(p => new Row(new[]
        {
            p.Role, p.Pid.ToString(), p.Name, p.SessionId.ToString(), p.CpuPercent?.ToString("F1") + "%", p.IoBytesPerSec != null ? AnalysisEngine.FormatRate(p.IoBytesPerSec.Value) : "n/a",
            p.StartTimeUtc?.ToLocalTime().ToString("HH:mm:ss") ?? "", p.CommandLine ?? p.Path ?? "",
        }, p.Role == "KVM" ? LowBack : null)).ToList());
        _meshConns.SetRows(m.Connections.Select(c => new Row(new[]
        {
            c.Protocol + (c.IpVersion == 6 ? "v6" : ""), $"{c.LocalAddress}:{c.LocalPort}", c.Protocol == "UDP" ? "" : $"{c.RemoteAddress}:{c.RemotePort}", c.State, c.Pid.ToString(), c.Purpose,
        }, c.IsEstablished ? OkBack : null)).ToList());
    }

    private void RefreshNetwork(SystemSnapshot live)
    {
        var f = _netFilter.Text.Trim();
        var rows = live.Connections
            .Where(c => !_netMeshOnly.Checked || c.IsMeshAgent)
            .Where(c => !_netListenOnly.Checked || c.IsListening)
            .Where(c => !_netHideLoopback.Checked || !(IsLoopback(c.LocalAddress) && (c.IsListening || IsLoopback(c.RemoteAddress))))
            .Where(c => f.Length == 0 || $"{c.ProcessName} {c.LocalAddress}:{c.LocalPort} {c.RemoteAddress}:{c.RemotePort} {c.Purpose} {c.Pid}".Contains(f, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(c => c.IsMeshAgent).ThenBy(c => c.Protocol).ThenBy(c => c.IsListening).ThenBy(c => c.ProcessName)
            .Select(c => new Row(new[]
            {
                c.Protocol + (c.IpVersion == 6 ? "v6" : ""), $"{c.LocalAddress}:{c.LocalPort}", c.Protocol == "UDP" || c.State == "LISTEN" ? "" : $"{c.RemoteAddress}:{c.RemotePort}",
                c.State, c.Pid.ToString(), c.ProcessName, c.Purpose, c.ProcessPath ?? "",
            }, c.IsMeshAgent ? MeshBack : null)).ToList();
        _network.SetRows(rows);
    }

    private static bool IsLoopback(string a) => a.StartsWith("127.") || a == "::1";

    private void RefreshProcesses(SystemSnapshot live)
    {
        var f = _procFilter.Text.Trim();
        var protectedPids = live.Windows.Where(w => w.IsCaptureProtected).Select(w => w.Pid).ToHashSet();
        _processes.SetRows(live.Processes
            .Where(p => f.Length == 0 || $"{p.Name} {p.Pid} {p.Company} {p.Path}".Contains(f, StringComparison.OrdinalIgnoreCase))
            .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .Select(p => new Row(new[]
            {
                p.Pid.ToString(), p.Name, p.SessionId.ToString(), p.StartTimeUtc?.ToLocalTime().ToString("MM-dd HH:mm:ss") ?? "", p.Company ?? "", p.Signer ?? "",
                p.IntegrityLevel ?? "", string.Join(", ", p.ModuleIndicators), p.Path ?? "",
            }, protectedPids.Contains(p.Pid) ? CritBack : Core.Catalogs.KnownSoftwareCatalog.Match(p.Name) != null ? MedBack : null)).ToList());
    }

    private void RefreshServices(SystemSnapshot live)
    {
        _services.SetRows(live.Services.OrderBy(s => s.Type).ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase).Select(s => new Row(new[]
        {
            s.Type, s.Name, s.DisplayName, s.State, s.StartMode, s.ProcessId == 0 ? "" : s.ProcessId.ToString(), s.PathName ?? "",
        }, SnapshotComparer.IsMeshName(s.Name) || SnapshotComparer.IsMeshName(s.PathName) ? MeshBack : null)).ToList());
        _drivers.SetRows(live.LoadedDrivers.OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase).Select(d => new Row(new[] { d.Name, d.Path ?? "" },
            Core.Catalogs.KnownSoftwareCatalog.Match(d.Name) != null ? MedBack : null)).ToList());
    }

    private void RefreshSecurity(SystemSnapshot live)
    {
        var sb = new StringBuilder();
        if (live.SecurityProducts.Count == 0) sb.AppendLine("Security Center: no products reported (normal on Windows Server)");
        foreach (var p in live.SecurityProducts)
            sb.AppendLine($"{p.Kind,-12}: {p.Name} — {(p.Enabled ? "enabled" : "DISABLED")}, {(p.UpToDate ? "up to date" : "out of date")} (state 0x{p.ProductState:X6})");
        if (live.Defender is { } def)
            sb.AppendLine($"Defender    : AV {def.AntivirusEnabled}, real-time {def.RealTimeProtectionEnabled}, behaviour {def.BehaviorMonitorEnabled}, tamper protection {def.IsTamperProtected}, version {def.ProductVersion} {def.Error}");
        sb.AppendLine();
        if (live.Firewall is { } fw)
        {
            if (fw.Error != null) sb.AppendLine(fw.Error);
            foreach (var p in fw.Profiles)
                sb.AppendLine($"Firewall {p.Name,-8}: {(p.IsActive ? "ACTIVE" : "inactive")}, {(p.Enabled ? "on" : "OFF")}, inbound {p.DefaultInboundAction}, outbound {p.DefaultOutboundAction}{(p.BlockAllInbound ? ", BLOCK ALL INBOUND" : "")}");
            sb.AppendLine($"{fw.Rules.Count} rules, {fw.Rules.Count(r => r.Enabled && r.Action == "Block")} enabled block rules, {fw.Rules.Count(r => SnapshotComparer.IsMeshName(r.Application) || SnapshotComparer.IsMeshName(r.Name))} mention the MeshCentral agent.");

            IEnumerable<FirewallRuleInfo> rules = _ruleScope.SelectedIndex switch
            {
                0 => fw.Rules.Where(r => SnapshotComparer.IsMeshName(r.Application) || SnapshotComparer.IsMeshName(r.Name)),
                1 => fw.Rules.Where(r => r.Enabled && r.Action == "Block"),
                _ => fw.Rules,
            };
            _rules.SetRows(rules.OrderBy(r => r.Name).Select(r => new Row(new[]
            {
                r.Name, r.Enabled ? "yes" : "no", r.Direction, r.Action, r.Protocol, r.LocalPorts ?? "", r.RemotePorts ?? "", r.RemoteAddresses ?? "", r.Application ?? r.Service ?? "", r.Profiles,
            }, r.Enabled && r.Action == "Block" ? HighBack : null)).ToList());
        }
        else sb.AppendLine("Firewall: not collected yet (full snapshot pending)");
        SetText(_securityInfo, sb.ToString());
    }

    private void RefreshEvents()
    {
        _events.SetRows(_engine.GetEvents().OrderByDescending(e => e.TimeUtc).Select(e => new Row(new[]
        {
            e.TimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"), e.Channel, e.Provider, e.EventId.ToString(), e.Level, e.Message.Replace("\r", " ").Replace("\n", " "),
        }, SeverityColor(TimelineBuilder.ClassifyEvent(e)), e)).ToList());
    }

    private void RefreshDiff(SystemSnapshot live)
    {
        var baseline = _engine.Baseline;
        if (baseline == null)
        {
            _diffInfo.Text = "No baseline yet. Press ① Take baseline before the client launches the application.";
            _diff.SetRows(Array.Empty<Row>());
            return;
        }
        var after = _engine.After ?? live;
        var diff = SnapshotComparer.Compare(baseline, after);
        _diffInfo.Text = $"Baseline {baseline.TimeUtc.ToLocalTime():HH:mm:ss}  →  {(_engine.After != null ? after.Label : "live state")} {after.TimeUtc.ToLocalTime():HH:mm:ss}:  {diff.Items.Count} change(s). " +
                         "Sorted by severity; the application that causes the black screen is usually among the High/Critical rows.";
        _diff.SetRows(diff.Items.OrderByDescending(i => i.Severity).ThenBy(i => i.Area).Select(i => new Row(
            new[] { i.Area, i.Change.ToString(), i.Severity.ToString(), i.Description }, SeverityColor(i.Severity), i)).ToList());
    }

    private void FlushLog()
    {
        string text;
        lock (_pendingLog)
        {
            if (_pendingLog.Length == 0) return;
            text = _pendingLog.ToString();
            _pendingLog.Clear();
        }
        AppendLog(text.TrimEnd());
    }

    private void AppendLog(string text)
    {
        if (_log.TextLength > 500_000) _log.Clear();
        _log.AppendText(text.Replace("\n", "\r\n").Replace("\r\r", "\r") + "\r\n");
    }

    private static void SetText(TextBox box, string text)
    {
        text = text.Replace("\r\n", "\n").Replace("\n", "\r\n");
        if (box.Text != text) box.Text = text;
    }

    private static Color? SeverityColor(Severity s) => s switch
    {
        Severity.Critical => CritBack,
        Severity.High => HighBack,
        Severity.Medium => MedBack,
        Severity.Low => null,
        _ => null,
    };
}
