using System.Diagnostics;
using MeshScreenDiag.Engine;
using MeshScreenDiag.Native;
using MeshScreenDiag.UI;

namespace MeshScreenDiag;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        // Stay out of the way of the client's applications and of MeshAgent.
        try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal; } catch { /* not critical */ }

        if (CliRunner.IsCliInvocation(args))
        {
            // WinExe has no console of its own: attach to the caller's (cmd / PowerShell / MeshCentral terminal).
            NativeMethods.AttachConsole(-1);
            // Run on an MTA thread-pool thread so Windows session/display notifications get their own message thread.
            return Task.Run(() => CliRunner.Run(args)).GetAwaiter().GetResult();
        }

        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.ThreadException += (_, e) =>
            MessageBox.Show(e.Exception.ToString(), "MeshScreenDiag — unexpected error", MessageBoxButtons.OK, MessageBoxIcon.Error);

        var settings = AppSettings.Load();
        using var engine = new MonitorEngine(settings);
        Application.Run(new MainForm(engine));
        return 0;
    }
}
