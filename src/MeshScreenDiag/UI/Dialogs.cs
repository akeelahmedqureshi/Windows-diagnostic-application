using MeshScreenDiag.Engine;

namespace MeshScreenDiag.UI;

internal static class Dialogs
{
    /// <summary>Simple multi-line text prompt. Returns null when cancelled.</summary>
    public static string? Prompt(IWin32Window owner, string title, string label, string initial = "")
    {
        using var f = new Form
        {
            Text = title,
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(560, 300),
            MinimizeBox = false,
            MaximizeBox = false,
            FormBorderStyle = FormBorderStyle.SizableToolWindow,
        };
        var lbl = new Label { Text = label, Dock = DockStyle.Top, Height = 40, Padding = new Padding(6) };
        var box = new TextBox { Multiline = true, Dock = DockStyle.Fill, Text = initial, ScrollBars = ScrollBars.Vertical };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 40, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(4) };
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Width = 90 };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = 90 };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        f.Controls.Add(box);
        f.Controls.Add(lbl);
        f.Controls.Add(buttons);
        f.AcceptButton = null; // Enter inserts new lines in the text box
        f.CancelButton = cancel;
        return f.ShowDialog(owner) == DialogResult.OK ? box.Text : null;
    }

    /// <summary>Edits a copy of the settings in a PropertyGrid. Returns true when the user pressed OK.</summary>
    public static bool EditSettings(IWin32Window owner, AppSettings settings)
    {
        var copy = System.Text.Json.JsonSerializer.Deserialize<AppSettings>(System.Text.Json.JsonSerializer.Serialize(settings))!;
        using var f = new Form
        {
            Text = "Settings",
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(640, 560),
            MinimizeBox = false,
            MaximizeBox = false,
        };
        var grid = new PropertyGrid { Dock = DockStyle.Fill, SelectedObject = copy, ToolbarVisible = false, PropertySort = PropertySort.Categorized };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 40, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(4) };
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Width = 90 };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = 90 };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        f.Controls.Add(grid);
        f.Controls.Add(buttons);
        f.AcceptButton = ok;
        f.CancelButton = cancel;
        if (f.ShowDialog(owner) != DialogResult.OK) return false;

        copy.Normalize();
        foreach (var p in typeof(AppSettings).GetProperties().Where(p => p.CanWrite))
            p.SetValue(settings, p.GetValue(copy));
        settings.Save();
        return true;
    }

    public static void ShowText(IWin32Window owner, string title, string text)
    {
        using var f = new Form { Text = title, StartPosition = FormStartPosition.CenterParent, Size = new Size(820, 520) };
        var box = new TextBox
        {
            Multiline = true, ReadOnly = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Both, WordWrap = true,
            Font = new Font(FontFamily.GenericMonospace, 9f), Text = text.Replace("\r\n", "\n").Replace("\n", "\r\n"),
        };
        f.Controls.Add(box);
        f.ShowDialog(owner);
    }
}
