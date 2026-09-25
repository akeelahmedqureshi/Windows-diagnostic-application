namespace MeshScreenDiag.UI;

internal sealed record Row(string[] Cells, Color? Back = null, object? Tag = null, bool Bold = false);

/// <summary>
/// A ListView in virtual mode: rows are supplied as a list and only the visible items are materialised,
/// so tables with thousands of rows can be refreshed every second without flicker. Click a column to sort.
/// </summary>
internal sealed class VirtualList : ListView
{
    private IReadOnlyList<Row> _source = Array.Empty<Row>();
    private List<Row> _view = new();
    private int _sortColumn = -1;
    private bool _sortDesc;
    private string _signature = "";
    private Font? _boldFont;

    public VirtualList(params (string name, int width)[] columns)
    {
        View = View.Details;
        FullRowSelect = true;
        GridLines = true;
        VirtualMode = true;
        HideSelection = false;
        MultiSelect = true;
        Dock = DockStyle.Fill;
        DoubleBuffered = true;
        foreach (var (name, width) in columns) Columns.Add(name, width);
        RetrieveVirtualItem += OnRetrieve;
        ColumnClick += OnColumnClick;
        KeyDown += OnKeyDown;
    }

    /// <summary>Invoked on double-click with the row's Tag.</summary>
    public event Action<Row>? RowActivated;

    public Row? SelectedRow => SelectedIndices.Count > 0 && SelectedIndices[0] < _view.Count ? _view[SelectedIndices[0]] : null;

    public int RowCount => _view.Count;

    public void SetRows(IReadOnlyList<Row> rows, bool scrollToEnd = false)
    {
        // Skip the refresh entirely when nothing changed (keeps selection and scroll position stable).
        var sig = rows.Count + "|" + (rows.Count > 0 ? string.Join("\u0001", rows[0].Cells) + string.Join("\u0001", rows[^1].Cells) : "") +
                  "|" + rows.Sum(r => (long)r.Cells.Sum(c => c?.Length ?? 0));
        if (sig == _signature) return;
        _signature = sig;
        _source = rows;
        ApplySort();
        var top = VirtualListSize > 0 && TopItem != null ? TopItem.Index : 0;
        VirtualListSize = _view.Count;
        Invalidate();
        if (_view.Count == 0) return;
        try
        {
            if (scrollToEnd) EnsureVisible(_view.Count - 1);
            else if (top > 0 && top < _view.Count) TopItem = Items[top];
        }
        catch
        {
            // TopItem can throw while the control is not yet visible.
        }
    }

    private void ApplySort()
    {
        _view = _source.ToList();
        if (_sortColumn < 0) return;
        var col = _sortColumn;
        int Cmp(Row a, Row b)
        {
            var x = col < a.Cells.Length ? a.Cells[col] ?? "" : "";
            var y = col < b.Cells.Length ? b.Cells[col] ?? "" : "";
            var c = double.TryParse(x.TrimEnd('%'), out var dx) && double.TryParse(y.TrimEnd('%'), out var dy)
                ? dx.CompareTo(dy)
                : string.Compare(x, y, StringComparison.OrdinalIgnoreCase);
            return _sortDesc ? -c : c;
        }
        _view.Sort(Cmp);
    }

    private void OnColumnClick(object? sender, ColumnClickEventArgs e)
    {
        _sortDesc = _sortColumn == e.Column && !_sortDesc;
        _sortColumn = e.Column;
        ApplySort();
        Invalidate();
    }

    private void OnRetrieve(object? sender, RetrieveVirtualItemEventArgs e)
    {
        if (e.ItemIndex >= _view.Count)
        {
            e.Item = new ListViewItem(new string[Columns.Count]);
            return;
        }
        var row = _view[e.ItemIndex];
        var cells = new string[Math.Max(Columns.Count, 1)];
        for (var i = 0; i < cells.Length; i++) cells[i] = i < row.Cells.Length ? row.Cells[i] ?? "" : "";
        var item = new ListViewItem(cells) { Tag = row };
        if (row.Back is { } back) item.BackColor = back;
        if (row.Bold) item.Font = _boldFont ??= new Font(Font, FontStyle.Bold);
        e.Item = item;
    }

    protected override void OnDoubleClick(EventArgs e)
    {
        base.OnDoubleClick(e);
        if (SelectedRow is { } r) RowActivated?.Invoke(r);
    }

    private void OnKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Control && e.KeyCode == Keys.C) CopySelection();
        if (e.Control && e.KeyCode == Keys.A)
        {
            for (var i = 0; i < _view.Count; i++) SelectedIndices.Add(i);
        }
    }

    public void CopySelection()
    {
        var lines = SelectedIndices.Cast<int>().Where(i => i < _view.Count).Select(i => string.Join("\t", _view[i].Cells)).ToList();
        if (lines.Count > 0) Clipboard.SetText(string.Join(Environment.NewLine, lines));
    }
}
