using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using Keep.App.ViewModels;
using Keep.Core.Model;

namespace Keep.App.Services;

/// <summary>Tray icon: keeps the guardian reachable while the window is hidden.</summary>
public sealed class TrayService : IDisposable
{
    private readonly App _app;
    private NotifyIcon? _icon;
    private ToolStripMenuItem? _autoRepairItem;
    private DateTime _lastBalloon = DateTime.MinValue;

    public TrayService(App app)
    {
        _app = app;
    }

    public void Attach()
    {
        var menu = new ContextMenuStrip
        {
            ShowImageMargin = false,
            Renderer = new ToolStripProfessionalRenderer(new DarkColorTable()),
            BackColor = Color.FromArgb(20, 26, 35),
            ForeColor = Color.FromArgb(233, 239, 247),
        };

        menu.Items.Add(Item("打开工作台", (_, _) => _app.ShowShell()));
        menu.Items.Add(Item("立即检测", (_, _) => _ = _app.ViewModel.ScanAsync(_app.ViewModel.AutoRepair)));
        menu.Items.Add(new ToolStripSeparator());
        _autoRepairItem = new ToolStripMenuItem("自动还原") { Checked = _app.ViewModel.AutoRepair, CheckOnClick = true };
        _autoRepairItem.Click += (_, _) => _app.ViewModel.AutoRepair = _autoRepairItem.Checked;
        menu.Items.Add(_autoRepairItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(Item("退出", (_, _) => _app.ExitApplication()));

        _icon = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Text = "Keep · 设置守护台",
            Visible = true,
            ContextMenuStrip = menu,
        };
        _icon.DoubleClick += (_, _) => _app.ShowShell();

        _app.ViewModel.Raised += OnRaised;
    }

    public void Notify(string title, string message)
    {
        if (_icon is null || DateTime.UtcNow - _lastBalloon < TimeSpan.FromSeconds(20))
        {
            return;
        }

        _lastBalloon = DateTime.UtcNow;
        _icon.BalloonTipTitle = title;
        _icon.BalloonTipText = message;
        _icon.BalloonTipIcon = ToolTipIcon.Info;
        _icon.ShowBalloonTip(4000);
    }

    private void OnRaised(object? sender, GuardianEvent e)
    {
        switch (e.Action)
        {
            case GuardianAction.Restored:
                Notify("已拦截一次篡改", $"{e.AppName} 想接管 {e.Target}，已还原为你的设置。");
                break;
            case GuardianAction.Blocked:
                Notify("发现篡改但被系统阻止修复", $"{e.Target} 已被改为 {e.From}，开启深度守护后才能还原。");
                break;
        }
    }

    private static ToolStripMenuItem Item(string text, EventHandler onClick)
    {
        var item = new ToolStripMenuItem(text);
        item.Click += onClick;
        return item;
    }

    public void Dispose()
    {
        if (_icon is not null)
        {
            _icon.Visible = false;
            _icon.Dispose();
            _icon = null;
        }
    }

    private sealed class DarkColorTable : ProfessionalColorTable
    {
        public override Color ToolStripDropDownBackground => Color.FromArgb(20, 26, 35);
        public override Color ImageMarginGradientBegin => Color.FromArgb(20, 26, 35);
        public override Color ImageMarginGradientMiddle => Color.FromArgb(20, 26, 35);
        public override Color ImageMarginGradientEnd => Color.FromArgb(20, 26, 35);
        public override Color MenuBorder => Color.FromArgb(35, 45, 59);
        public override Color MenuItemBorder => Color.FromArgb(61, 220, 151);
        public override Color MenuItemSelected => Color.FromArgb(25, 33, 44);
        public override Color SeparatorDark => Color.FromArgb(35, 45, 59);
        public override Color SeparatorLight => Color.FromArgb(35, 45, 59);
    }
}
