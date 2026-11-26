using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Keep.App.ViewModels;
using Keep.App.Views;

namespace Keep.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;
    private readonly Dictionary<string, FrameworkElement> _pages = new();
    private readonly DispatcherTimer _timer;
    private DateTime _nextScan = DateTime.UtcNow;
    private bool _exiting;
    private bool _switching;
    private string _currentPage = "overview";

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = viewModel;

        _pages["overview"] = new OverviewPage();
        _pages["rules"] = new RulesPage();
        _pages["history"] = new HistoryPage();
        _pages["settings"] = new SettingsPage();

        foreach (var page in _pages.Values)
        {
            page.DataContext = viewModel;
        }

        ShowPage("overview");
        viewModel.IntervalChanged += (_, _) => ScheduleNext();
        ScheduleNext();
        _viewModel.Countdown = $"00:{Math.Min(59, Math.Max(1, _viewModel.IntervalSeconds)):00}";

        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _timer.Tick += OnTick;
        _timer.Start();
    }

    public void ShowPage(string key)
    {
        if (!_pages.TryGetValue(key, out var page))
        {
            return;
        }

        _currentPage = key;
        PageHost.Content = page;

        _switching = true;
        NavOverview.IsChecked = key == "overview";
        NavRules.IsChecked = key == "rules";
        NavHistory.IsChecked = key == "history";
        NavSettings.IsChecked = key == "settings";
        _switching = false;
    }

    public BitmapSource RenderToBitmap(int width, int height)
    {
        Root.Measure(new Size(width, height));
        Root.Arrange(new Rect(0, 0, width, height));
        Root.UpdateLayout();

        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(Root);
        bitmap.Freeze();
        return bitmap;
    }

    public void CloseForExit()
    {
        _exiting = true;
        _timer.Stop();
        Close();
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (!_exiting)
        {
            e.Cancel = true;
            Hide();
            (Application.Current as App)?.ShowTrayHint();
            return;
        }

        base.OnClosing(e);
    }

    private void OnNavChecked(object sender, RoutedEventArgs e)
    {
        if (_switching || sender is not RadioButton { Tag: string key })
        {
            return;
        }

        ShowPage(key);
    }

    private void ScheduleNext()
    {
        _nextScan = DateTime.UtcNow.AddSeconds(Math.Max(5, _viewModel.IntervalSeconds));
    }

    private async void OnTick(object? sender, EventArgs e)
    {
        var remaining = _nextScan - DateTime.UtcNow;
        if (remaining < TimeSpan.Zero)
        {
            remaining = TimeSpan.Zero;
        }

        _viewModel.Countdown = remaining.TotalSeconds >= 1
            ? $"00:{remaining.Seconds:00}"
            : "即将检测";

        if (remaining > TimeSpan.Zero || _viewModel.Scanning)
        {
            return;
        }

        ScheduleNext();
        try
        {
            await _viewModel.ScanAsync(_viewModel.AutoRepair);
        }
        catch (Exception ex)
        {
            _viewModel.ScanInfo = $"检测失败：{ex.Message}";
        }
        finally
        {
            ScheduleNext();
        }
    }
}
