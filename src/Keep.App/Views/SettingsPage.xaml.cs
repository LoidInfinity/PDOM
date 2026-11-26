using System.Windows;
using System.Windows.Controls;
using Keep.App.Services;
using Keep.App.ViewModels;

namespace Keep.App.Views;

public partial class SettingsPage : UserControl
{
    public SettingsPage()
    {
        InitializeComponent();
        Loaded += (_, _) => Sync();
        DataContextChanged += (_, _) => Sync();
    }

    private MainViewModel? ViewModel => DataContext as MainViewModel;

    private void Sync()
    {
        if (ViewModel is null)
        {
            return;
        }

        CheckInterval(ViewModel.IntervalSeconds);
        CheckLimit(ViewModel.HistoryLimit);
        DeepModeSwitch.IsChecked = ViewModel.DeepMode;
    }

    private void CheckInterval(int seconds)
    {
        Interval15.IsChecked = seconds == 15;
        Interval30.IsChecked = seconds == 30;
        Interval60.IsChecked = seconds == 60;
        Interval120.IsChecked = seconds == 120;
        Interval300.IsChecked = seconds == 300;
        Interval600.IsChecked = seconds == 600;
    }

    private void CheckLimit(int limit)
    {
        Limit100.IsChecked = limit == 100;
        Limit500.IsChecked = limit == 500;
        Limit1000.IsChecked = limit == 1000;
    }

    private void OnIntervalChecked(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not null && sender is RadioButton { Tag: string tag } && int.TryParse(tag, out var seconds))
        {
            ViewModel.IntervalSeconds = seconds;
        }
    }

    private void OnLimitChecked(object sender, RoutedEventArgs e)
    {
        if (ViewModel is not null && sender is RadioButton { Tag: string tag } && int.TryParse(tag, out var limit))
        {
            ViewModel.HistoryLimit = limit;
        }
    }

    private void OnCaptureBrowsers(object sender, RoutedEventArgs e)
    {
        ViewModel?.CaptureBrowsers();
        MessageBox.Show("已把当前浏览器主页、启动页与搜索引擎记录为基准。", "Keep",
            MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void OnDeepModeClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null)
        {
            return;
        }

        var enable = DeepModeSwitch.IsChecked == true;
        if (enable == ViewModel.DeepMode)
        {
            return;
        }

        if (enable)
        {
            var confirm = MessageBox.Show(
                "停止 UCPD 后，Keep 才能自动还原默认浏览器 / HTML / PDF 关联。\n\n是否继续？（需要管理员授权）",
                "开启深度守护", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.OK)
            {
                DeepModeSwitch.IsChecked = ViewModel.DeepMode;
                return;
            }
        }

        var (ok, message) = DeepMode.Apply(enable);
        ViewModel.RefreshUcpdState();
        DeepModeSwitch.IsChecked = ViewModel.DeepMode;

        MessageBox.Show(message, ok ? "已更新" : "未完成", MessageBoxButton.OK,
            ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }
}
