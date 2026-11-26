using System.Windows;
using System.Windows.Controls;
using Keep.App.Services;
using Keep.App.ViewModels;
using Keep.Core.Engine;

namespace Keep.App.Views;

public partial class OverviewPage : UserControl
{
    public OverviewPage()
    {
        InitializeComponent();
    }

    private MainViewModel? ViewModel => DataContext as MainViewModel;

    private async void OnDeepMode(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(
            "深度守护会停止 Windows 的 UCPD 驱动，使 Keep 能够自动还原被篡改的默认浏览器、HTML 与 PDF 关联。\n\n" +
            "代价是：其它程序也可能重新改写这些关联，需要由 Keep 的定时检测来兜底。\n\n" +
            "是否继续？（需要管理员授权，可随时在设置中恢复）",
            "开启深度守护",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.OK)
        {
            return;
        }

        var (ok, message) = DeepMode.Apply(true);
        MessageBox.Show(message, ok ? "深度守护已开启" : "操作失败",
            MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);

        ViewModel?.RefreshUcpdState();
        if (ok && ViewModel is not null)
        {
            await ViewModel.ScanAsync(true);
        }
    }

    private void OnRepairBrowser(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: BrowserRow row } || ViewModel is null)
        {
            return;
        }

        var message = ViewModel.RepairBrowser(row);
        MessageBox.Show(message, "浏览器设置", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void OnShowAllHistory(object sender, RoutedEventArgs e)
    {
        (Window.GetWindow(this) as MainWindow)?.ShowPage("history");
    }
}
