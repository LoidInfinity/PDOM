using System.IO;
using System.Windows;
using System.Windows.Threading;
using Keep.App.Services;
using Keep.App.ViewModels;
using Keep.Core.Engine;
using Keep.Core.Storage;

namespace Keep.App;

public partial class App : Application
{
    private Mutex? _instanceMutex;
    private TrayService? _tray;

    public MainViewModel ViewModel { get; private set; } = null!;

    public MainWindow? Shell { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandledException;

        if (e.Args.Length >= 2 && e.Args[0] == "--ucpd")
        {
            RunUcpdHelper(string.Equals(e.Args[1], "on", StringComparison.OrdinalIgnoreCase));
            Shutdown();
            return;
        }

        if (e.Args.Length >= 2 && e.Args[0] == "--render")
        {
            RenderPages(e.Args[1]);
            Shutdown();
            return;
        }

        _instanceMutex = new Mutex(true, "Keep.Guardian.SingleInstance", out var created);
        if (!created)
        {
            Shutdown();
            return;
        }

        AppPaths.EnsureCreated();
        ViewModel = new MainViewModel();
        ViewModel.Initialize();

        Shell = new MainWindow(ViewModel);
        Shell.Show();
        Shell.Activate();

        _tray = new TrayService(this);
        _tray.Attach();

        if (ViewModel.Settings.StartWithWindows)
        {
            AutostartService.SetEnabled(true);
        }

        _ = ViewModel.ScanAsync(ViewModel.Settings.AutoRepair);
    }

    public void ExitApplication()
    {
        _tray?.Dispose();
        Shell?.CloseForExit();
        Shutdown();
    }

    public void ShowTrayHint()
    {
        _tray?.Notify("Keep 仍在后台守护", "窗口已最小化到托盘，检测与还原不会停止。");
    }

    public void ShowShell()
    {
        if (Shell is null)
        {
            return;
        }

        Shell.Show();
        Shell.WindowState = WindowState.Normal;
        Shell.Activate();
        Shell.Topmost = true;
        Shell.Topmost = false;
    }

    private void RenderPages(string directory)
    {
        try
        {
            Directory.CreateDirectory(directory);
            AppPaths.EnsureCreated();
            ViewModel = new MainViewModel();
            ViewModel.Initialize();
            ViewModel.RefreshRules();

            Shell = new MainWindow(ViewModel);
            foreach (var page in new[] { "overview", "rules", "history", "settings" })
            {
                Shell.ShowPage(page);
                var bitmap = Shell.RenderToBitmap(1220, 820);
                var path = Path.Combine(directory, $"keep-{page}.png");
                using var stream = File.Create(path);
                var encoder = new System.Windows.Media.Imaging.PngBitmapEncoder();
                encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));
                encoder.Save(stream);
                Console.WriteLine($"rendered {path}");
            }
        }
        catch (Exception ex)
        {
            File.WriteAllText(Path.Combine(directory, "render-error.txt"), ex.ToString());
        }
    }

    private void RunUcpdHelper(bool enable)
    {
        var (ok, message) = UcpdController.SetEnabled(enable);
        AppPaths.EnsureCreated();
        File.WriteAllText(Path.Combine(AppPaths.Root, "ucpd-result.json"),
            System.Text.Json.JsonSerializer.Serialize(new { ok, message, at = DateTime.UtcNow }));
        Shutdown(ok ? 0 : 1);
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            AppPaths.EnsureCreated();
            File.AppendAllText(Path.Combine(AppPaths.Root, "app-error.log"),
                $"[{DateTime.Now:O}] {e.Exception}\n\n");
        }
        catch (IOException)
        {
            // Nothing useful left to do.
        }

        MessageBox.Show($"Keep 遇到错误：{e.Exception.Message}\n\n详细日志已写入 {AppPaths.Root}",
            "Keep", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }
}
