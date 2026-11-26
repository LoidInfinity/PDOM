using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using Keep.Core.Engine;
using Keep.Core.Interop;
using Keep.Core.Storage;

namespace Keep.App.Services;

/// <summary>
/// Enables or disables UCPD, elevating through a second instance of the app
/// (UAC prompt) when needed.
/// </summary>
public static class DeepMode
{
    public static (bool Ok, string Message) Apply(bool enable)
    {
        if (Elevation.IsElevated())
        {
            return UcpdController.SetEnabled(enable);
        }

        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe))
        {
            return (false, "找不到当前程序路径");
        }

        var resultFile = Path.Combine(AppPaths.Root, "ucpd-result.json");
        try
        {
            if (File.Exists(resultFile))
            {
                File.Delete(resultFile);
            }
        }
        catch (IOException)
        {
            // A stale result is handled by the timestamp check below.
        }

        try
        {
            var startInfo = new ProcessStartInfo(exe)
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            startInfo.ArgumentList.Add("--ucpd");
            startInfo.ArgumentList.Add(enable ? "on" : "off");

            using var process = Process.Start(startInfo);
            process?.WaitForExit(30_000);
        }
        catch (Win32Exception)
        {
            return (false, "已取消管理员授权");
        }

        if (!File.Exists(resultFile))
        {
            return (false, "提权进程没有返回结果");
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(resultFile));
            var ok = document.RootElement.TryGetProperty("ok", out var okElement) && okElement.GetBoolean();
            var message = document.RootElement.TryGetProperty("message", out var messageElement)
                ? messageElement.GetString() ?? string.Empty
                : string.Empty;
            return (ok, message);
        }
        catch (JsonException)
        {
            return (false, "无法解析提权结果");
        }
    }
}
