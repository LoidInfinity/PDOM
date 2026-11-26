using System.Diagnostics;
using Keep.Core.Associations;
using Keep.Core.Interop;

namespace Keep.Core.Engine;

/// <summary>
/// Turns the Windows User Choice Protection Driver on or off. UCPD is what
/// stops third-party tools from writing http/https/.html/.pdf associations, so
/// the guardian can only auto-repair those while the driver is stopped. The
/// change is a normal, reversible service configuration and requires
/// administrator rights.
/// </summary>
public static class UcpdController
{
    public static (bool Ok, string Message) SetEnabled(bool enabled)
    {
        if (!Elevation.IsElevated())
        {
            return (false, "需要管理员权限");
        }

        if (!UcpdGuard.DriverInstalled)
        {
            return (false, "此系统没有 UCPD 驱动");
        }

        var config = Run("config", "UCPD", "start=", enabled ? "system" : "disabled");
        if (config.ExitCode != 0)
        {
            return (false, $"配置服务失败：{FirstLine(config.Error) ?? FirstLine(config.Output) ?? $"exit {config.ExitCode}"}");
        }

        var control = Run(enabled ? "start" : "stop", "UCPD");
        if (control.ExitCode != 0)
        {
            var message = FirstLine(control.Error) ?? FirstLine(control.Output) ?? string.Empty;
            // Starting an already-running driver is not an error for us.
            if (!message.Contains("已经运行", StringComparison.OrdinalIgnoreCase)
                && !message.Contains("already been started", StringComparison.OrdinalIgnoreCase))
            {
                return (false, $"{(enabled ? "启动" : "停止")} UCPD 失败：{message}");
            }
        }

        var active = UcpdGuard.IsProtectionActive;
        return enabled == active
            ? (true, enabled ? "UCPD 已恢复运行" : "UCPD 已停止，深度守护生效")
            : (false, "服务状态未按预期变化，请重启后再试");
    }

    private static (int ExitCode, string Output, string Error) Run(params string[] arguments)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "sc.exe"),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (var argument in arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }

            using var process = Process.Start(startInfo)!;
            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit(15_000);
            return (process.HasExited ? process.ExitCode : -1, output, error);
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, ex.Message);
        }
    }

    private static string? FirstLine(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
}
