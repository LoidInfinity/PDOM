namespace Keep.Core.Associations;

/// <summary>
/// Detects the Windows "User Choice Protection Driver" (UCPD), which since
/// Windows 11 24H2 denies third-party writes to a handful of UserChoice keys
/// (http, https, .html, .htm, .pdf). Those targets can still be *detected*,
/// but a silent restore needs UCPD stopped.
/// </summary>
public static class UcpdGuard
{
    private static readonly HashSet<string> ProtectedTargets = new(StringComparer.OrdinalIgnoreCase)
    {
        "http", "https", ".html", ".htm", ".pdf",
    };

    public const string ServiceName = "UCPD";
    public const string DriverPath = @"C:\Windows\System32\drivers\UCPD.sys";

    public static bool IsProtectedTarget(string target) => ProtectedTargets.Contains(target);

    public static bool DriverInstalled => File.Exists(DriverPath);

    public static bool ServiceRunning => Interop.ServiceNative.IsServiceRunning(ServiceName);

    /// <summary>Service start type (2/3 = automatic/demand, 4 = disabled), or null if absent.</summary>
    public static int? StartType
    {
        get
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\UCPD");
            return key?.GetValue("Start") as int?;
        }
    }

    /// <summary>True when the driver is installed, enabled and currently filtering writes.</summary>
    public static bool IsProtectionActive => DriverInstalled && ServiceRunning && StartType != 4;

    public static string Describe()
    {
        if (!DriverInstalled)
        {
            return "UCPD driver not present";
        }

        var start = StartType switch
        {
            0 => "boot",
            1 => "system",
            2 => "automatic",
            3 => "manual",
            4 => "disabled",
            _ => "unknown",
        };

        return $"present, start={start}, running={ServiceRunning}";
    }
}
