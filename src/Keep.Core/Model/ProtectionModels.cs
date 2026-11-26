using Keep.Core.Storage;

namespace Keep.Core.Model;

/// <summary>A default app the guardian promises to keep in place.</summary>
public sealed class ProtectionRule
{
    /// <summary>Association target: ".pdf" for extensions, "http" for protocols.</summary>
    public string Target { get; set; } = string.Empty;

    /// <summary>"ext" or "protocol".</summary>
    public string Kind { get; set; } = "ext";

    public string ProgId { get; set; } = string.Empty;

    public string AppName { get; set; } = string.Empty;

    public string? Executable { get; set; }

    public bool Enabled { get; set; } = true;

    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsBrowserTarget => Target is "http" or "https" or ".html" or ".htm";

    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsProtocol => Kind == "protocol";

    public override string ToString() => $"{Target} -> {ProgId}";
}

public sealed class ProtectionBaseline
{
    public int Version { get; set; } = 1;

    public DateTime CapturedUtc { get; set; }

    public List<ProtectionRule> Rules { get; set; } = new();

    public static ProtectionBaseline? Load() => JsonFile.Read<ProtectionBaseline>(AppPaths.BaselineFile);

    public void Save() => JsonFile.Write(AppPaths.BaselineFile, this);
}

/// <summary>User-tunable behaviour.</summary>
public sealed class KeepSettings
{
    public int ScanIntervalSeconds { get; set; } = 60;

    public bool AutoRepair { get; set; } = true;

    public bool StartWithWindows { get; set; } = true;

    /// <summary>True once the user opted into stopping the UCPD driver.</summary>
    public bool DeepMode { get; set; }

    public bool MonitorBrowserSettings { get; set; } = true;

    public int HistoryLimit { get; set; } = 500;

    public DateTime? LastScanUtc { get; set; }

    public DateTime? BaselineCapturedUtc { get; set; }

    public static KeepSettings Load() =>
        JsonFile.Read<KeepSettings>(AppPaths.SettingsFile) ?? new KeepSettings();

    public void Save() => JsonFile.Write(AppPaths.SettingsFile, this);

    public KeepSettings Clone() => (KeepSettings)MemberwiseClone();
}
