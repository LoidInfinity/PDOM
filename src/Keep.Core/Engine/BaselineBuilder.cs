using Keep.Core.Associations;
using Keep.Core.Model;

namespace Keep.Core.Engine;

/// <summary>Builds the "this is how it should be" snapshot from the live system.</summary>
public static class BaselineBuilder
{
    private const string FileExtsRoot = @"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts";
    private const string UrlAssocRoot = @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations";

    public static ProtectionBaseline Capture()
    {
        var legacy = new UserChoiceStore();
        var latest = new UserChoiceLatestStore();
        var rules = new List<ProtectionRule>();

        foreach (var target in EnumerateTargets())
        {
            var kind = target.StartsWith('.') ? "ext" : "protocol";
            var effective = DefaultAssociationQuery.GetDefaultProgId(target);
            var legacyProgId = legacy.Read(target).ProgId;
            var latestProgId = latest.Read(target).ProgId;

            // A known hijack pattern writes only UserChoiceLatest: the legacy
            // UserChoice still reflects what the user picked in Windows
            // Settings. For web targets prefer that legacy value, otherwise we
            // would enshrine the hijack as the desired state.
            var expected = IsWebTarget(target) && !string.IsNullOrWhiteSpace(legacyProgId)
                ? legacyProgId
                : FirstNonEmpty(effective, latestProgId, legacyProgId);

            if (string.IsNullOrEmpty(expected))
            {
                continue;
            }

            var executable = ProbeExecutable(target, expected);
            var appName = ProbeAppName(target, expected);

            rules.Add(new ProtectionRule
            {
                Target = target,
                Kind = kind,
                ProgId = expected,
                AppName = appName,
                Executable = executable,
                Enabled = true,
            });
        }

        return new ProtectionBaseline
        {
            CapturedUtc = DateTime.UtcNow,
            Rules = rules
                .OrderBy(r => r.Target)
                .ToList(),
        };
    }

    public static IEnumerable<string> EnumerateTargets()
    {
        using var exts = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(FileExtsRoot);
        if (exts is not null)
        {
            foreach (var name in exts.GetSubKeyNames())
            {
                if (name.StartsWith('.'))
                {
                    yield return name;
                }
            }
        }

        using var urls = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(UrlAssocRoot);
        if (urls is not null)
        {
            foreach (var name in urls.GetSubKeyNames())
            {
                yield return name;
            }
        }
    }

    private static string? FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));

    private static bool IsWebTarget(string target) =>
        target is "http" or "https" or ".html" or ".htm";

    private static string? ProbeExecutable(string target, string progId) =>
        ProgIdResolver.GetExecutable(progId) ?? AssociationQuery.GetExecutable(target);

    private static string ProbeAppName(string target, string progId)
    {
        var resolved = ProgIdResolver.GetExecutable(progId);
        if (resolved is not null)
        {
            return ProgIdResolver.GetAppName(progId);
        }

        return AssociationQuery.GetFriendlyAppName(target) ?? progId;
    }
}
