using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keep.Core.Storage;

namespace Keep.Core.Browser;

/// <summary>The browser settings we watch: start page, startup tabs, search engine.</summary>
public sealed class BrowserProfileRule
{
    public string Browser { get; set; } = string.Empty;

    public string Profile { get; set; } = "Default";

    public string PreferencesPath { get; set; } = string.Empty;

    public string? Homepage { get; set; }

    public bool HomepageIsNewTab { get; set; }

    public List<string> StartupUrls { get; set; } = new();

    public string? SearchProvider { get; set; }

    public string DisplayName => $"{Browser} · {Profile}";
}

public sealed class BrowserBaseline
{
    public DateTime CapturedUtc { get; set; }

    public List<BrowserProfileRule> Profiles { get; set; } = new();

    public static string FilePath => Path.Combine(AppPaths.Root, "browsers.json");

    public static BrowserBaseline? Load() => JsonFile.Read<BrowserBaseline>(FilePath);

    public void Save() => JsonFile.Write(FilePath, this);
}

public sealed record BrowserProblem(string Kind, string Detail);

public sealed record BrowserStatus(BrowserProfileRule Rule, bool Running, IReadOnlyList<BrowserProblem> Problems)
{
    public bool Ok => Problems.Count == 0;
}

/// <summary>
/// Reads Chromium-style <c>Preferences</c> files (Edge/Chrome/Brave) and
/// reports homepage / startup tabs / default search drift. Repairs are written
/// directly to the JSON file and only attempted while the browser is closed.
/// </summary>
public sealed class BrowserMonitor
{
    private static readonly (string Name, string Vendor, string Product, string Process)[] KnownBrowsers =
    {
        ("Microsoft Edge", "Microsoft", "Edge", "msedge"),
        ("Google Chrome", "Google", "Chrome", "chrome"),
        ("Brave", "BraveSoftware", "Brave-Browser", "brave"),
        ("Vivaldi", "Vivaldi", "Vivaldi", "vivaldi"),
    };

    public BrowserBaseline Capture()
    {
        var baseline = new BrowserBaseline { CapturedUtc = DateTime.UtcNow };
        foreach (var profile in Discover())
        {
            baseline.Profiles.Add(profile);
        }

        return baseline;
    }

    public IEnumerable<BrowserProfileRule> Discover()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        foreach (var (name, vendor, product, _) in KnownBrowsers)
        {
            var root = Path.Combine(local, vendor, product, "User Data");
            if (!Directory.Exists(root))
            {
                continue;
            }

            foreach (var prefs in Directory.EnumerateFiles(root, "Preferences", SearchOption.AllDirectories))
            {
                var profileDirectory = Path.GetFileName(Path.GetDirectoryName(prefs));
                if (profileDirectory is "Snapshots" or "Backup" or null)
                {
                    continue;
                }

                var rule = Parse(prefs, name, profileDirectory);
                if (rule is not null)
                {
                    yield return rule;
                }
            }
        }
    }

    public BrowserStatus Evaluate(BrowserProfileRule expected)
    {
        var running = IsRunning(expected.Browser);
        var problems = new List<BrowserProblem>();

        var current = Parse(expected.PreferencesPath, expected.Browser, expected.Profile);
        if (current is null)
        {
            return new BrowserStatus(expected, running, new[] { new BrowserProblem("missing", "配置文件不存在") });
        }

        if (!string.Equals(current.Homepage ?? string.Empty, expected.Homepage ?? string.Empty, StringComparison.OrdinalIgnoreCase))
        {
            problems.Add(new BrowserProblem("homepage", $"{Show(expected.Homepage)} → {Show(current.Homepage)}"));
        }

        if (current.HomepageIsNewTab != expected.HomepageIsNewTab)
        {
            problems.Add(new BrowserProblem("homepage-mode", "主页开关被修改"));
        }

        if (!current.StartupUrls.SequenceEqual(expected.StartupUrls, StringComparer.OrdinalIgnoreCase))
        {
            problems.Add(new BrowserProblem("startup", $"{expected.StartupUrls.Count} 个启动页 → {current.StartupUrls.Count} 个"));
        }

        if (!string.Equals(current.SearchProvider ?? string.Empty, expected.SearchProvider ?? string.Empty, StringComparison.OrdinalIgnoreCase))
        {
            problems.Add(new BrowserProblem("search", $"{Show(expected.SearchProvider)} → {Show(current.SearchProvider)}"));
        }

        return new BrowserStatus(expected, running, problems);
    }

    /// <summary>Restores the watched fields. Returns null on success.</summary>
    public string? Repair(BrowserProfileRule expected)
    {
        if (IsRunning(expected.Browser))
        {
            return $"{expected.Browser} 正在运行，关闭后才能写回设置";
        }

        if (!File.Exists(expected.PreferencesPath))
        {
            return "配置文件不存在";
        }

        try
        {
            var root = JsonNode.Parse(File.ReadAllText(expected.PreferencesPath)) as JsonObject;
            if (root is null)
            {
                return "配置文件格式无法解析";
            }

            root["homepage"] = expected.Homepage ?? string.Empty;
            root["homepage_is_newtabpage"] = expected.HomepageIsNewTab;

            var session = root["session"] as JsonObject ?? new JsonObject();
            root["session"] = session;
            session["startup_urls"] = new JsonArray(expected.StartupUrls.Select(u => (JsonNode?)JsonValue.Create(u)).ToArray());

            if (!string.IsNullOrEmpty(expected.SearchProvider))
            {
                if (root["default_search_provider_data"] is JsonObject data && data["template_url_data"] is JsonObject template)
                {
                    template["keyword"] = expected.SearchProvider;
                }
            }

            var temp = expected.PreferencesPath + ".keep.tmp";
            File.WriteAllText(temp, root.ToJsonString(new JsonSerializerOptions { WriteIndented = false }));
            File.Copy(temp, expected.PreferencesPath, overwrite: true);
            File.Delete(temp);
            return null;
        }
        catch (JsonException)
        {
            return "配置文件格式无法解析";
        }
        catch (IOException ex)
        {
            return ex.Message;
        }
        catch (UnauthorizedAccessException ex)
        {
            return ex.Message;
        }
    }

    public static bool IsRunning(string browser)
    {
        var process = KnownBrowsers.FirstOrDefault(b => b.Name == browser).Process;
        if (string.IsNullOrEmpty(process))
        {
            return false;
        }

        return Process.GetProcessesByName(process).Length > 0;
    }

    private static BrowserProfileRule? Parse(string path, string browser, string profile)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;

            var homepage = root.TryGetProperty("homepage", out var homepageElement) ? homepageElement.GetString() : null;

            var newTab = false;
            if (root.TryGetProperty("homepage_is_newtabpage", out var newTabElement)
                && (newTabElement.ValueKind == JsonValueKind.True || newTabElement.ValueKind == JsonValueKind.False))
            {
                newTab = newTabElement.GetBoolean();
            }

            var startup = new List<string>();
            if (root.TryGetProperty("session", out var session)
                && session.TryGetProperty("startup_urls", out var urls)
                && urls.ValueKind == JsonValueKind.Array)
            {
                foreach (var url in urls.EnumerateArray())
                {
                    var value = url.GetString();
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        startup.Add(value);
                    }
                }
            }

            string? search = null;
            if (root.TryGetProperty("default_search_provider_data", out var data)
                && data.TryGetProperty("template_url_data", out var template)
                && template.TryGetProperty("keyword", out var keyword))
            {
                search = keyword.GetString();
            }
            else if (root.TryGetProperty("default_search_provider", out var provider)
                     && provider.TryGetProperty("keyword", out var legacyKeyword))
            {
                search = legacyKeyword.GetString();
            }

            return new BrowserProfileRule
            {
                Browser = browser,
                Profile = profile,
                PreferencesPath = path,
                Homepage = homepage,
                HomepageIsNewTab = newTab,
                StartupUrls = startup,
                SearchProvider = search,
            };
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string Show(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "（空）" : value;
}
