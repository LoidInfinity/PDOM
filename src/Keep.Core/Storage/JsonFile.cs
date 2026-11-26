using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keep.Core.Storage;

/// <summary>Well-known locations for the guardian's own state.</summary>
public static class AppPaths
{
    public static string Root { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Keep");

    public static string SettingsFile => Path.Combine(Root, "settings.json");
    public static string BaselineFile => Path.Combine(Root, "baseline.json");
    public static string EventsFile => Path.Combine(Root, "events.jsonl");
    public static string TempDirectory => Path.Combine(Root, "tmp");

    public static void EnsureCreated()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(TempDirectory);
    }
}

/// <summary>Small JSON persistence helper with atomic-ish writes.</summary>
public static class JsonFile
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static T? Read<T>(string path) where T : class
    {
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            return JsonSerializer.Deserialize<T>(File.ReadAllText(path), Options);
        }
        catch (JsonException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    public static void Write<T>(string path, T value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(value, Options));
        File.Move(temp, path, overwrite: true);
    }
}
