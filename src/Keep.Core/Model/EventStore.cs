using System.Text;
using System.Text.Json;
using Keep.Core.Storage;

namespace Keep.Core.Model;

public enum GuardianAction
{
    Detected,
    Restored,
    Blocked,
    Failed,
    Info,
}

/// <summary>One entry in the tamper history.</summary>
public sealed class GuardianEvent
{
    public string Id { get; set; } = Guid.NewGuid().ToString("n")[..12];

    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;

    public string Target { get; set; } = string.Empty;

    public string AppName { get; set; } = string.Empty;

    /// <summary>ProgId that was in effect ("" when nothing was set).</summary>
    public string From { get; set; } = string.Empty;

    /// <summary>ProgId the guardian put back.</summary>
    public string To { get; set; } = string.Empty;

    public GuardianAction Action { get; set; }

    public string? Message { get; set; }
}

/// <summary>Append-only history (JSONL on disk, bounded ring in memory).</summary>
public sealed class EventStore
{
    private static readonly JsonSerializerOptions CompactOptions = new(JsonFile.Options)
    {
        WriteIndented = false,
    };

    private readonly List<GuardianEvent> _events = new();
    private readonly object _gate = new();
    private int _appendsSinceCompact;

    public int Limit { get; set; } = 500;

    public IReadOnlyList<GuardianEvent> Recent
    {
        get
        {
            lock (_gate)
            {
                return _events.ToList();
            }
        }
    }

    public int CountToday(GuardianAction action) => Recent.Count(e =>
        e.Action == action && e.TimestampUtc.ToLocalTime().Date == DateTime.Today);

    public static EventStore Load(int limit)
    {
        var store = new EventStore { Limit = limit };
        if (!File.Exists(AppPaths.EventsFile))
        {
            return store;
        }

        try
        {
            var text = File.ReadAllText(AppPaths.EventsFile);
            foreach (var chunk in SplitJsonObjects(text))
            {
                try
                {
                    var item = JsonSerializer.Deserialize<GuardianEvent>(chunk, JsonFile.Options);
                    if (item is not null)
                    {
                        store._events.Add(item);
                    }
                }
                catch (JsonException)
                {
                    // Skip a corrupt record rather than losing the whole history.
                }
            }
        }
        catch (IOException)
        {
            return store;
        }

        if (store._events.Count > limit)
        {
            store._events.RemoveRange(0, store._events.Count - limit);
        }

        store._events.Reverse();
        return store;
    }

    public void Append(GuardianEvent item)
    {
        lock (_gate)
        {
            _events.Insert(0, item);
            if (_events.Count > Limit)
            {
                _events.RemoveRange(Limit, _events.Count - Limit);
            }

            AppPaths.EnsureCreated();
            File.AppendAllText(AppPaths.EventsFile, JsonSerializer.Serialize(item, CompactOptions) + Environment.NewLine);

            if (++_appendsSinceCompact > 100)
            {
                Compact();
            }
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _events.Clear();
            if (File.Exists(AppPaths.EventsFile))
            {
                File.Delete(AppPaths.EventsFile);
            }
        }
    }

    private void Compact()
    {
        _appendsSinceCompact = 0;
        var snapshot = _events.AsEnumerable().Reverse().Take(Limit).ToList();
        var temp = AppPaths.EventsFile + ".tmp";
        File.WriteAllLines(temp, snapshot.Select(e => JsonSerializer.Serialize(e, CompactOptions)));
        File.Move(temp, AppPaths.EventsFile, overwrite: true);
    }

    /// <summary>
    /// Splits a file that may contain compact JSONL or pretty-printed objects
    /// (older builds wrote indented entries) into individual JSON documents.
    /// </summary>
    public static IEnumerable<string> SplitJsonObjects(string text)
    {
        var buffer = new StringBuilder();
        var depth = 0;
        var inString = false;
        var escape = false;

        foreach (var ch in text)
        {
            if (inString)
            {
                buffer.Append(ch);
                if (escape)
                {
                    escape = false;
                }
                else if (ch == '\\')
                {
                    escape = true;
                }
                else if (ch == '"')
                {
                    inString = false;
                }

                continue;
            }

            switch (ch)
            {
                case '"':
                    inString = true;
                    buffer.Append(ch);
                    break;
                case '{':
                    depth++;
                    buffer.Append(ch);
                    break;
                case '}':
                    depth--;
                    buffer.Append(ch);
                    if (depth == 0)
                    {
                        yield return buffer.ToString();
                        buffer.Clear();
                    }

                    break;
                default:
                    if (depth > 0)
                    {
                        buffer.Append(ch);
                    }

                    break;
            }
        }
    }
}
