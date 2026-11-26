using System.Globalization;
using Keep.Core.Associations;
using Keep.Core.Model;
using Keep.Core.Storage;

var tests = new (string Name, Action Run)[]
{
    ("latest hash matches the published reference vector", LatestReferenceVector),
    ("latest hash reproduces Explorer data on this machine", LatestLiveVectors),
    ("legacy hash reproduces Explorer data on this machine", LegacyLiveVectors),
    ("UCPD protected target set is exact", ProtectedTargets),
    ("event history survives compact and pretty JSONL", EventSplitter),
    ("settings round-trip through the JSON store", SettingsRoundTrip),
};

var failed = 0;
foreach (var (name, run) in tests)
{
    try
    {
        run();
        Console.WriteLine($"PASS  {name}");
    }
    catch (Exception ex)
    {
        failed++;
        Console.WriteLine($"FAIL  {name}: {ex.Message}");
    }
}

Console.WriteLine(failed == 0 ? $"\nall {tests.Length} tests passed" : $"\n{failed} of {tests.Length} tests failed");
return failed == 0 ? 0 : 1;

static void LatestReferenceVector()
{
    const string canonical =
        "copyright (c) microsoft. all rights reserved {3822b7ca-c2f4-4889-b8cc-4ce39a8fb81c}.pdd01dcb06ea49f32a0" +
        "b4deb148-0249-44c4-a8d3-5409e822c599msedgepdfs-1-5-21-673349297-2269585490-1023937497-500";

    Assert.Equal("JOBZ2dl4dKM=", UserChoiceLatestHash.Compute(canonical), "reference hash");
}

static void LatestLiveVectors()
{
    const string machineId = "{868D1AFF-A716-4BE7-B8C3-B0295C38CD65}";
    const string sid = "S-1-5-21-2484668175-2420551369-7022879-1001";

    var cases = new (string Target, string ProgId, string Timestamp, string Hash)[]
    {
        (".txt", "AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw", "2026-11-26T09:10:47.7330068Z", "yxdAwmpHGDw="),
        (".zip", "HrASOpen", "2026-11-26T08:55:22.8508989Z", "murFPj7VIO4="),
        (".html", "QuarkHTM", "2026-11-26T08:06:48.6670500Z", "uu7OIo8HV0Y="),
    };

    foreach (var (target, progId, timestamp, expected) in cases)
    {
        var lwt = DateTime.Parse(timestamp, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
        var canonical = UserChoiceLatestHash.BuildCanonical(target, progId, machineId, sid, lwt);
        Assert.Equal(expected, UserChoiceLatestHash.Compute(canonical), $"{target} latest hash");
    }
}

static void LegacyLiveVectors()
{
    const string sid = "S-1-5-21-2484668175-2420551369-7022879-1001";
    var cases = new (string Target, string ProgId, string Timestamp, string Hash)[]
    {
        (".html", "MSEdgeHTM", "2026-07-13T14:29:07.2425305Z", "D+1wZIZ0gOk="),
        (".txt", "AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw", "2026-11-26T09:10:47.7388174Z", "bccISEshHnQ="),
    };

    foreach (var (target, progId, timestamp, expected) in cases)
    {
        var lwt = DateTime.Parse(timestamp, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
        Assert.Equal(expected, UserChoiceHash.Compute(target, sid, progId, lwt), $"{target} legacy hash");
    }
}

static void ProtectedTargets()
{
    Assert.True(UcpdGuard.IsProtectedTarget("http"), "http protected");
    Assert.True(UcpdGuard.IsProtectedTarget(".PDF"), "pdf protected (case-insensitive)");
    Assert.False(UcpdGuard.IsProtectedTarget(".txt"), ".txt not protected");
    Assert.False(UcpdGuard.IsProtectedTarget("mailto"), "mailto not protected");
}

static void EventSplitter()
{
    var pretty = """
        {
          "target": ".html",
          "message": "a { brace } inside a string",
          "action": "blocked"
        }
        {
          "target": "http",
          "action": "restored"
        }
        """;

    var chunks = EventStore.SplitJsonObjects(pretty).ToList();
    Assert.Equal(2, chunks.Count, "pretty chunks");
    Assert.Contains(chunks[0], "a { brace } inside a string", "braces inside strings are preserved");

    var compact = """{"target":".txt","action":"detected"}""" + "\n" + """{"target":".zip","action":"failed"}""";
    Assert.Equal(2, EventStore.SplitJsonObjects(compact).Count(), "compact chunks");
}

static void SettingsRoundTrip()
{
    var temp = Path.Combine(Path.GetTempPath(), $"keep-test-{Guid.NewGuid():n}.json");
    try
    {
        JsonFile.Write(temp, new KeepSettings { ScanIntervalSeconds = 42, AutoRepair = false });
        var loaded = JsonFile.Read<KeepSettings>(temp)!;
        Assert.Equal(42, loaded.ScanIntervalSeconds, "interval");
        Assert.False(loaded.AutoRepair, "auto repair");
        Assert.True(File.Exists(temp), "file written");
    }
    finally
    {
        if (File.Exists(temp))
        {
            File.Delete(temp);
        }
    }
}

internal static class Assert
{
    public static void Equal<T>(T expected, T actual, string what)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"{what}: expected '{expected}' but got '{actual}'");
        }
    }

    public static void True(bool condition, string what)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"{what}: expected true");
        }
    }

    public static void False(bool condition, string what)
    {
        if (condition)
        {
            throw new InvalidOperationException($"{what}: expected false");
        }
    }

    public static void Contains(string value, string expected, string what)
    {
        if (!value.Contains(expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"{what}: '{expected}' not found");
        }
    }
}
