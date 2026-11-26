using Keep.Core.Associations;
using Keep.Core.Engine;
using Keep.Core.Model;
using Keep.Core.Storage;

namespace Keep.Cli;

internal static class Program
{
    private static int Main(string[] args)
    {
        var command = args.Length > 0 ? args[0].ToLowerInvariant() : "help";
        try
        {
            return command switch
            {
                "verify" => Verify(args.Skip(1).ToArray()),
                "list" => List(args.Skip(1).ToArray()),
                "write" => Write(args.Skip(1).ToArray()),
                "roundtrip" => RoundTrip(args.Skip(1).ToArray()),
                "default" => Default(args.Skip(1).ToArray()),
                "latest" => Latest(args.Skip(1).ToArray()),
                "latestwrite" => LatestWrite(args.Skip(1).ToArray()),
                "vector" => Vector(),
                "assocwrite" => AssocWrite(args.Skip(1).ToArray()),
                "capture" => Capture(),
                "scan" => Scan(args.Skip(1).ToArray()),
                "dump" => Dump(args.Skip(1).ToArray()),
                "ucpd" => Ucpd(),
                _ => Help(),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static int Help()
    {
        Console.WriteLine("""
            keep CLI - association diagnostics

              verify            recompute the UserChoice hash for every association and report mismatches
              list [--all]      list associations with the executable the shell resolves
              write <t> <pid>   write an association (target ".txt" or protocol "http")
              roundtrip <t>     backup, change, verify, restore an association
              ucpd              show UserChoice Protection Driver status
            """);
        return 0;
    }

    private static int Capture()
    {
        var settings = KeepSettings.Load();
        var baseline = BaselineBuilder.Capture();
        baseline.Save();
        settings.BaselineCapturedUtc = baseline.CapturedUtc;
        settings.Save();
        Console.WriteLine($"captured {baseline.Rules.Count} protected associations -> {AppPaths.BaselineFile}");

        foreach (var group in baseline.Rules.GroupBy(r => r.AppName).OrderByDescending(g => g.Count()).Take(10))
        {
            Console.WriteLine($"  {group.Key,-32} {group.Count()}");
        }

        return 0;
    }

    private static int Dump(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("usage: dump <target> [...]");
            return 1;
        }

        var legacyStore = new UserChoiceStore();
        var latestStore = new UserChoiceLatestStore();
        Console.WriteLine($"sid={legacyStore.UserSid}");
        Console.WriteLine($"machineId={latestStore.MachineId}");

        foreach (var target in args)
        {
            var legacy = legacyStore.Read(target);
            var latest = latestStore.Read(target);
            Console.WriteLine($"[{target}]");
            Console.WriteLine($"  legacy progId={legacy.ProgId} hash={legacy.Hash} lwt={legacy.LastWriteUtc:O} valid={legacyStore.IsHashValid(legacy)}");
            Console.WriteLine($"  latest progId={latest.ProgId} hash={latest.Hash} lwt={latest.ProgIdLastWriteUtc:O} valid={latestStore.IsHashValid(latest)}");
        }

        return 0;
    }

    private static int Scan(string[] args)
    {
        var baseline = ProtectionBaseline.Load();
        if (baseline is null)
        {
            Console.Error.WriteLine("no baseline; run `capture` first");
            return 1;
        }

        var settings = KeepSettings.Load();
        var events = EventStore.Load(settings.HistoryLimit);
        var engine = new GuardianEngine(baseline, settings, events);
        var repair = args.Contains("--repair");
        var started = DateTime.UtcNow;
        var report = engine.Scan(repair);
        var elapsed = DateTime.UtcNow - started;
        settings.Save();

        Console.WriteLine($"checked={report.Checked} healthy={report.Healthy} problems={report.Problems} " +
                          $"restored={report.Restored} blocked={report.Blocked} failed={report.Failed} " +
                          $"in {elapsed.TotalMilliseconds:F0} ms");

        foreach (var item in report.Items.Take(40))
        {
            Console.WriteLine($"  {item.Rule.Target,-12} {item.State,-16} current={item.CurrentProgId,-32} expected={item.Rule.ProgId}");
        }

        return 0;
    }

    private static int Ucpd()
    {
        Console.WriteLine($"UCPD: {UcpdGuard.Describe()}");
        Console.WriteLine($"protection active: {UcpdGuard.IsProtectionActive}");
        return 0;
    }

    private static int Verify(string[] args)
    {
        var store = new UserChoiceStore();
        Console.WriteLine($"user SID: {store.UserSid}");
        Console.WriteLine($"UCPD: {UcpdGuard.Describe()} -> active={UcpdGuard.IsProtectionActive}");
        Console.WriteLine();

        var targets = EnumerateTargets().ToArray();
        var valid = 0;
        var invalid = 0;
        var missing = 0;
        var failures = new List<string>();

        foreach (var target in targets)
        {
            var snapshot = store.Read(target);
            if (!snapshot.Exists)
            {
                missing++;
                continue;
            }

            if (store.IsHashValid(snapshot))
            {
                valid++;
            }
            else
            {
                invalid++;
                failures.Add($"{target,-12} progid={snapshot.ProgId,-28} stored={snapshot.Hash,-16} lwt={snapshot.LastWriteUtc:O}");
            }
        }

        Console.WriteLine($"targets={targets.Length}  hash-valid={valid}  hash-invalid={invalid}  missing={missing}");
        if (failures.Count > 0)
        {
            Console.WriteLine("-- invalid --");
            foreach (var line in failures)
            {
                Console.WriteLine(line);
            }
        }

        return invalid == 0 ? 0 : 2;
    }

    private static int List(string[] args)
    {
        var all = args.Contains("--all");
        var store = new UserChoiceStore();
        foreach (var target in EnumerateTargets())
        {
            var snapshot = store.Read(target);
            if (!snapshot.Exists && !all)
            {
                continue;
            }

            var exe = AssociationQuery.GetExecutable(target);
            var name = AssociationQuery.GetFriendlyAppName(target);
            var state = snapshot.Exists ? (store.IsHashValid(snapshot) ? "ok" : "bad-hash") : "none";
            Console.WriteLine($"{target,-12} {state,-9} {snapshot.ProgId,-28} {name,-28} {exe}");
        }

        return 0;
    }

    private static int Write(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: write <target> <progId>");
            return 1;
        }

        var target = args[0];
        var progId = args[1];
        var store = new UserChoiceStore();
        var before = store.Read(target);
        Console.WriteLine($"before: exists={before.Exists} progId={before.ProgId} hash={before.Hash}");

        var error = store.Write(target, progId);
        Console.WriteLine(error is null ? "write: ok" : $"write: {error}");

        var after = store.Read(target);
        Console.WriteLine($"after:  exists={after.Exists} progId={after.ProgId} hash={after.Hash} valid={store.IsHashValid(after)}");
        Console.WriteLine($"shell exe: {AssociationQuery.GetExecutable(target)}");

        return error is null && store.IsHashValid(after) ? 0 : 3;
    }

    private static int Latest(string[] args)
    {
        var store = new UserChoiceLatestStore();
        var targets = args.Length > 0 ? args : EnumerateTargets().ToArray();
        var ok = 0;
        var bad = 0;
        var missing = 0;

        foreach (var target in targets)
        {
            var snapshot = store.Read(target);
            if (!snapshot.Exists)
            {
                missing++;
                continue;
            }

            var valid = store.IsHashValid(snapshot);
            if (valid)
            {
                ok++;
            }
            else
            {
                bad++;
            }

            Console.WriteLine($"{target,-12} latest={(valid ? "ok" : "bad"),-4} progId={snapshot.ProgId,-30} hash={snapshot.Hash}");
        }

        Console.WriteLine($"latest-valid={ok} latest-invalid={bad} missing={missing}");
        return bad == 0 ? 0 : 2;
    }

    private static int LatestWrite(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: latestwrite <target> <progId>");
            return 1;
        }

        var store = new UserChoiceLatestStore();
        var error = store.Write(args[0], args[1]);
        var snapshot = store.Read(args[0]);
        Console.WriteLine(error ?? "write: ok");
        Console.WriteLine($"progId={snapshot.ProgId} hash={snapshot.Hash} valid={store.IsHashValid(snapshot)}");
        Console.WriteLine($"shell default: {DefaultAssociationQuery.GetDefaultProgId(args[0])}");
        return error is null && store.IsHashValid(snapshot) ? 0 : 3;
    }

    private static int AssocWrite(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: assocwrite <target> <progId>");
            return 1;
        }

        var writer = new AssociationWriter();
        var result = writer.Write(args[0], args[1]);
        Console.WriteLine($"ok={result.Ok} effective={result.Effective} resolved={result.ResolvedProgId}");
        Console.WriteLine($"legacy: {result.LegacyError ?? "ok"}");
        Console.WriteLine($"latest: {result.LatestError ?? "ok"}");
        return result.Ok && result.Effective ? 0 : 3;
    }

    private static int Vector()
    {
        const string canonical =
            "copyright (c) microsoft. all rights reserved {3822b7ca-c2f4-4889-b8cc-4ce39a8fb81c}.pdd01dcb06ea49f32a0" +
            "b4deb148-0249-44c4-a8d3-5409e822c599msedgepdf" +
            "s-1-5-21-673349297-2269585490-1023937497-500";
        const string expected = "JOBZ2dl4dKM=";
        var actual = UserChoiceLatestHash.Compute(canonical);
        Console.WriteLine($"vector: {actual} (expected {expected}) {(actual == expected ? "OK" : "FAIL")}");
        return actual == expected ? 0 : 2;
    }

    private static int Default(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("usage: default <target>");
            return 1;
        }

        foreach (var target in args)
        {
            var registered = DefaultAssociationQuery.GetDefaultProgId(target);
            var store = new UserChoiceStore();
            var snapshot = store.Read(target);
            Console.WriteLine($"{target,-12} shell={registered ?? "(none)",-28} userChoice={snapshot.ProgId ?? "(none)",-28} valid={store.IsHashValid(snapshot)}");
        }

        return 0;
    }

    private static int RoundTrip(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("usage: roundtrip <target>");
            return 1;
        }

        var target = args[0];
        var store = new UserChoiceStore();
        var before = store.Read(target);
        if (!before.Exists || string.IsNullOrEmpty(before.ProgId))
        {
            Console.Error.WriteLine($"{target} has no UserChoice to back up.");
            return 1;
        }

        Console.WriteLine($"backup: progId={before.ProgId} valid={store.IsHashValid(before)} exe={AssociationQuery.GetExecutable(target)}");

        // Rewrite the same ProgId with a freshly computed hash. If the hash is
        // correct the shell keeps resolving the same executable.
        var error = store.Write(target, before.ProgId);
        var after = store.Read(target);
        Console.WriteLine($"rewrite: {error ?? "ok"}, progId={after.ProgId}, valid={store.IsHashValid(after)}");
        Console.WriteLine($"shell exe: {AssociationQuery.GetExecutable(target)}");
        return error is null && store.IsHashValid(after) ? 0 : 3;
    }

    private static IEnumerable<string> EnumerateTargets()
    {
        const string fileExts = @"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts";
        const string urlAssoc = @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations";

        using var exts = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(fileExts);
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

        using var urls = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(urlAssoc);
        if (urls is not null)
        {
            foreach (var name in urls.GetSubKeyNames())
            {
                yield return name;
            }
        }
    }
}

