using Keep.Core.Associations;
using Keep.Core.Model;

namespace Keep.Core.Engine;

public enum RuleState
{
    Ok,

    /// <summary>Another program owns the association.</summary>
    Tampered,

    /// <summary>No default app is registered any more.</summary>
    NoDefault,

    /// <summary>Tampered, but Windows (UCPD) refuses third-party writes.</summary>
    BlockedBySystem,

    /// <summary>The expected program is no longer installed; nothing to repair.</summary>
    AppMissing,
}

public sealed record RuleStatus(
    ProtectionRule Rule,
    RuleState State,
    string CurrentProgId,
    string CurrentAppName,
    bool RepairBlocked)
{
    public bool NeedsRepair => State is RuleState.Tampered or RuleState.NoDefault or RuleState.BlockedBySystem;
}

public sealed record ScanReport(
    DateTime TimestampUtc,
    IReadOnlyList<RuleStatus> Items,
    int Restored,
    int Blocked,
    int Failed)
{
    public int Checked => Items.Count;

    public int Problems => Items.Count(i => i.NeedsRepair);

    public int Healthy => Items.Count(i => i.State == RuleState.Ok);
}

/// <summary>Evaluates the baseline against the live machine and repairs drift.</summary>
public sealed class GuardianEngine
{
    private readonly UserChoiceStore _legacy = new();
    private readonly UserChoiceLatestStore _latest = new();
    private readonly AssociationWriter _writer = new();
    private readonly Dictionary<string, DateTime> _lastDetected = new(StringComparer.OrdinalIgnoreCase);

    // Targets where Windows refused a write at least once (UCPD also covers
    // some Office associations that are not in the static list).
    private readonly HashSet<string> _systemBlocked = new(StringComparer.OrdinalIgnoreCase);

    public ProtectionBaseline Baseline { get; private set; }

    public KeepSettings Settings { get; }

    public EventStore Events { get; }

    public GuardianEngine(ProtectionBaseline baseline, KeepSettings settings, EventStore events)
    {
        Baseline = baseline;
        Settings = settings;
        Events = events;
    }

    /// <summary>Windows blocks writes to these targets while UCPD is running.</summary>
    public bool IsWriteBlocked(ProtectionRule rule) =>
        (UcpdGuard.IsProtectionActive && UcpdGuard.IsProtectedTarget(rule.Target))
        || (_systemBlocked.Contains(rule.Target) && UcpdGuard.IsProtectionActive);

    public RuleStatus Evaluate(ProtectionRule rule)
    {
        var latest = _latest.Read(rule.Target);
        var legacy = _legacy.Read(rule.Target);
        var registered = FirstNonEmpty(latest.ProgId, legacy.ProgId);
        var blocked = IsWriteBlocked(rule);

        if (!string.IsNullOrEmpty(registered)
            && string.Equals(registered, rule.ProgId, StringComparison.OrdinalIgnoreCase))
        {
            // The registry already names the expected app. A shell query that
            // returns nothing here usually means the app was uninstalled
            // rather than tampered with, so treating it as healthy avoids
            // retrying a repair that can never succeed.
            return new RuleStatus(rule, RuleState.Ok, registered!, rule.AppName, blocked);
        }

        var effective = DefaultAssociationQuery.GetDefaultProgId(rule.Target);
        if (string.Equals(effective, rule.ProgId, StringComparison.OrdinalIgnoreCase))
        {
            return new RuleStatus(rule, RuleState.Ok, effective!, rule.AppName, blocked);
        }

        if (blocked)
        {
            return new RuleStatus(rule, RuleState.BlockedBySystem, effective ?? registered ?? string.Empty, rule.AppName, true);
        }

        var state = string.IsNullOrEmpty(effective) && string.IsNullOrEmpty(registered)
            ? RuleState.NoDefault
            : RuleState.Tampered;

        // An app that was uninstalled leaves a ProgId that can never resolve.
        // Report it once but do not keep trying to repair it.
        if (state == RuleState.Tampered
            && string.IsNullOrEmpty(effective)
            && !rule.ProgId.StartsWith("AppX", StringComparison.OrdinalIgnoreCase)
            && ProgIdResolver.GetExecutable(rule.ProgId) is null)
        {
            state = RuleState.AppMissing;
        }

        return new RuleStatus(rule, state, effective ?? registered ?? string.Empty, rule.AppName, false);
    }

    public ScanReport Scan(bool allowRepair, CancellationToken cancellationToken = default)
    {
        var statuses = new List<RuleStatus>(Baseline.Rules.Count);
        var restored = 0;
        var blocked = 0;
        var failed = 0;
        var now = DateTime.UtcNow;

        foreach (var rule in Baseline.Rules.Where(r => r.Enabled))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var status = Evaluate(rule);
            if (!status.NeedsRepair)
            {
                continue;
            }

            if (status.State == RuleState.BlockedBySystem)
            {
                blocked++;
                statuses.Add(status);
                RecordDetected(status, "Windows 的 UCPD 驱动阻止了写入；开启「深度守护」后可自动还原。", now);
                continue;
            }

            if (!allowRepair)
            {
                statuses.Add(status);
                RecordDetected(status, null, now);
                continue;
            }

            var outcome = Repair(rule);
            statuses.Add(outcome.Status);
            switch (outcome.Action)
            {
                case GuardianAction.Restored:
                    restored++;
                    break;
                case GuardianAction.Blocked:
                    blocked++;
                    break;
                default:
                    failed++;
                    break;
            }
        }

        Settings.LastScanUtc = now;
        return new ScanReport(now, statuses, restored, blocked, failed);
    }

    public sealed record RepairOutcome(RuleStatus Status, GuardianAction Action, string? Message);

    public RepairOutcome Repair(ProtectionRule rule)
    {
        if (IsWriteBlocked(rule))
        {
            var blockedStatus = new RuleStatus(rule, RuleState.BlockedBySystem, string.Empty, rule.AppName, true);
            var message = "Windows 的 UCPD 驱动阻止了写入；开启「深度守护」后可自动还原。";
            Events.Append(News(rule, GuardianAction.Blocked, string.Empty, rule.ProgId, message));
            return new RepairOutcome(blockedStatus, GuardianAction.Blocked, message);
        }

        var before = DefaultAssociationQuery.GetDefaultProgId(rule.Target) ?? string.Empty;
        var result = _writer.Write(rule.Target, rule.ProgId);

        if (result.Effective)
        {
            Events.Append(News(rule, GuardianAction.Restored, before, rule.ProgId, null));
            return new RepairOutcome(new RuleStatus(rule, RuleState.Ok, rule.ProgId, rule.AppName, false), GuardianAction.Restored, null);
        }

        if (IsAccessDenied(result))
        {
            _systemBlocked.Add(rule.Target);
            var blockedReason = "Windows 的 UCPD 驱动阻止了写入；开启「深度守护」后可自动还原。";
            Events.Append(News(rule, GuardianAction.Blocked, before, rule.ProgId, blockedReason));
            return new RepairOutcome(
                new RuleStatus(rule, RuleState.BlockedBySystem, before, rule.AppName, true),
                GuardianAction.Blocked,
                blockedReason);
        }

        var reason = result.LatestError ?? result.LegacyError ?? "写入后系统仍未采用目标程序。";
        Events.Append(News(rule, GuardianAction.Failed, before, rule.ProgId, reason));
        return new RepairOutcome(
            new RuleStatus(rule, RuleState.Tampered, before, rule.AppName, false),
            GuardianAction.Failed,
            reason);
    }

    public int RepairAll(IEnumerable<ProtectionRule> rules)
    {
        var repaired = 0;
        foreach (var rule in rules)
        {
            if (Repair(rule).Action == GuardianAction.Restored)
            {
                repaired++;
            }
        }

        return repaired;
    }

    private static bool IsAccessDenied(AssociationWriter.Result result) =>
        result.LegacyError == UserChoiceStore.AccessDeniedMessage || result.LatestError == UserChoiceStore.AccessDeniedMessage;

    private void RecordDetected(RuleStatus status, string? message, DateTime now)
    {
        if (_lastDetected.TryGetValue(status.Rule.Target, out var last) && now - last < TimeSpan.FromMinutes(10))
        {
            return;
        }

        // Also suppress repeats across restarts: the same target already
        // reported recently in the persisted history.
        if (Events.Recent.Any(e =>
                e.Action == GuardianAction.Detected
                && string.Equals(e.Target, status.Rule.Target, StringComparison.OrdinalIgnoreCase)
                && now - e.TimestampUtc < TimeSpan.FromMinutes(10)))
        {
            _lastDetected[status.Rule.Target] = now;
            return;
        }

        _lastDetected[status.Rule.Target] = now;
        Events.Append(News(status.Rule, GuardianAction.Detected, status.CurrentProgId, status.Rule.ProgId, message));
    }

    private static GuardianEvent News(ProtectionRule rule, GuardianAction action, string from, string to, string? message) => new()
    {
        Target = rule.Target,
        AppName = rule.AppName,
        From = from,
        To = to,
        Action = action,
        Message = message,
    };

    private static string? FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
}
