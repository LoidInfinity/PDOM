using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using Keep.App.Services;
using Keep.Core.Associations;
using Keep.Core.Browser;
using Keep.Core.Engine;
using Keep.Core.Model;
using Keep.Core.Storage;

namespace Keep.App.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private readonly SemaphoreSlim _scanGate = new(1, 1);
    private ProtectionBaseline? _baseline;
    private KeepSettings _settings = new();
    private EventStore _events = new();
    private GuardianEngine? _engine;
    private ScanReport? _lastReport;
    private string _searchText = string.Empty;
    private string _filter = "all";
    private string _scanInfo = "尚未检测";
    private string _countdown = string.Empty;
    private int _restoredToday;
    private int _blockedCount;

    public MainViewModel()
    {
        RulesView = CollectionViewSource.GetDefaultView(Rules);
        RulesView.Filter = FilterRule;
        RulesView.SortDescriptions.Add(new SortDescription(nameof(RuleRow.GroupRank), ListSortDirection.Ascending));
        RulesView.SortDescriptions.Add(new SortDescription(nameof(RuleRow.Target), ListSortDirection.Ascending));

        ScanCommand = new RelayCommand(() => _ = ScanAsync(AutoRepair));
        CaptureCommand = new RelayCommand(CaptureBaseline);
        RepairAllCommand = new RelayCommand(() => _ = RepairProblemsAsync());
        RepairRuleCommand = new RelayCommand(parameter =>
        {
            if (parameter is RuleRow row)
            {
                _ = RepairRuleAsync(row);
            }
        });
        ClearHistoryCommand = new RelayCommand(ClearHistory);
        OpenDataFolderCommand = new RelayCommand(OpenDataFolder);
        DismissBannerCommand = new RelayCommand(() =>
        {
            BannerDismissed = true;
            Raise(nameof(ShowUcpdBanner));
        });
    }

    public ObservableCollection<RuleRow> Rules { get; } = new();

    public ObservableCollection<EventRow> History { get; } = new();

    public ObservableCollection<BrowserRow> Browsers { get; } = new();

    public ICollectionView RulesView { get; }

    public RelayCommand ScanCommand { get; }

    public RelayCommand CaptureCommand { get; }

    public RelayCommand RepairAllCommand { get; }

    public RelayCommand RepairRuleCommand { get; }

    public RelayCommand ClearHistoryCommand { get; }

    public RelayCommand OpenDataFolderCommand { get; }

    public RelayCommand DismissBannerCommand { get; }

    public KeepSettings Settings => _settings;

    public ProtectionBaseline? Baseline => _baseline;

    public GuardianEngine? Engine => _engine;

    public bool HasBaseline => _baseline is not null && _baseline.Rules.Count > 0;

    public bool Scanning { get; private set; }

    public bool BannerDismissed { get; private set; }

    public bool UcpdActive => UcpdGuard.IsProtectionActive;

    public bool DeepMode => !UcpdActive;

    public bool ShowUcpdBanner => UcpdActive && HasBaseline && !BannerDismissed;

    public string UcpdText => UcpdGuard.IsProtectionActive
        ? "UCPD 正在拦截默认浏览器 / HTML / PDF 的自动还原"
        : UcpdGuard.DriverInstalled ? "UCPD 已停止，深度守护生效" : "此系统没有 UCPD 驱动";

    public string StatusTitle => HasBaseline
        ? (ProblemCount == 0 ? "系统设置处于守护中" : $"发现 {ProblemCount} 项设置偏离基准")
        : "灏氭湭寤虹珛瀹堟姢鍩哄噯";

    public string StatusSubtitle => HasBaseline
        ? "任何程序改动默认打开方式、默认浏览器，都会在下一轮检测中被发现并还原。"
        : "先把你当前的默认应用记录为基准，之后被改动时会自动还原。";

    public int TotalRules => Rules.Count;

    public int HealthyCount => Rules.Count(r => r.IsHealthy);

    public int ProblemCount => Rules.Count(r => r.HasProblem);

    public int RestoredToday => _restoredToday;

    public int BlockedCount => _blockedCount;

    public bool HasProblems => ProblemCount > 0;

    public int BrowserProblemCount => Browsers.Count(b => !b.IsOk);

    public IEnumerable<EventRow> RecentHistory => History.Take(6);

    public bool HasHistory => History.Count > 0;

    public string ScanInfo
    {
        get => _scanInfo;
        set => Set(ref _scanInfo, value);
    }

    public string Countdown
    {
        get => _countdown;
        set => Set(ref _countdown, value);
    }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (Set(ref _searchText, value))
            {
                RulesView.Refresh();
            }
        }
    }

    public string Filter
    {
        get => _filter;
        set
        {
            if (Set(ref _filter, value))
            {
                RulesView.Refresh();
            }
        }
    }

    public bool AutoRepair
    {
        get => _settings.AutoRepair;
        set
        {
            if (_settings.AutoRepair == value)
            {
                return;
            }

            _settings.AutoRepair = value;
            _settings.Save();
            Raise();
            Raise(nameof(AutoRepairText));
        }
    }

    public string AutoRepairText => AutoRepair ? "自动还原" : "仅告警";

    public bool StartWithWindows
    {
        get => _settings.StartWithWindows;
        set
        {
            if (_settings.StartWithWindows == value)
            {
                return;
            }

            _settings.StartWithWindows = value;
            _settings.Save();
            Raise();
            AutostartService.SetEnabled(value);
        }
    }

    public int IntervalSeconds
    {
        get => _settings.ScanIntervalSeconds;
        set
        {
            if (_settings.ScanIntervalSeconds == value)
            {
                return;
            }

            _settings.ScanIntervalSeconds = value;
            _settings.Save();
            Raise();
            Raise(nameof(IntervalText));
            IntervalChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public string IntervalText => IntervalSeconds < 60 ? $"{IntervalSeconds} 秒" : $"{IntervalSeconds / 60} 分钟";

    public bool MonitorBrowsers
    {
        get => _settings.MonitorBrowserSettings;
        set
        {
            if (_settings.MonitorBrowserSettings == value)
            {
                return;
            }

            _settings.MonitorBrowserSettings = value;
            _settings.Save();
            Raise();
        }
    }

    public int HistoryLimit
    {
        get => _settings.HistoryLimit;
        set
        {
            if (_settings.HistoryLimit == value)
            {
                return;
            }

            _settings.HistoryLimit = value;
            _events.Limit = value;
            _settings.Save();
            Raise();
        }
    }

    public bool IsElevated => Keep.Core.Interop.Elevation.IsElevated();

    public event EventHandler? IntervalChanged;

    public event EventHandler<GuardianEvent>? Raised;

    public event EventHandler? Updated;

    public void Initialize()
    {
        AppPaths.EnsureCreated();
        _settings = KeepSettings.Load();
        _events = EventStore.Load(_settings.HistoryLimit);
        _baseline = ProtectionBaseline.Load();

        if (_baseline is null)
        {
            _baseline = BaselineBuilder.Capture();
            _baseline.Save();
            _settings.BaselineCapturedUtc = _baseline.CapturedUtc;
            _settings.Save();
        }

        _engine = new GuardianEngine(_baseline, _settings, _events);
        _restoredToday = _events.CountToday(GuardianAction.Restored);
        LoadRules();
        LoadHistory();
        LoadBrowsers();
        ScanInfo = _settings.LastScanUtc is { } last
            ? $"上次检测 {last.ToLocalTime():HH:mm:ss}"
            : "尚未检测";
        RaiseSummary();
    }

    public async Task<ScanReport?> ScanAsync(bool allowRepair)
    {
        if (_engine is null || !HasBaseline)
        {
            return null;
        }

        if (!await _scanGate.WaitAsync(0).ConfigureAwait(false))
        {
            return null;
        }

        try
        {
            Scanning = true;
            var started = DateTime.UtcNow;
            var report = await Task.Run(() => _engine.Scan(allowRepair)).ConfigureAwait(false);
            var elapsed = (DateTime.UtcNow - started).TotalMilliseconds;

            await RunOnUi(() =>
            {
                _lastReport = report;
                _restoredToday = _events.CountToday(GuardianAction.Restored);
                _blockedCount = report.Blocked;
                ApplyReport(report);
                LoadHistory();
                if (_settings.MonitorBrowserSettings)
                {
                    EvaluateBrowsers();
                }

                ScanInfo = $"上次检测 {report.TimestampUtc.ToLocalTime():HH:mm:ss} · 用时 {elapsed:F0} ms";
                RaiseSummary();
                Updated?.Invoke(this, EventArgs.Empty);

                foreach (var item in report.Items.Take(3))
                {
                    var latest = _events.Recent.FirstOrDefault(e => e.Target == item.Rule.Target);
                    if (latest is not null && latest.Action is GuardianAction.Restored or GuardianAction.Blocked)
                    {
                        Raised?.Invoke(this, latest);
                    }
                }
            }).ConfigureAwait(false);

            return report;
        }
        finally
        {
            Scanning = false;
            _scanGate.Release();
        }
    }

    public void CaptureBaseline()
    {
        _baseline = BaselineBuilder.Capture();
        _baseline.Save();
        _settings.BaselineCapturedUtc = _baseline.CapturedUtc;
        _settings.Save();
        _engine = new GuardianEngine(_baseline, _settings, _events);
        LoadRules();
        if (_settings.MonitorBrowserSettings)
        {
            CaptureBrowsers();
        }

        ScanInfo = "已把当前设置记录为基准";
        RaiseSummary();
        Updated?.Invoke(this, EventArgs.Empty);
    }

    public async Task<int> RepairProblemsAsync()
    {
        if (_engine is null)
        {
            return 0;
        }

        var targets = Rules.Where(r => r.HasProblem).Select(r => r.Rule).ToList();
        var repaired = await Task.Run(() => _engine.RepairAll(targets)).ConfigureAwait(false);
        await RunOnUi(() =>
        {
            RefreshRules();
            LoadHistory();
            _restoredToday = _events.CountToday(GuardianAction.Restored);
            RaiseSummary();
            Updated?.Invoke(this, EventArgs.Empty);
        }).ConfigureAwait(false);
        return repaired;
    }

    public async Task RepairRuleAsync(RuleRow row)
    {
        if (_engine is null)
        {
            return;
        }

        await Task.Run(() => _engine.Repair(row.Rule)).ConfigureAwait(false);
        await RunOnUi(() =>
        {
            row.Apply(_engine.Evaluate(row.Rule));
            LoadHistory();
            _restoredToday = _events.CountToday(GuardianAction.Restored);
            RaiseSummary();
        }).ConfigureAwait(false);
    }

    public void RefreshRules()
    {
        if (_engine is null)
        {
            return;
        }

        foreach (var row in Rules)
        {
            row.Apply(_engine.Evaluate(row.Rule));
        }

        RaiseSummary();
    }

    public void ClearHistory()
    {
        _events.Clear();
        LoadHistory();
        _restoredToday = 0;
        RaiseSummary();
    }

    public void CaptureBrowsers()
    {
        var baseline = new BrowserMonitor().Capture();
        baseline.Save();
        LoadBrowsers();
    }

    public void EvaluateBrowsers()
    {
        var baseline = BrowserBaseline.Load();
        if (baseline is null || baseline.Profiles.Count == 0)
        {
            LoadBrowsers();
            return;
        }

        var monitor = new BrowserMonitor();
        foreach (var row in Browsers)
        {
            var rule = baseline.Profiles.FirstOrDefault(p => p.PreferencesPath == row.Status.Rule.PreferencesPath);
            if (rule is not null)
            {
                row.Update(monitor.Evaluate(rule));
            }
        }

        Raise(nameof(BrowserProblemCount));
    }

    public string RepairBrowser(BrowserRow row)
    {
        var result = new BrowserMonitor().Repair(row.Status.Rule);
        EvaluateBrowsers();
        return result ?? "已写回浏览器设置";
    }

    public void SaveBaseline() => _baseline?.Save();

    public void RefreshUcpdState() => RaiseSummary();

    private void OpenDataFolder()
    {
        AppPaths.EnsureCreated();
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "explorer.exe",
            Arguments = AppPaths.Root,
            UseShellExecute = true,
        });
    }

    private void LoadRules()
    {
        Rules.Clear();
        if (_baseline is null)
        {
            return;
        }

        foreach (var rule in _baseline.Rules.OrderBy(r => r.Target))
        {
            Rules.Add(new RuleRow(rule));
        }

        if (_engine is not null)
        {
            foreach (var row in Rules)
            {
                row.Apply(_engine.Evaluate(row.Rule));
            }
        }

        RulesView.Refresh();
    }

    private void LoadHistory()
    {
        History.Clear();
        foreach (var item in _events.Recent.Take(200))
        {
            History.Add(new EventRow(item));
        }

        Raise(nameof(RecentHistory));
        Raise(nameof(HasHistory));
    }

    private void LoadBrowsers()
    {
        Browsers.Clear();
        var baseline = BrowserBaseline.Load();
        if (baseline is null || baseline.Profiles.Count == 0)
        {
            var monitor = new BrowserMonitor();
            foreach (var profile in monitor.Discover())
            {
                Browsers.Add(new BrowserRow(new BrowserStatus(profile, false, Array.Empty<BrowserProblem>())));
            }

            Raise(nameof(BrowserProblemCount));
            return;
        }

        var browserMonitor = new BrowserMonitor();
        foreach (var profile in baseline.Profiles)
        {
            Browsers.Add(new BrowserRow(browserMonitor.Evaluate(profile)));
        }

        Raise(nameof(BrowserProblemCount));
    }

    private void ApplyReport(ScanReport report)
    {
        var byTarget = report.Items.ToDictionary(i => i.Rule.Target, i => i, StringComparer.OrdinalIgnoreCase);
        foreach (var row in Rules)
        {
            if (byTarget.TryGetValue(row.Rule.Target, out var status))
            {
                row.Apply(status);
                continue;
            }

            row.State = RuleState.Ok;
            row.CurrentText = row.ProgId;
        }
    }

    private bool FilterRule(object item)
    {
        if (item is not RuleRow row)
        {
            return false;
        }

        if (Filter == "problem" && !row.HasProblem)
        {
            return false;
        }

        if (Filter == "browser" && !row.Rule.IsBrowserTarget)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(SearchText))
        {
            return true;
        }

        var needle = SearchText.Trim();
        return row.Target.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.AppName.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || row.ProgId.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private void RaiseSummary()
    {
        Raise(nameof(StatusTitle));
        Raise(nameof(StatusSubtitle));
        Raise(nameof(TotalRules));
        Raise(nameof(HealthyCount));
        Raise(nameof(ProblemCount));
        Raise(nameof(HasProblems));
        Raise(nameof(RestoredToday));
        Raise(nameof(BlockedCount));
        Raise(nameof(UcpdActive));
        Raise(nameof(DeepMode));
        Raise(nameof(UcpdText));
        Raise(nameof(HasBaseline));
        Raise(nameof(BrowserProblemCount));
        Raise(nameof(ShowUcpdBanner));
        Raise(nameof(AutoRepairText));
        Raise(nameof(IntervalText));
    }

    private static Task RunOnUi(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess())
        {
            action();
            return Task.CompletedTask;
        }

        return dispatcher.InvokeAsync(action).Task;
    }
}

