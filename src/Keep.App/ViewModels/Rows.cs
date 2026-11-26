using Keep.Core.Browser;
using Keep.Core.Engine;
using Keep.Core.Model;

namespace Keep.App.ViewModels;

/// <summary>One row in the rules table.</summary>
public sealed class RuleRow : ObservableObject
{
    private RuleState _state = RuleState.Ok;
    private string _currentText = string.Empty;

    public RuleRow(ProtectionRule rule)
    {
        Rule = rule;
    }

    public ProtectionRule Rule { get; }

    public string Target => Rule.Target;

    public string KindText => Rule.IsProtocol ? "协议" : "文件";

    public string AppName => Rule.AppName;

    public string ProgId => Rule.ProgId;

    public string GroupText => Rule.IsBrowserTarget ? "浏览器" : Rule.IsProtocol ? "协议" : "文件关联";

    public int GroupRank => Rule.IsBrowserTarget ? 0 : Rule.IsProtocol ? 2 : 1;

    public bool Enabled
    {
        get => Rule.Enabled;
        set
        {
            if (Rule.Enabled == value)
            {
                return;
            }

            Rule.Enabled = value;
            Raise();
            Raise(nameof(EnabledText));
        }
    }

    public string EnabledText => Enabled ? "守护中" : "已暂停";

    public RuleState State
    {
        get => _state;
        set
        {
            if (Set(ref _state, value))
            {
                Raise(nameof(StatusText));
                Raise(nameof(StatusBrush));
                Raise(nameof(IsHealthy));
                Raise(nameof(HasProblem));
                Raise(nameof(IsBlocked));
            }
        }
    }

    public string CurrentText
    {
        get => _currentText;
        set => Set(ref _currentText, value);
    }

    public string StatusText => State switch
    {
        RuleState.Ok => "正常",
        RuleState.Tampered => "已被篡改",
        RuleState.NoDefault => "未设置默认",
        RuleState.BlockedBySystem => "受系统保护",
        RuleState.AppMissing => "程序缺失",
        _ => "未知",
    };

    public string StatusBrush => State switch
    {
        RuleState.Ok => "#3DDC97",
        RuleState.Tampered => "#FF6B6B",
        RuleState.NoDefault => "#F5A524",
        RuleState.BlockedBySystem => "#5B8CFF",
        RuleState.AppMissing => "#5C6B7E",
        _ => "#8B98A9",
    };

    public bool IsHealthy => State == RuleState.Ok;

    public bool HasProblem => State is RuleState.Tampered or RuleState.NoDefault or RuleState.BlockedBySystem;

    public bool IsBlocked => State == RuleState.BlockedBySystem;

    public string DetailText => string.IsNullOrWhiteSpace(CurrentText) ? "无默认程序" : CurrentText;

    public void Apply(RuleStatus status)
    {
        State = status.State;
        CurrentText = status.CurrentProgId;
        Raise(nameof(DetailText));
    }
}

/// <summary>One row in the history list.</summary>
public sealed class EventRow : ObservableObject
{
    public EventRow(GuardianEvent source)
    {
        Source = source;
    }

    public GuardianEvent Source { get; }

    public string TimeText
    {
        get
        {
            var local = Source.TimestampUtc.ToLocalTime();
            return local.Date == DateTime.Today
                ? local.ToString("HH:mm:ss")
                : local.ToString("MM-dd HH:mm");
        }
    }

    public string TargetText => Source.Target;

    public string AppName => Source.AppName;

    public string ActionText => Source.Action switch
    {
        GuardianAction.Restored => "已还原",
        GuardianAction.Blocked => "被拦截",
        GuardianAction.Failed => "还原失败",
        GuardianAction.Detected => "发现篡改",
        _ => "记录",
    };

    public string ActionBrush => Source.Action switch
    {
        GuardianAction.Restored => "#3DDC97",
        GuardianAction.Blocked => "#5B8CFF",
        GuardianAction.Failed => "#FF6B6B",
        GuardianAction.Detected => "#F5A524",
        _ => "#8B98A9",
    };

    public string ChangeText => string.IsNullOrEmpty(Source.From) && string.IsNullOrEmpty(Source.To)
        ? string.Empty
        : $"{Short(Source.From)} → {Short(Source.To)}";

    public string? Message => Source.Message;

    public bool HasMessage => !string.IsNullOrWhiteSpace(Source.Message);

    private static string Short(string value) =>
        string.IsNullOrWhiteSpace(value) ? "（无）" : value;
}

/// <summary>One browser profile row.</summary>
public sealed class BrowserRow : ObservableObject
{
    public BrowserRow(BrowserStatus status)
    {
        Status = status;
    }

    public BrowserStatus Status { get; private set; }

    public string DisplayName => Status.Rule.DisplayName;

    public bool IsOk => Status.Ok;

    public string StatusText => Status.Ok ? "正常" : "已变更";

    public string StatusBrush => Status.Ok ? "#3DDC97" : "#F5A524";

    public string DetailText => Status.Ok
        ? $"主页 {Show(Status.Rule.Homepage)} · 搜索 {Show(Status.Rule.SearchProvider)}"
        : string.Join("；", Status.Problems.Select(p => p.Detail));

    public string Homepage => string.IsNullOrWhiteSpace(Status.Rule.Homepage) ? "（空白页）" : Status.Rule.Homepage!;

    public string SearchProvider => string.IsNullOrWhiteSpace(Status.Rule.SearchProvider) ? "（未设置）" : Status.Rule.SearchProvider!;

    public void Update(BrowserStatus status)
    {
        Status = status;
        Raise(nameof(IsOk));
        Raise(nameof(StatusText));
        Raise(nameof(StatusBrush));
        Raise(nameof(DetailText));
    }

    private static string Show(string? value) => string.IsNullOrWhiteSpace(value) ? "空白页" : value!;
}
