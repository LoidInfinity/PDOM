using System.Security.Principal;
using Keep.Core.Interop;

namespace Keep.Core.Associations;

/// <summary>Kind of Windows association target.</summary>
public enum AssociationKind
{
    /// <summary>A file extension such as ".txt" (FileExts key).</summary>
    FileExtension,

    /// <summary>A URL protocol such as "http" (UrlAssociations key).</summary>
    Protocol,
}

/// <summary>A snapshot of one HKCU UserChoice key.</summary>
public sealed record UserChoiceSnapshot(
    string Target,
    AssociationKind Kind,
    bool Exists,
    string? ProgId,
    string? Hash,
    DateTime? LastWriteUtc)
{
    public static UserChoiceSnapshot Missing(string target, AssociationKind kind) =>
        new(target, kind, false, null, null, null);
}

/// <summary>
/// Reads, validates and rewrites per-user association keys
/// (<c>HKCU\...\FileExts\&lt;ext&gt;\UserChoice</c> and
/// <c>HKCU\...\UrlAssociations\&lt;proto&gt;\UserChoice</c>).
/// </summary>
public sealed class UserChoiceStore
{
    private const string FileExtsRoot = @"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts";
    private const string UrlAssocRoot = @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations";

    private readonly Lazy<string> _userSid = new(() =>
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value ?? throw new InvalidOperationException("Cannot resolve the current user SID.");
    });

    /// <summary>String SID of the current user.</summary>
    public string UserSid => _userSid.Value;

    public static AssociationKind KindOf(string target) =>
        target.StartsWith('.') ? AssociationKind.FileExtension : AssociationKind.Protocol;

    public static string KeyPath(string target) =>
        (KindOf(target) == AssociationKind.FileExtension ? FileExtsRoot : UrlAssocRoot) + "\\" + target;

    public UserChoiceSnapshot Read(string target)
    {
        var kind = KindOf(target);
        var path = KeyPath(target);

        if (RegistryNative.Open(RegistryNative.HkeyCurrentUser, path + "\\UserChoice", RegistryNative.KeyRead, out var key) != 0)
        {
            return UserChoiceSnapshot.Missing(target, kind);
        }

        using (key)
        {
            var lastWrite = RegistryNative.GetLastWriteTimeUtc(key);
            var progId = RegistryNative.GetString(key, "ProgId");
            var hash = RegistryNative.GetString(key, "Hash");
            return new UserChoiceSnapshot(target, kind, true, progId, hash, lastWrite);
        }
    }

    /// <summary>
    /// True when the stored hash matches the key timestamp and ProgId, i.e.
    /// Explorer will actually honour this association. A key that exists but
    /// fails this check behaves like "no default app" in the shell.
    /// </summary>
    public bool IsHashValid(UserChoiceSnapshot snapshot)
    {
        if (!snapshot.Exists || string.IsNullOrEmpty(snapshot.ProgId) || snapshot.LastWriteUtc is null)
        {
            return false;
        }

        return UserChoiceHash.IsValid(snapshot.Hash ?? string.Empty, snapshot.Target, UserSid, snapshot.ProgId, snapshot.LastWriteUtc.Value);
    }

    /// <summary>
    /// Writes <paramref name="progId"/> and a freshly computed hash for the
    /// current timestamp. Returns null on success, or a human-readable reason.
    /// </summary>
    public string? Write(string target, string progId)
    {
        var path = KeyPath(target) + "\\UserChoice";
        var rc = RegistryNative.Create(
            RegistryNative.HkeyCurrentUser,
            path,
            RegistryNative.KeyAllAccess,
            out var key,
            out _);

        if (rc != 0)
        {
            return Describe(rc);
        }

        using (key)
        {
            // The hash covers the key's last-write time, which is set by these
            // writes, so compute an expected stamp, write, then confirm. A write
            // that straddles a minute boundary is retried once with the new
            // stamp.
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var stamp = UserChoiceHash.TruncateToMinute(DateTime.UtcNow);
                var hash = UserChoiceHash.Compute(target, UserSid, progId, stamp);
                if (hash.Length == 0)
                {
                    return "Hash computation failed.";
                }

                var setProgId = RegistryNative.SetString(key, "ProgId", progId);
                if (setProgId != 0)
                {
                    return Describe(setProgId);
                }

                var setHash = RegistryNative.SetString(key, "Hash", hash);
                if (setHash != 0)
                {
                    return Describe(setHash);
                }

                var lastWrite = RegistryNative.GetLastWriteTimeUtc(key);
                if (lastWrite is null)
                {
                    return "Written, but the key timestamp could not be verified.";
                }

                if (UserChoiceHash.TruncateToMinute(lastWrite.Value) == stamp)
                {
                    return null;
                }
            }

            return "Written, but the timestamp crossed a minute boundary twice; retry the scan.";
        }
    }

    public string? Delete(string target)
    {
        var path = KeyPath(target) + "\\UserChoice";
        var rc = RegistryNative.Delete(RegistryNative.HkeyCurrentUser, path);
        return rc == 0 || rc == RegistryNative.ErrorFileNotFound ? null : Describe(rc);
    }

    public const string AccessDeniedMessage = "写入被系统拒绝（可能受 UCPD 保护）";

    public static string Describe(int win32Error) => win32Error switch
    {
        RegistryNative.ErrorAccessDenied => AccessDeniedMessage,
        RegistryNative.ErrorFileNotFound => "注册表项不存在。",
        _ => $"注册表错误 {win32Error}。",
    };
}

