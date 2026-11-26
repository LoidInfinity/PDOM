using Keep.Core.Interop;

namespace Keep.Core.Associations;

/// <summary>Snapshot of a <c>UserChoiceLatest</c> pair.</summary>
public sealed record UserChoiceLatestSnapshot(
    string Target,
    bool Exists,
    string? ProgId,
    string? Hash,
    DateTime? ProgIdLastWriteUtc);

/// <summary>
/// Reads and writes the second-generation association data that Windows 11
/// 24H2+ actually honours (<c>UserChoiceLatest\Hash</c> plus
/// <c>UserChoiceLatest\ProgId</c>).
/// </summary>
public sealed class UserChoiceLatestStore
{
    private const string MachineIdKey = @"SOFTWARE\Microsoft\SQMClient";

    private readonly UserChoiceStore _legacy = new();
    private readonly Lazy<string> _machineId = new(() =>
    {
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(MachineIdKey);
        return key?.GetValue("MachineID") as string ?? string.Empty;
    });

    public string UserSid => _legacy.UserSid;

    public string MachineId => _machineId.Value;

    public UserChoiceLatestSnapshot Read(string target)
    {
        var path = UserChoiceStore.KeyPath(target) + "\\UserChoiceLatest";
        var progIdPath = path + "\\ProgId";

        if (RegistryNative.Open(RegistryNative.HkeyCurrentUser, path, RegistryNative.KeyRead, out var key) != 0)
        {
            return new UserChoiceLatestSnapshot(target, false, null, null, null);
        }

        using (key)
        {
            var hash = RegistryNative.GetString(key, "Hash");

            if (RegistryNative.Open(RegistryNative.HkeyCurrentUser, progIdPath, RegistryNative.KeyRead, out var progIdKey) != 0)
            {
                return new UserChoiceLatestSnapshot(target, true, null, hash, null);
            }

            using (progIdKey)
            {
                var progId = RegistryNative.GetString(progIdKey, "ProgId");
                var lastWrite = RegistryNative.GetLastWriteTimeUtc(progIdKey);
                return new UserChoiceLatestSnapshot(target, true, progId, hash, lastWrite);
            }
        }
    }

    public bool IsHashValid(UserChoiceLatestSnapshot snapshot)
    {
        if (!snapshot.Exists || string.IsNullOrEmpty(snapshot.ProgId) || snapshot.ProgIdLastWriteUtc is null)
        {
            return false;
        }

        return UserChoiceLatestHash.IsValid(
            snapshot.Hash,
            snapshot.Target,
            snapshot.ProgId,
            MachineId,
            UserSid,
            snapshot.ProgIdLastWriteUtc.Value);
    }

    /// <summary>
    /// Writes the Latest pair. The hash covers the ProgId subkey's last-write
    /// time, so the value is written first and the timestamp read back before
    /// hashing. Returns null on success.
    /// </summary>
    public string? Write(string target, string progId)
    {
        var path = UserChoiceStore.KeyPath(target) + "\\UserChoiceLatest";
        var progIdPath = path + "\\ProgId";

        var rc = RegistryNative.Create(RegistryNative.HkeyCurrentUser, progIdPath, RegistryNative.KeyAllAccess, out var progIdKey, out _);
        if (rc != 0)
        {
            return UserChoiceStore.Describe(rc);
        }

        using (progIdKey)
        {
            var set = RegistryNative.SetString(progIdKey, "ProgId", progId);
            if (set != 0)
            {
                return UserChoiceStore.Describe(set);
            }
        }

        var lastWrite = RegistryNative.Open(RegistryNative.HkeyCurrentUser, progIdPath, RegistryNative.KeyRead, out var readKey) == 0
            ? ReadLastWrite(readKey)
            : null;

        if (lastWrite is null)
        {
            return "Could not read the ProgId key timestamp.";
        }

        var canonical = UserChoiceLatestHash.BuildCanonical(target, progId, MachineId, UserSid, lastWrite.Value);
        var hash = UserChoiceLatestHash.Compute(canonical);

        rc = RegistryNative.Create(RegistryNative.HkeyCurrentUser, path, RegistryNative.KeyAllAccess, out var key, out _);
        if (rc != 0)
        {
            return UserChoiceStore.Describe(rc);
        }

        using (key)
        {
            var set = RegistryNative.SetString(key, "Hash", hash);
            if (set != 0)
            {
                return UserChoiceStore.Describe(set);
            }
        }

        return null;
    }

    private static DateTime? ReadLastWrite(SafeRegKey key)
    {
        using (key)
        {
            return RegistryNative.GetLastWriteTimeUtc(key);
        }
    }
}

/// <summary>
/// High level association writer: keeps the legacy and Latest data in sync and
/// confirms that the shell actually resolves the requested ProgId.
/// </summary>
public sealed class AssociationWriter
{
    private readonly UserChoiceStore _legacy = new();
    private readonly UserChoiceLatestStore _latest = new();

    public sealed record Result(
        bool Ok,
        bool Effective,
        string? LegacyError,
        string? LatestError,
        string? ResolvedProgId);

    public Result Write(string target, string progId)
    {
        // The Latest pair is what Explorer validates on Windows 11 24H2+, so
        // it goes first. The legacy pair is kept in sync for older code paths
        // and for our own tamper detection, but a UCPD block there must not
        // stop the restore.
        var latestError = _latest.Write(target, progId);
        var legacyError = _legacy.Write(target, progId);
        Interop.ShellNative.NotifyAssociationsChanged();

        var resolved = DefaultAssociationQuery.GetDefaultProgId(target);
        var effective = string.Equals(resolved, progId, StringComparison.OrdinalIgnoreCase);

        return new Result(legacyError is null && latestError is null, effective, legacyError, latestError, resolved);
    }
}

