using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Keep.Core.Interop;

/// <summary>
/// Thin, dependency-free wrapper over the few advapi32 registry calls that
/// System.Registry does not expose (notably the key last-write timestamp,
/// which is part of the UserChoice hash input).
/// </summary>
internal static class RegistryNative
{
    public const int HkeyCurrentUser = unchecked((int)0x80000001);

    public const int KeyQueryValue = 0x0001;
    public const int KeySetValue = 0x0002;
    public const int KeyCreateSubKey = 0x0004;
    public const int KeyEnumerateSubKeys = 0x0008;
    public const int KeyRead = 0x20019;
    public const int KeyWrite = 0x20006;
    public const int KeyAllAccess = 0xF003F;

    public const int RegSz = 1;
    public const int RegOptionNonVolatile = 0;

    public const int ErrorSuccess = 0;
    public const int ErrorFileNotFound = 2;
    public const int ErrorAccessDenied = 5;

    [DllImport("advapi32.dll", EntryPoint = "RegOpenKeyExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegOpenKeyExW(IntPtr hKey, string lpSubKey, int ulOptions, int samDesired, out SafeRegKey phkResult);

    [DllImport("advapi32.dll", EntryPoint = "RegCreateKeyExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegCreateKeyExW(
        IntPtr hKey, string lpSubKey, int reserved, string? lpClass, int dwOptions,
        int samDesired, IntPtr lpSecurityAttributes, out SafeRegKey phkResult, out int lpdwDisposition);

    [DllImport("advapi32.dll", EntryPoint = "RegQueryInfoKeyW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegQueryInfoKeyW(
        SafeRegKey hKey, IntPtr lpClass, IntPtr lpcchClass, IntPtr lpReserved,
        out int lpcSubKeys, out int lpcbMaxSubKeyLen, out int lpcbMaxClassLen,
        out int lpcValues, out int lpcbMaxValueNameLen, out int lpcbMaxValueLen,
        out int lpcbSecurityDescriptor, out long lpftLastWriteTime);

    [DllImport("advapi32.dll", EntryPoint = "RegQueryValueExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegQueryValueExW(
        SafeRegKey hKey, string lpValueName, IntPtr lpReserved, out int lpType,
        byte[]? lpData, ref int lpcbData);

    [DllImport("advapi32.dll", EntryPoint = "RegSetValueExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegSetValueExW(
        SafeRegKey hKey, string lpValueName, int reserved, int dwType,
        byte[] lpData, int cbData);

    [DllImport("advapi32.dll", EntryPoint = "RegDeleteKeyW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegDeleteKeyW(IntPtr hKey, string lpSubKey);

    [DllImport("advapi32.dll", EntryPoint = "RegDeleteTreeW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegDeleteTreeW(IntPtr hKey, string lpSubKey);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int RegCloseKey(IntPtr hKey);

    internal static int CloseKey(IntPtr hKey) => RegCloseKey(hKey);

    [DllImport("advapi32.dll", EntryPoint = "RegNotifyChangeKeyValue", SetLastError = true)]
    private static extern int RegNotifyChangeKeyValue(
        SafeRegKey hKey, bool bWatchSubtree, int dwNotifyFilter, IntPtr hEvent, bool fAsynchronous);

    public static int Open(int root, string subKey, int access, out SafeRegKey key) =>
        RegOpenKeyExW((IntPtr)root, subKey, 0, access, out key);

    public static int Create(int root, string subKey, int access, out SafeRegKey key, out int disposition) =>
        RegCreateKeyExW((IntPtr)root, subKey, 0, null, RegOptionNonVolatile, access, IntPtr.Zero, out key, out disposition);

    public static int Delete(int root, string subKey) => RegDeleteKeyW((IntPtr)root, subKey);

    public static int DeleteTree(int root, string subKey) => RegDeleteTreeW((IntPtr)root, subKey);

    /// <summary>Returns the key's last write time as UTC <see cref="DateTime"/>, or null when unavailable.</summary>
    public static DateTime? GetLastWriteTimeUtc(SafeRegKey key)
    {
        var rc = RegQueryInfoKeyW(
            key, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
            out _, out _, out _, out _, out _, out _, out _, out var fileTime);
        if (rc != ErrorSuccess || fileTime == 0)
        {
            return null;
        }
        try
        {
            return DateTime.FromFileTimeUtc(fileTime);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    public static string? GetString(SafeRegKey key, string valueName)
    {
        var size = 0;
        var rc = RegQueryValueExW(key, valueName, IntPtr.Zero, out var type, null, ref size);
        if (rc != ErrorSuccess || size <= 0 || type != RegSz)
        {
            return null;
        }

        var buffer = new byte[size];
        rc = RegQueryValueExW(key, valueName, IntPtr.Zero, out type, buffer, ref size);
        if (rc != ErrorSuccess || type != RegSz)
        {
            return null;
        }

        var text = System.Text.Encoding.Unicode.GetString(buffer, 0, size);
        var terminator = text.IndexOf('\0');
        return terminator >= 0 ? text[..terminator] : text;
    }

    public static int SetString(SafeRegKey key, string valueName, string value)
    {
        var bytes = System.Text.Encoding.Unicode.GetBytes(value + "\0");
        return RegSetValueExW(key, valueName, 0, RegSz, bytes, bytes.Length);
    }

    /// <summary>Registers a change notification on an already-open key, synchronously.</summary>
    public static int NotifyChange(SafeRegKey key, bool watchSubtree)
    {
        const int regNotifyChangeName = 0x1;
        const int regNotifyChangeLastSet = 0x4;
        return RegNotifyChangeKeyValue(key, watchSubtree, regNotifyChangeName | regNotifyChangeLastSet, IntPtr.Zero, false);
    }
}

internal sealed class SafeRegKey : SafeHandleZeroOrMinusOneIsInvalid
{
    private SafeRegKey() : base(true)
    {
    }

    protected override bool ReleaseHandle() => RegistryNative.CloseKey(handle) == 0;
}
