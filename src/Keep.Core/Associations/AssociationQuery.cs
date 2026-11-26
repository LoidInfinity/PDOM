using System.Text;

namespace Keep.Core.Associations;

/// <summary>Resolves what a target actually opens through the shell association APIs.</summary>
public static class AssociationQuery
{
    private const int AssocStrCommand = 1;
    private const int AssocStrExecutable = 2;
    private const int AssocStrFriendlyAppName = 4;
    private const int AssocStrProgId = 20;
    private const int AssocFNone = 0;
    private const int AssocFNotruncate = 0x20;

    [System.Runtime.InteropServices.DllImport("shlwapi.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern int AssocQueryStringW(
        int flags, int str, string assoc, string? extra,
        StringBuilder? outBuffer, ref int outBufferSize);

    public static string? GetExecutable(string target) => Query(target, AssocStrExecutable);

    public static string? GetCommand(string target) => Query(target, AssocStrCommand);

    public static string? GetFriendlyAppName(string target) => Query(target, AssocStrFriendlyAppName);

    public static string? GetProgId(string target) => Query(target, AssocStrProgId);

    /// <summary>Extracts the executable path from a shell command line.</summary>
    public static string? ExecutableFromCommand(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return null;
        }

        command = command.Trim();
        if (command.StartsWith('"'))
        {
            var end = command.IndexOf('"', 1);
            return end > 1 ? command[1..end] : null;
        }

        var space = command.IndexOf(' ');
        return space < 0 ? command : command[..space];
    }

    private static string? Query(string target, int str)
    {
        var size = 1024;
        var buffer = new StringBuilder(size);
        var hr = AssocQueryStringW(AssocFNone | AssocFNotruncate, str, target, null, buffer, ref size);
        if (hr != 0)
        {
            buffer = new StringBuilder(Math.Max(size, 1024));
            size = buffer.Capacity;
            hr = AssocQueryStringW(AssocFNone, str, target, null, buffer, ref size);
            if (hr != 0)
            {
                return null;
            }
        }

        var value = buffer.ToString();
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}
