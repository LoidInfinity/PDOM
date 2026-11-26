using System.Diagnostics;

namespace Keep.Core.Associations;

/// <summary>Resolves display information for a ProgId without touching UserChoice.</summary>
public static class ProgIdResolver
{
    public static string? GetCommand(string progId)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey(progId + @"\shell\open\command");
            return key?.GetValue(null) as string;
        }
        catch (System.Security.SecurityException)
        {
            return null;
        }
    }

    public static string? GetExecutable(string progId)
    {
        var command = GetCommand(progId);
        var exe = AssociationQuery.ExecutableFromCommand(command);
        if (string.IsNullOrWhiteSpace(exe))
        {
            return null;
        }

        exe = Environment.ExpandEnvironmentVariables(exe.Trim('"'));
        return File.Exists(exe) ? exe : null;
    }

    public static string GetAppName(string progId)
    {
        var exe = GetExecutable(progId);
        if (!string.IsNullOrWhiteSpace(exe))
        {
            try
            {
                var info = FileVersionInfo.GetVersionInfo(exe);
                if (!string.IsNullOrWhiteSpace(info.FileDescription))
                {
                    return info.FileDescription!;
                }
            }
            catch (FileNotFoundException)
            {
                // Fall through to a name derived from the path.
            }

            return Path.GetFileNameWithoutExtension(exe);
        }

        try
        {
            using var key = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey(progId);
            var name = key?.GetValue(null) as string;
            if (!string.IsNullOrWhiteSpace(name))
            {
                return name!;
            }
        }
        catch (System.Security.SecurityException)
        {
            // Ignore and fall back to the ProgId.
        }

        return progId;
    }
}
