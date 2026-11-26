using System.Runtime.InteropServices;

namespace Keep.Core.Interop;

/// <summary>Service-control helpers used to detect the UCPD filter driver.</summary>
internal static class ServiceNative
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceStatusProcess = 0x0004;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenServiceW(IntPtr scManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatus(IntPtr service, out ServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    public static bool IsServiceRunning(string name)
    {
        var scm = IntPtr.Zero;
        var service = IntPtr.Zero;
        try
        {
            scm = OpenSCManagerW(null, null, ScManagerConnect);
            if (scm == IntPtr.Zero)
            {
                return false;
            }

            service = OpenServiceW(scm, name, ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                return false;
            }

            return QueryServiceStatus(service, out var status) && status.dwCurrentState == ServiceStatusProcess;
        }
        finally
        {
            if (service != IntPtr.Zero)
            {
                CloseServiceHandle(service);
            }

            if (scm != IntPtr.Zero)
            {
                CloseServiceHandle(scm);
            }
        }
    }
}

/// <summary>True when a process holds the interactive-user token elevation.</summary>
public static class Elevation
{
    public static bool IsElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
}

