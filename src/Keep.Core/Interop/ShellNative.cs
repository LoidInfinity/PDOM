namespace Keep.Core.Interop;

/// <summary>Notifies the shell that associations changed so caches are refreshed.</summary>
internal static class ShellNative
{
    private const int ShcneAssocChanged = 0x08000000;
    private const uint ShcnfIdList = 0x0000;
    private const uint ShcnfFlush = 0x1000;

    [System.Runtime.InteropServices.DllImport("shell32.dll")]
    private static extern void SHChangeNotify(int eventId, uint flags, IntPtr item1, IntPtr item2);

    public static void NotifyAssociationsChanged()
    {
        try
        {
            SHChangeNotify(ShcneAssocChanged, ShcnfIdList | ShcnfFlush, IntPtr.Zero, IntPtr.Zero);
        }
        catch
        {
            // Best effort: the shell will pick the change up on its own eventually.
        }
    }
}
