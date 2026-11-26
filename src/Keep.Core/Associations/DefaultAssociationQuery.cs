using System.Runtime.InteropServices;

namespace Keep.Core.Associations;

/// <summary>
/// Asks the shell which ProgId is the effective default for a target
/// (IApplicationAssociationRegistration::QueryCurrentDefault). This is the same
/// data Explorer uses, unlike AssocQueryString which may fall back to
/// perceived-type handlers.
/// </summary>
public static class DefaultAssociationQuery
{
    private static readonly Guid ClsidApplicationAssociationRegistration = new("591209c7-767b-42b2-9fba-44ee4615f2c7");

    private enum AssociationType
    {
        FileExtension = 0,
        UrlProtocol = 1,
        StartMenuClient = 2,
        MimeType = 3,
    }

    private enum AssociationLevel
    {
        None = 0,
        User = 1,
        Effective = 2,
        Machine = 3,
    }

    [ComImport]
    [Guid("4e530b0a-e611-4c77-a3ac-9031d022281b")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IApplicationAssociationRegistration
    {
        [PreserveSig]
        int QueryCurrentDefault(
            [MarshalAs(UnmanagedType.LPWStr)] string query,
            AssociationType queryType,
            AssociationLevel queryLevel,
            [MarshalAs(UnmanagedType.LPWStr)] out string? association);

        [PreserveSig]
        int QueryAppIsDefault(
            [MarshalAs(UnmanagedType.LPWStr)] string query,
            AssociationType queryType,
            AssociationLevel queryLevel,
            [MarshalAs(UnmanagedType.LPWStr)] string appRegistryName,
            out bool isDefault);

        [PreserveSig]
        int QueryAppIsDefaultAll(AssociationLevel queryLevel, [MarshalAs(UnmanagedType.LPWStr)] string appRegistryName, out bool isDefault);

        [PreserveSig]
        int SetAppAsDefault([MarshalAs(UnmanagedType.LPWStr)] string appRegistryName, [MarshalAs(UnmanagedType.LPWStr)] string set, AssociationType setType);

        [PreserveSig]
        int SetAppAsDefaultAll([MarshalAs(UnmanagedType.LPWStr)] string appRegistryName);

        [PreserveSig]
        int ClearUserAssociations();
    }

    /// <summary>Returns the effective default ProgId, or null when the shell reports none.</summary>
    public static string? GetDefaultProgId(string target)
    {
        try
        {
            var type = Type.GetTypeFromCLSID(ClsidApplicationAssociationRegistration);
            if (type is null)
            {
                return null;
            }

            var registration = (IApplicationAssociationRegistration)Activator.CreateInstance(type)!;
            var associationType = target.StartsWith('.') ? AssociationType.FileExtension : AssociationType.UrlProtocol;
            var hr = registration.QueryCurrentDefault(target, associationType, AssociationLevel.Effective, out var association);
            return hr == 0 && !string.IsNullOrWhiteSpace(association) ? association : null;
        }
        catch (COMException)
        {
            return null;
        }
        catch (InvalidCastException)
        {
            return null;
        }
    }
}
