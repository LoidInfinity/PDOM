using System.Security.Cryptography;
using System.Text;

namespace Keep.Core.Associations;

/// <summary>
/// Windows UserChoice hash (the "legacy" V1 scheme still used by Explorer on
/// Windows 10/11 to validate a per-user file/protocol association).
///
/// The algorithm is public knowledge and has several independent
/// re-implementations; this port follows the documented construction:
///   input = lower( target + userSid + progId + FILETIME(high,low, hex) + experience )
///   md5   = MD5(UTF-16LE(input + NUL))
///   out   = scramble(md5) -> 8 bytes -> base64
/// The registry value is only honoured by Explorer when this hash matches the
/// UserChoice key's own last-write timestamp, which is why <see cref="Compute"/>
/// takes the timestamp explicitly.
/// </summary>
public static class UserChoiceHash
{
    // Microsoft's static experience string. It is baked into Windows; there is
    // no way to derive it, and it has been stable since Windows 10 1703.
    private const string Experience =
        "user choice set via windows user experience {d18b6dd5-6124-4341-9318-804003bafa0b}";

    /// <summary>
    /// Computes the base64 UserChoice hash for an association.
    /// </summary>
    /// <param name="target">Extension (".html") or protocol ("http").</param>
    /// <param name="userSid">String SID of the user that owns the HKCU key.</param>
    /// <param name="progId">ProgId stored in the UserChoice key.</param>
    /// <param name="lastWriteUtc">Last-write time of the UserChoice key (UTC).</param>
    public static string Compute(string target, string userSid, string progId, DateTime lastWriteUtc)
    {
        var stamp = TruncateToMinute(lastWriteUtc);
        var fileTime = stamp.ToFileTimeUtc();
        var high = (uint)(fileTime >> 32);
        var low = (uint)fileTime;

        var input = string.Concat(
            target,
            userSid,
            progId,
            high.ToString("x8"),
            low.ToString("x8"),
            Experience).ToLowerInvariant();

        // Including the NUL terminator is part of the algorithm.
        var bytes = Encoding.Unicode.GetBytes(input + "\0");
        return ComputeFromBytes(bytes);
    }

    internal static string ComputeFromBytes(byte[] bytes)
    {
        const int dwordsPerBlock = 2;
        const int blockSize = sizeof(uint) * dwordsPerBlock;

        // Trailing bytes that do not fill a block are ignored.
        var blockCount = bytes.Length / blockSize;
        if (blockCount == 0)
        {
            throw new ArgumentException("Input is too short for the UserChoice hash.", nameof(bytes));
        }

        var md5 = MD5.HashData(bytes);
        var m0 = BitConverter.ToUInt32(md5, 0) | 1u;
        var m1 = BitConverter.ToUInt32(md5, 4) | 1u;

        uint[] C0(int j) => j == 0
            ? [m0, 0xCF98B111u, 0x87085B9Fu, 0x12CEB96Du, 0x257E1D83u]
            : [m1, 0xA27416F5u, 0xD38396FFu, 0x7C932B89u, 0xBFA49F69u];

        uint[] C1(int j) => j == 0
            ? [m0, 0xEF0569FBu, 0x689B6B9Fu, 0x79F8A395u, 0xC3EFEA97u]
            : [m1, 0xC31713DBu, 0xDDCD1F0Fu, 0x59C3AF2Du, 0x35BD1EC9u];

        unchecked
        {
            uint h0 = 0, h1 = 0, h0Acc = 0, h1Acc = 0;

            for (var i = 0; i < blockCount; i++)
            {
                for (var j = 0; j < dwordsPerBlock; j++)
                {
                    var c0 = C0(j);
                    var c1 = C1(j);
                    var input = BitConverter.ToUInt32(bytes, (i * dwordsPerBlock + j) * sizeof(uint));

                    h0 += input;
                    h0 *= c0[0];
                    h0 = WordSwap(h0) * c0[1];
                    h0 = WordSwap(h0) * c0[2];
                    h0 = WordSwap(h0) * c0[3];
                    h0 = WordSwap(h0) * c0[4];
                    h0Acc += h0;

                    h1 += input;
                    h1 = WordSwap(h1) * c1[1] + h1 * c1[0];
                    h1 = (h1 >> 16) * c1[2] + h1 * c1[3];
                    h1 = WordSwap(h1) * c1[4] + h1;
                    h1Acc += h1;
                }
            }

            var result = new byte[8];
            BitConverter.TryWriteBytes(result.AsSpan(0, 4), h0 ^ h1);
            BitConverter.TryWriteBytes(result.AsSpan(4, 4), h0Acc ^ h1Acc);
            return Convert.ToBase64String(result);
        }
    }

    /// <summary>
    /// True when <paramref name="storedHash"/> is exactly what Explorer expects
    /// for the given association and key timestamp.
    /// </summary>
    public static bool IsValid(string storedHash, string target, string userSid, string progId, DateTime lastWriteUtc)
    {
        if (string.IsNullOrEmpty(storedHash))
        {
            return false;
        }

        try
        {
            return string.Equals(storedHash, Compute(target, userSid, progId, lastWriteUtc), StringComparison.Ordinal);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>The timestamp resolution used by the hash is one minute.</summary>
    public static DateTime TruncateToMinute(DateTime value)
    {
        var utc = value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();
        return utc.AddTicks(-(utc.Ticks % TimeSpan.TicksPerMinute));
    }

    private static uint WordSwap(uint v) => (v >> 16) | (v << 16);
}
