using System.Security.Cryptography;
using System.Text;

namespace Keep.Core.Associations;

/// <summary>
/// Windows 11 24H2+ "UserChoiceLatest" association hash, stored next to the
/// legacy <c>UserChoice</c> key as
/// <c>UserChoiceLatest\Hash</c> (with the chosen app in
/// <c>UserChoiceLatest\ProgId</c>).
///
/// Newer Windows builds validate this value instead of the legacy hash, so a
/// legacy-only write is silently ignored by the shell. The construction is
/// documented by independent reverse engineering (cssxn/UserChoiceLatestHash,
/// MIT); this is a managed port of that reference implementation, and it
/// reproduces hashes produced by Explorer on the target machine.
/// </summary>
public static class UserChoiceLatestHash
{
    private const ulong RepeatSentinel = 0xFBFFFFFFFFFFFFFF;
    private const ulong RepeatTokenA = 0xFE00000000000000;
    private const ulong RepeatTokenB = 0xFE00800000000000;
    private const ulong RepeatTokenC = 0xFF00000000000000;
    private const ulong RepeatTokenD = 0xFE007DFFFFFFFFFF;
    private const ulong RepeatTokenE = 0xFE00801F7FFFFFFF;
    private const uint SeenModulo = 0x2803;

    private const string Salt3822 = "Copyright (C) Microsoft. All rights reserved {3822B7CA-C2F4-4889-B8CC-4CE39A8FB81C}";
    private const string Salt97B6 = "Copyright (C) Microsoft. All rights reserved {97B6BCF4-C367-4577-95BE-73BD3053A5E0}";
    private const string SaltD185 = "Copyright (C) Microsoft. All rights reserved {D185E0A1-E265-4724-AA21-3A17B038D72E}";

    private static readonly uint[] SeedA = { 0x69FB0000, 0x79F8A395, 0x3CE8EC25, 0x10FA9605 };
    private static readonly uint[] SeedB = { 0x12CEB96D, 0x2B890000, 0x5B9F0000, 0x2C7C6901 };

    private static readonly Lazy<byte[]> ByteClass = new(() => UserChoiceLatestTables.Decode(UserChoiceLatestTables.ByteClassHex));
    private static readonly Lazy<byte[]> TokenRegion = new(() => UserChoiceLatestTables.Decode(UserChoiceLatestTables.TokenRegionHex));
    private static readonly Lazy<byte[]> BitWidth = new(() => UserChoiceLatestTables.Decode(UserChoiceLatestTables.TokenBitWidthHex));
    private static readonly Lazy<byte[]> ShortRewind = new(() => UserChoiceLatestTables.Decode(UserChoiceLatestTables.ShortRewindHex));
    private static readonly Lazy<byte[]> LongRewind = new(() => UserChoiceLatestTables.Decode(UserChoiceLatestTables.LongRewindHex));
    private static readonly Lazy<byte[]> FallbackTokenCode = new(() => UserChoiceLatestTables.Decode(UserChoiceLatestTables.FallbackTokenCodeHex));

    /// <summary>Builds the canonical input string for a live association.</summary>
    public static string BuildCanonical(string target, string progId, string machineId, string userSid, DateTime lastWriteUtc)
    {
        var trimmed = machineId.StartsWith('{') && machineId.EndsWith('}')
            ? machineId[1..^1]
            : machineId;

        if (trimmed.Length == 0)
        {
            throw new ArgumentException("Machine ID is empty.", nameof(machineId));
        }

        var modClass = trimmed[^1] % 3;
        var salt = modClass switch
        {
            0 => Salt3822,
            1 => SaltD185,
            _ => Salt97B6,
        };

        var fileTime = lastWriteUtc.ToFileTimeUtc();
        fileTime = (fileTime / 10_000) * 10_000; // Explorer round-trips through SYSTEMTIME: millisecond precision
        var stamp = $"{fileTime >> 32:x8}{fileTime & 0xFFFFFFFF:x8}";

        return modClass switch
        {
            0 => salt + target + stamp + trimmed + progId + userSid,
            1 => salt + stamp + target + userSid + trimmed + progId,
            _ => userSid + stamp + salt + target + trimmed + progId,
        };
    }

    /// <summary>Computes the registry hash value for a canonical input string.</summary>
    public static string Compute(string canonicalInput)
    {
        var lowered = canonicalInput.ToLowerInvariant();
        var words = ToWords(lowered);

        var state = new EncoderState();
        var consumed = FirstPass(state, words);
        SecondPass(state, words, consumed);
        state.Entries[0] = state.TotalUnits | ((ulong)state.Count << 32);

        var packed = new List<ushort>();
        for (ulong i = 0; i < state.Count; i++)
        {
            var value = state.Entries[(int)i];
            for (var shift = 0; shift < 64; shift += 16)
            {
                var part = (ushort)((value >> shift) & 0xFFFF);
                if (part != 0)
                {
                    packed.Add(part);
                }
            }
        }

        packed.Add(0);

        var raw = new byte[packed.Count * 2];
        for (var i = 0; i < packed.Count; i++)
        {
            raw[i * 2] = (byte)(packed[i] & 0xFF);
            raw[i * 2 + 1] = (byte)(packed[i] >> 8);
        }

        var digest = MD5.HashData(raw);

        var byteLen = packed.Count * 2;
        var dwordLen = byteLen >> 2;
        var mixCount = (byteLen & 4) == 0 ? dwordLen : dwordLen - 1;

        var dwords = new uint[(packed.Count + 1) / 2];
        for (var i = 0; i < dwords.Length; i++)
        {
            var lo = (uint)packed[i * 2];
            var hi = i * 2 + 1 < packed.Count ? (uint)packed[i * 2 + 1] : 0u;
            dwords[i] = lo | (hi << 16);
        }

        Span<uint> pairA = stackalloc uint[2];
        Span<uint> pairB = stackalloc uint[2];
        if (mixCount >= 2)
        {
            MixA(dwords, mixCount, digest, SeedA, pairA);
            MixB(dwords, mixCount, digest, SeedB, pairB);
        }

        var low = pairA[0] ^ pairB[0];
        var high = pairA[1] ^ pairB[1];

        Span<byte> final8 = stackalloc byte[8];
        BitConverter.TryWriteBytes(final8[..4], low);
        BitConverter.TryWriteBytes(final8[4..], high);
        return Convert.ToBase64String(final8);
    }

    /// <summary>Verifies a stored hash against the association context.</summary>
    public static bool IsValid(string? storedHash, string target, string progId, string machineId, string userSid, DateTime lastWriteUtc)
    {
        if (string.IsNullOrEmpty(storedHash))
        {
            return false;
        }

        try
        {
            var canonical = BuildCanonical(target, progId, machineId, userSid, lastWriteUtc);
            return string.Equals(Compute(canonical), storedHash, StringComparison.Ordinal);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static ushort[] ToWords(string value)
    {
        var bytes = Encoding.Unicode.GetBytes(value);
        var words = new ushort[bytes.Length / 2];
        for (var i = 0; i < words.Length; i++)
        {
            words[i] = (ushort)(bytes[i * 2] | (bytes[i * 2 + 1] << 8));
        }

        return words;
    }

    private sealed class EncoderState
    {
        public readonly List<ulong> Entries = new(4096) { 0UL };
        public readonly bool[] Seen = new bool[SeenModulo];
        public ulong Count = 1;
        public ulong Last = RepeatSentinel;
        public uint Repeat;
        public uint TotalUnits;

        public bool TestSeen(ulong value) => Seen[value % SeenModulo];

        public void MarkSeen(ulong value) => Seen[value % SeenModulo] = true;

        public void Push(ulong value)
        {
            if ((ulong)Entries.Count <= Count)
            {
                Entries.Add(0);
            }

            Entries[(int)Count] = value;
            Count++;
        }

        public ulong? FindPrevious(ulong value)
        {
            if (!TestSeen(value) || Count == 0)
            {
                return null;
            }

            var start = Count > 0x400 ? Count - 0x400 : 0UL;
            for (var idx = Count - 1; ; idx--)
            {
                if (Entries[(int)idx] == value)
                {
                    return Count - idx;
                }

                if (idx == start)
                {
                    break;
                }
            }

            return null;
        }
    }

    private static int ClassFromWord(ushort ch)
    {
        var hi = ch >> 8;
        return hi != 0 ? ByteClass.Value[hi] + 8 : ByteClass.Value[ch & 0xFF];
    }

    private static (ulong Token, byte Kind, int Length)? BuildToken(ushort[] words, int cursor, int end)
    {
        if (cursor >= end)
        {
            return null;
        }

        var region = TokenRegion.Value;
        var code = (uint)region[ClassFromWord(words[cursor]) + 256];
        var tokenLength = (int)region[code];
        if (cursor + tokenLength > end)
        {
            return null;
        }

        var baseOffset = 168 * (int)code;
        while (true)
        {
            var pos = 0;
            var done = false;
            if (tokenLength != 0)
            {
                var probe = cursor;
                while ((ulong)words[probe] < (1UL << BitWidth.Value[baseOffset + pos]))
                {
                    pos++;
                    probe++;
                    if (pos >= tokenLength)
                    {
                        done = true;
                        break;
                    }
                }
            }

            if (done || tokenLength == 0)
            {
                break;
            }

            code++;
            baseOffset = 168 * (int)code;
            tokenLength = (int)region[code];
            if (tokenLength > end - cursor)
            {
                break;
            }
        }

        return FinishToken(words, cursor, (byte)code, tokenLength, baseOffset);
    }

    private static (ulong Token, byte Kind, int Length)? BuildTokenSecondPass(ushort[] words, int cursor, int end)
    {
        if (cursor >= end)
        {
            return null;
        }

        var region = TokenRegion.Value;
        var remain = end - cursor;
        var code = (uint)region[ClassFromWord(words[cursor]) + 256];
        var tokenLength = (int)region[code];
        if (tokenLength > remain)
        {
            code = FallbackTokenCode.Value[remain];
            tokenLength = (int)region[code];
        }

        var baseOffset = 168 * (int)code;
        while (true)
        {
            var pos = 0;
            var retry = false;
            if (tokenLength != 0)
            {
                var probe = cursor;
                while (probe < end)
                {
                    if ((ulong)words[probe] >= (1UL << BitWidth.Value[baseOffset + pos]))
                    {
                        code++;
                        baseOffset = 168 * (int)code;
                        tokenLength = (int)region[code];
                        if (tokenLength <= remain)
                        {
                            retry = true;
                        }

                        break;
                    }

                    pos++;
                    probe++;
                    if (pos >= tokenLength)
                    {
                        break;
                    }
                }
            }

            if (!retry)
            {
                break;
            }
        }

        return FinishToken(words, cursor, (byte)code, tokenLength, baseOffset);
    }

    private static (ulong, byte, int) FinishToken(ushort[] words, int cursor, byte code, int tokenLength, int baseOffset)
    {
        var token = (ulong)code << 56;
        var shift = 56;
        for (var i = 0; i < tokenLength; i++)
        {
            shift -= BitWidth.Value[baseOffset + i];
            token |= (ulong)words[cursor + i] << shift;
        }

        return (token, code, tokenLength);
    }

    private static int EmitFirstPass(EncoderState state, ushort[] words, int cursor, int end, ulong token, byte kind)
    {
        if (token == state.Last && state.Repeat < 0xFF)
        {
            state.Repeat++;
            return cursor;
        }

        if (state.Repeat != 0)
        {
            var distance = state.FindPrevious(state.Last);
            if (distance is not null)
            {
                var rep = state.Repeat - 1;
                ulong entry;
                if (distance >= 0x800)
                {
                    var packed = (token >> 17) | ((ulong)rep << 48) | RepeatTokenA;
                    state.MarkSeen(packed);
                    state.Push(packed);
                    entry = state.Last;
                }
                else
                {
                    var repBits = ((ulong)((ushort)(distance.Value - 1)) & 0x03FF) | ((ulong)rep << 11);
                    entry = (token >> 27) | (repBits << 37) | RepeatTokenB;
                }

                state.MarkSeen(entry);
                state.Push(entry);
                state.Last = RepeatSentinel;
                state.Repeat = 0;
                return cursor - (distance >= 0x800 ? LongRewind.Value[kind] : ShortRewind.Value[kind]);
            }
        }
        else
        {
            var distance = state.FindPrevious(token);
            if (distance is not null && cursor < end)
            {
                var nextKind = TokenRegion.Value[ClassFromWord(words[cursor]) + 256];
                var entry = distance >= 0x800
                    ? token
                    : (token >> 18) | ((distance.Value - 1) << 46) | RepeatTokenC;
                state.MarkSeen(entry);
                state.Push(entry);
                if (distance < 0x800)
                {
                    cursor -= ShortRewind.Value[nextKind + 256];
                }

                state.Last = token;
                return cursor;
            }
        }

        state.MarkSeen(token);
        state.Push(token);
        state.Last = token;
        return cursor;
    }

    private static int EmitSecondPass(EncoderState state, ushort[] words, int cursor, int end, ulong token, byte kind)
    {
        if (token == state.Last && state.Repeat < 0xFF)
        {
            state.Repeat++;
            return cursor;
        }

        if (state.Repeat != 0)
        {
            var distance = state.FindPrevious(state.Last);
            if (distance is not null)
            {
                var rep = state.Repeat - 1;
                ulong entry;
                if (distance >= 0x800)
                {
                    var packed = (token >> 17) | ((ulong)rep << 48) | RepeatTokenA;
                    state.MarkSeen(packed);
                    state.Push(packed);
                    entry = state.Last;
                }
                else
                {
                    var repBits = ((ulong)((ushort)(distance.Value - 1)) & 0x03FF) | ((ulong)rep << 11);
                    entry = (token >> 27) | (repBits << 37) | RepeatTokenB;
                }

                state.MarkSeen(entry);
                state.Push(entry);
                state.Last = RepeatSentinel;
                state.Repeat = 0;
                return cursor - (distance >= 0x800 ? LongRewind.Value[kind] : ShortRewind.Value[kind]);
            }
        }

        state.MarkSeen(token);
        state.Push(token);
        state.Last = token;
        return cursor;
    }

    private static void FlushSecondPass(EncoderState state)
    {
        if (state.Repeat == 0)
        {
            return;
        }

        ulong entry;
        if (state.Last == RepeatSentinel)
        {
            entry = ((ulong)state.Repeat << 48) | RepeatTokenD;
        }
        else
        {
            var distance = state.FindPrevious(state.Last);
            if (distance is not null && distance != 0)
            {
                var repBits = ((ulong)((ushort)(distance.Value - 1)) & 0x03FF) | ((ulong)(state.Repeat - 1) << 11);
                entry = (repBits << 37) | RepeatTokenE;
            }
            else
            {
                var repeatToken = ((ulong)state.Repeat << 48) | RepeatTokenD;
                state.MarkSeen(repeatToken);
                state.Push(repeatToken);
                entry = state.Last;
            }
        }

        state.MarkSeen(entry);
        state.Push(entry);
        state.Repeat = 0;
        state.Last = RepeatSentinel;
    }

    private static int FirstPass(EncoderState state, ushort[] words)
    {
        var end = words.Length;
        var cursor = 0;
        var consumed = 0;
        var result = (ulong)((2249744775UL * (uint)words.Length) >> 32);
        var quota = (result + (((ulong)words.Length - result) >> 1)) >> 7;

        while ((uint)quota > 1)
        {
            var limit = (uint)quota - 1;
            uint processed = 0;
            while (processed < limit)
            {
                var built = BuildToken(words, cursor, end);
                if (built is null)
                {
                    break;
                }

                var (token, kind, length) = built.Value;
                consumed += length;
                cursor += length;
                cursor = EmitFirstPass(state, words, cursor, end, token, kind);
                processed++;
            }

            result = (ulong)((2249744775UL * (uint)(end - cursor)) >> 32);
            quota = ((uint)result + (((uint)(end - cursor) - (uint)result) >> 1)) >> 7;
        }

        return consumed;
    }

    private static void SecondPass(EncoderState state, ushort[] words, int start)
    {
        var end = words.Length;
        var cursor = start;
        while (cursor < end)
        {
            var built = BuildTokenSecondPass(words, cursor, end);
            if (built is null)
            {
                break;
            }

            var (token, kind, length) = built.Value;
            state.TotalUnits += (uint)length;
            cursor += length;
            cursor = EmitSecondPass(state, words, cursor, end, token, kind);
        }

        FlushSecondPass(state);
    }

    private static uint LowMul(uint a, uint b) => (uint)((ulong)a * b);

    private static void MixA(uint[] words, int count, byte[] md5, uint[] seed, Span<uint> output)
    {
        unchecked
        {
            var md0 = BitConverter.ToUInt32(md5, 0) | 1u;
            var md1 = (BitConverter.ToUInt32(md5, 4) | 1u) + 0x13DB0000u;
            var s0 = seed[0];
            var s1 = seed[1];
            var s2 = seed[2];
            var s3 = seed[3];

            uint sum = 0, acc = 0;
            var p = 0;
            var remaining = count;

            var loops = ((uint)(remaining - 2) >> 1) + 1;
            var mul = md0 + s0;
            while (loops-- != 0)
            {
                acc += words[p];
                remaining -= 2;
                var x = acc;
                var hi = x >> 16;
                p += 2;

                var t = LowMul(x, mul) - LowMul(hi, s3);
                mul = md0 + s0;

                var s = LowMul(t, s1) + LowMul(t >> 16, 0x689B6B9Fu);
                var part1 = LowMul(s, 0xEA970001u) - LowMul(s >> 16, 0x3C101569u);

                var w = words[p - 1] + part1;
                var t2 = LowMul(w, md1) - LowMul(w >> 16, s2);
                var temp = LowMul(t2, 0x59C3AF2Du) - LowMul(t2 >> 16, 0x2232E0F1u);
                acc = LowMul(temp >> 16, 0x35BD1EC9u) + LowMul(temp, 0x1EC90001u);
                sum += part1 + acc;
            }

            if (remaining == 1)
            {
                acc += words[p];
                var t = LowMul(acc, md0 + s0) - LowMul(acc >> 16, s3);
                var part = LowMul(t, s1) - LowMul(t >> 16, 0x689B6B9Fu);
                part += LowMul(t >> 16, 0x39646B9Fu);

                var t2 = LowMul(part, md1) - LowMul(part >> 16, s2);
                var temp = LowMul(t2, 0x59C3AF2Du) - LowMul(t2 >> 16, 0x2232E0F1u);
                var extra = LowMul(t2, 0x2A18AF2Du) + LowMul(t2 >> 16, 0x02941F0Fu) + LowMul(temp >> 16, 0x35BD1EC9u);
                acc = extra;
                sum += part + acc;
            }

            output[0] = acc;
            output[1] = sum;
        }
    }

    private static void MixB(uint[] words, int count, byte[] md5, uint[] seed, Span<uint> output)
    {
        unchecked
        {
            var s0 = seed[0];
            var s1 = seed[1];
            var s2 = seed[2];
            var s3 = seed[3];
            var md1 = BitConverter.ToUInt32(md5, 4) | 1u;
            var md0 = BitConverter.ToUInt32(md5, 0) | 1u;

            uint sum = 0, acc = 0;
            var p = 0;
            var remaining = count;

            var loops = ((uint)(remaining - 2) >> 1) + 1;
            while (loops-- != 0)
            {
                var x = words[p] + acc;
                remaining -= 2;
                p += 2;

                var t = LowMul(x, md0);
                var a = LowMul(t, 0xB1110000u) - LowMul(t >> 16, 0x30674EEFu);
                var b = LowMul(a, s2);
                var c = b - LowMul(a >> 16, 0x78F7A461u);
                c = LowMul(c >> 16, s0) - LowMul(a >> 16, 0x164D0000u) - LowMul(b, 0x46930000u);
                var d = LowMul(c >> 16, 0x257E1D83u) + LowMul(c, 0x1D830000u);

                var e = words[p - 1] + d;
                var f = LowMul(e, md1);
                var g = LowMul(f, 0x16F50000u) - LowMul(f >> 16, 0x5D8BE90Bu);
                var h = LowMul(g >> 16, s3);
                var i = LowMul(g, 0x69010000u) + h;
                var j = LowMul(i, s1);
                var k = (0u - h - LowMul(g, 0x69010000u)) >> 16;
                var m = LowMul(k, 0x7C932B89u) - j;
                var n = LowMul(k, 0xF2310000u) - LowMul(m >> 16, 0x405B6097u);
                n += LowMul(j, 0x60970000u);

                acc = n;
                sum += d + acc;
            }

            if (remaining == 1)
            {
                var x = words[p] + acc;
                var t = LowMul(x, md0);
                var a = LowMul(t, 0xB1110000u) - LowMul(t >> 16, 0x30674EEFu);
                var b = LowMul(a, s2);
                var c = LowMul(a >> 16, 0xE9B30000u) - LowMul(b, 0x46930000u)
                    + LowMul((b - LowMul(a >> 16, 0x78F7A461u)) >> 16, s0);
                var d = LowMul(c >> 16, 0x257E1D83u) + LowMul(c, 0x1D830000u);

                var e = LowMul(d, md1);
                var f = LowMul(e, 0x16F50000u) - LowMul(e >> 16, 0x5D8BE90Bu);
                var h = LowMul(f >> 16, s3);
                var i = LowMul(f, 0x69010000u) + h;
                var j = LowMul(i, s1);
                var k = (0u - h - LowMul(f, 0x69010000u)) >> 16;
                var m = LowMul(k, 0x7C932B89u) - j;
                var n = LowMul(k, 0xF2310000u) - LowMul(m >> 16, 0x405B6097u);
                n += LowMul(j, 0x60970000u);

                acc = n;
                sum += d + acc;
            }

            output[0] = acc;
            output[1] = sum;
        }
    }
}

