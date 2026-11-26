"""Prototype of the Windows 11 24H2+ "UserChoiceLatest" hash.

Port of the public reverse engineering in cssxn/UserChoiceLatestHash (MIT).
Used only to validate the algorithm against live registry data before the
same logic is ported to C#.
"""
import base64
import ctypes
import ctypes.wintypes as wt
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TABLES_INC = ROOT / "tools" / "ref" / "tables.inc"

K_REPEAT_SENTINEL = 0xFBFFFFFFFFFFFFFF
K_REPEAT_TOKEN_A = 0xFE00000000000000
K_REPEAT_TOKEN_B = 0xFE00800000000000
K_REPEAT_TOKEN_C = 0xFF00000000000000
K_REPEAT_TOKEN_D = 0xFE007DFFFFFFFFFF
K_REPEAT_TOKEN_E = 0xFE00801F7FFFFFFF
K_SEEN_MODULO = 0x2803
MASK64 = 0xFFFFFFFFFFFFFFFF
MASK32 = 0xFFFFFFFF

SEED_A_BYTES = bytes([0x00, 0x00, 0xFB, 0x69, 0x95, 0xA3, 0xF8, 0x79,
                      0x25, 0xEC, 0xE8, 0x3C, 0x05, 0x96, 0xFA, 0x10])
SEED_B_BYTES = bytes([0x6D, 0xB9, 0xCE, 0x12, 0x00, 0x00, 0x89, 0x2B,
                      0x00, 0x00, 0x9F, 0x5B, 0x01, 0x69, 0x7C, 0x2C])

SALT_3822 = "Copyright (C) Microsoft. All rights reserved {3822B7CA-C2F4-4889-B8CC-4CE39A8FB81C}"
SALT_97B6 = "Copyright (C) Microsoft. All rights reserved {97B6BCF4-C367-4577-95BE-73BD3053A5E0}"
SALT_D185 = "Copyright (C) Microsoft. All rights reserved {D185E0A1-E265-4724-AA21-3A17B038D72E}"


def load_tables():
    text = TABLES_INC.read_text(encoding="utf-8", errors="ignore")
    out = {}
    for name in ("kTokenRegionHex", "kLongRewindTableHex", "kFallbackTokenCodeTableHex",
                 "kByteClassTableHex", "kTokenBitWidthTableHex", "kShortRewindTableHex"):
        m = re.search(name + r"\s*=\s*((?:\s*\"[0-9a-fA-F]*\"\s*)+);", text)
        if not m:
            raise RuntimeError("table not found: " + name)
        hexstr = "".join(re.findall(r'"([0-9a-fA-F]*)"', m.group(1)))
        out[name] = bytes.fromhex(hexstr)
    return out


def seed_words(b):
    return [int.from_bytes(b[i * 4:i * 4 + 4], "little") for i in range(4)]


class EncoderState:
    def __init__(self):
        self.entries = [0]
        self.seen = set()
        self.count = 1
        self.last = K_REPEAT_SENTINEL
        self.repeat = 0
        self.total_units = 0

    def test_seen(self, value):
        return (value % K_SEEN_MODULO) in self.seen

    def mark_seen(self, value):
        self.seen.add(value % K_SEEN_MODULO)

    def push(self, value):
        self.entries.append(value & MASK64)
        self.count += 1

    def find_previous(self, value):
        if not self.test_seen(value) or self.count == 0:
            return None
        start = self.count - 0x400 if self.count > 0x400 else 0
        idx = self.count - 1
        while True:
            if self.entries[idx] == value:
                return self.count - idx
            if idx == start:
                break
            idx -= 1
        return None


class Hasher:
    def __init__(self, tables):
        self.t = tables
        self.byte_class = tables["kByteClassTableHex"]
        self.token_region = tables["kTokenRegionHex"]
        self.bit_width = tables["kTokenBitWidthTableHex"]
        self.short_rewind = tables["kShortRewindTableHex"]
        self.long_rewind = tables["kLongRewindTableHex"]
        self.fallback = tables["kFallbackTokenCodeTableHex"]
        self.seeds_a = seed_words(SEED_A_BYTES)
        self.seeds_b = seed_words(SEED_B_BYTES)

    def class_from_word(self, ch):
        hi = ch >> 8
        if hi != 0:
            return (self.byte_class[hi] + 8) & 0xFF
        return self.byte_class[ch & 0xFF]

    def build_token(self, words, cursor, end):
        if cursor >= end:
            return None
        code = self.token_region[self.class_from_word(words[cursor]) + 256]
        token_len = self.token_region[code]
        if cursor + token_len > end:
            return None
        base = 168 * code
        while True:
            pos = 0
            if token_len == 0:
                break
            probe = cursor
            done = False
            while words[probe] < (1 << self.bit_width[base + pos]):
                pos += 1
                probe += 1
                if pos >= token_len:
                    done = True
                    break
            if done:
                break
            code += 1
            base = 168 * code
            token_len = self.token_region[code]
            if token_len > (end - cursor):
                break
        token = (code & 0xFF) << 56
        shift = 56
        for i in range(token_len):
            shift -= self.bit_width[base + i]
            token |= words[cursor + i] << shift
        return token, code, token_len

    def build_token_second(self, words, cursor, end):
        if cursor >= end:
            return None
        remain = end - cursor
        code = self.token_region[self.class_from_word(words[cursor]) + 256]
        token_len = self.token_region[code]
        if token_len > remain:
            code = self.fallback[remain]
            token_len = self.token_region[code]
        base = 168 * code
        while True:
            pos = 0
            retry = False
            if token_len != 0:
                probe = cursor
                while probe < end:
                    if words[probe] >= (1 << self.bit_width[base + pos]):
                        code += 1
                        base = 168 * code
                        token_len = self.token_region[code]
                        if token_len <= remain:
                            retry = True
                        break
                    pos += 1
                    probe += 1
                    if pos >= token_len:
                        break
            if not retry:
                break
        token = (code & 0xFF) << 56
        shift = 56
        for i in range(token_len):
            if cursor + i >= end:
                break
            shift -= self.bit_width[base + i]
            token |= words[cursor + i] << shift
        return token, code, token_len

    def emit_first(self, st, words, cursor, end, token, kind):
        if token == st.last and st.repeat < 0xFF:
            st.repeat += 1
            return cursor
        if st.repeat != 0:
            distance = st.find_previous(st.last)
            if distance is not None:
                rep = st.repeat - 1
                if distance >= 0x800:
                    packed = ((token >> 17) | (rep << 48) | K_REPEAT_TOKEN_A) & MASK64
                    st.mark_seen(packed)
                    st.push(packed)
                    entry = st.last
                else:
                    entry = ((token >> 27)
                             | ((((distance - 1) & 0x3FF) | (rep << 11)) << 37)
                             | K_REPEAT_TOKEN_B) & MASK64
                st.mark_seen(entry)
                st.push(entry)
                st.last = K_REPEAT_SENTINEL
                st.repeat = 0
                rewind = self.long_rewind[kind] if distance >= 0x800 else self.short_rewind[kind]
                return cursor - rewind
        else:
            distance = st.find_previous(token)
            if distance is not None and cursor < end:
                next_kind = self.token_region[self.class_from_word(words[cursor]) + 256]
                if distance >= 0x800:
                    entry = token
                else:
                    entry = ((token >> 18) | ((distance - 1) << 46) | K_REPEAT_TOKEN_C) & MASK64
                st.mark_seen(entry)
                st.push(entry)
                if distance < 0x800:
                    cursor -= self.short_rewind[next_kind + 256]
                st.last = token
                return cursor
        st.mark_seen(token)
        st.push(token)
        st.last = token
        return cursor

    def emit_second(self, st, words, cursor, end, token, kind):
        if token == st.last and st.repeat < 0xFF:
            st.repeat += 1
            return cursor
        if st.repeat != 0:
            distance = st.find_previous(st.last)
            if distance is not None:
                rep = st.repeat - 1
                if distance >= 0x800:
                    packed = ((token >> 17) | (rep << 48) | K_REPEAT_TOKEN_A) & MASK64
                    st.mark_seen(packed)
                    st.push(packed)
                    entry = st.last
                else:
                    entry = ((token >> 27)
                             | ((((distance - 1) & 0x3FF) | (rep << 11)) << 37)
                             | K_REPEAT_TOKEN_B) & MASK64
                st.mark_seen(entry)
                st.push(entry)
                st.last = K_REPEAT_SENTINEL
                st.repeat = 0
                rewind = self.long_rewind[kind] if distance >= 0x800 else self.short_rewind[kind]
                return cursor - rewind
        st.mark_seen(token)
        st.push(token)
        st.last = token
        return cursor

    def flush_second(self, st):
        if st.repeat == 0:
            return
        if st.last == K_REPEAT_SENTINEL:
            entry = ((st.repeat << 48) | K_REPEAT_TOKEN_D) & MASK64
        else:
            distance = st.find_previous(st.last)
            if distance is not None and distance != 0:
                entry = ((((distance - 1) & 0x3FF) | ((st.repeat - 1) << 11)) << 37) | K_REPEAT_TOKEN_E
                entry &= MASK64
            else:
                repeat_token = ((st.repeat << 48) | K_REPEAT_TOKEN_D) & MASK64
                st.mark_seen(repeat_token)
                st.push(repeat_token)
                entry = st.last
        st.mark_seen(entry)
        st.push(entry)
        st.repeat = 0
        st.last = K_REPEAT_SENTINEL

    def first_pass(self, st, words):
        n = len(words)
        end = n
        cursor = 0
        consumed = 0
        result = (2249744775 * n) >> 32
        quota = (result + ((n - result) >> 1)) >> 7
        while (quota & MASK32) > 1:
            limit = quota - 1
            processed = 0
            while processed < limit:
                built = self.build_token(words, cursor, end)
                if built is None:
                    break
                token, kind, tlen = built
                consumed += tlen
                cursor += tlen
                cursor = self.emit_first(st, words, cursor, end, token, kind)
                processed += 1
            result = (2249744775 * (end - cursor)) >> 32
            quota = ((result & MASK32) + (((end - cursor) - result) >> 1)) >> 7
        return consumed

    def second_pass(self, st, words, start):
        end = len(words)
        cursor = start
        while cursor < end:
            built = self.build_token_second(words, cursor, end)
            if built is None:
                break
            token, kind, tlen = built
            st.total_units += tlen
            cursor += tlen
            cursor = self.emit_second(st, words, cursor, end, token, kind)
        self.flush_second(st)

    def compute(self, canonical: str) -> str:
        lowered = canonical.lower()
        words = list(memoryview(lowered.encode("utf-16-le")).cast("H"))
        st = EncoderState()
        consumed = self.first_pass(st, words)
        self.second_pass(st, words, consumed)
        st.entries[0] = (st.total_units & MASK64) | ((st.count & MASK64) << 32)

        packed = []
        for idx in range(st.count):
            value = st.entries[idx]
            for shift in (0, 16, 32, 48):
                part = (value >> shift) & 0xFFFF
                if part != 0:
                    packed.append(part)
        packed.append(0)

        raw = b"".join(p.to_bytes(2, "little") for p in packed)
        digest = hashlib.md5(raw).digest()
        md5 = [int.from_bytes(digest[i * 4:i * 4 + 4], "little") for i in range(4)]

        byte_len = len(packed) * 2
        dword_len = byte_len >> 2
        mix_count = dword_len if (byte_len & 4) == 0 else dword_len - 1
        dwords = []
        for i in range((len(packed) + 1) // 2):
            lo = packed[i * 2]
            hi = packed[i * 2 + 1] if i * 2 + 1 < len(packed) else 0
            dwords.append((lo | (hi << 16)) & MASK32)

        pair_a = [0, 0]
        pair_b = [0, 0]
        if mix_count >= 2:
            pair_a = self.mix_a(dwords, mix_count, md5, self.seeds_a)
            pair_b = self.mix_b(dwords, mix_count, md5, self.seeds_b)

        low = pair_a[0] ^ pair_b[0]
        high = pair_a[1] ^ pair_b[1]
        final8 = low.to_bytes(4, "little") + high.to_bytes(4, "little")
        return base64.b64encode(final8).decode("ascii")

    @staticmethod
    def _lo(a, b):
        return (a * b) & MASK32

    def mix_a(self, words, count, md5, seed):
        md0 = md5[0] | 1
        md1 = ((md5[1] | 1) + 0x13DB0000) & MASK32
        s0, s1, s2, s3 = seed
        total = 0
        acc = 0
        p = 0
        remaining = count
        loops = (((remaining - 2) & MASK32) >> 1) + 1
        mul = (md0 + s0) & MASK32
        while loops:
            acc = (acc + words[p]) & MASK32
            remaining -= 2
            x = acc
            hi = x >> 16
            p += 2
            t = (self._lo(x, mul) - self._lo(hi, s3)) & MASK32
            mul = (md0 + s0) & MASK32
            s = (self._lo(t, s1) + self._lo(t >> 16, 0x689B6B9F)) & MASK32
            part1 = (self._lo(s, 0xEA970001) - self._lo(s >> 16, 0x3C101569)) & MASK32
            w = (words[p - 1] + part1) & MASK32
            t2 = (self._lo(w, md1) - self._lo(w >> 16, s2)) & MASK32
            temp = (self._lo(t2, 0x59C3AF2D) - self._lo(t2 >> 16, 0x2232E0F1)) & MASK32
            acc = (self._lo(temp >> 16, 0x35BD1EC9) + self._lo(temp, 0x1EC90001)) & MASK32
            total = (total + part1 + acc) & MASK32
            loops -= 1

        if remaining == 1:
            acc = (acc + words[p]) & MASK32
            t = (self._lo(acc, (md0 + s0) & MASK32) - self._lo(acc >> 16, s3)) & MASK32
            part = (self._lo(t, s1) - self._lo(t >> 16, 0x689B6B9F) + self._lo(t >> 16, 0x39646B9F)) & MASK32
            t2 = (self._lo(part, md1) - self._lo(part >> 16, s2)) & MASK32
            temp = (self._lo(t2, 0x59C3AF2D) - self._lo(t2 >> 16, 0x2232E0F1)) & MASK32
            extra = (self._lo(t2, 0x2A18AF2D) + self._lo(t2 >> 16, 0x02941F0F) + self._lo(temp >> 16, 0x35BD1EC9)) & MASK32
            acc = extra
            total = (total + part + acc) & MASK32

        return [acc, total]

    def mix_b(self, words, count, md5, seed):
        s0, s1, s2, s3 = seed
        md1 = md5[1] | 1
        md0 = md5[0] | 1
        total = 0
        acc = 0
        p = 0
        remaining = count
        loops = (((remaining - 2) & MASK32) >> 1) + 1
        while loops:
            x = (words[p] + acc) & MASK32
            remaining -= 2
            p += 2

            t = self._lo(x, md0)
            a = (self._lo(t, 0xB1110000) - self._lo(t >> 16, 0x30674EEF)) & MASK32
            b = self._lo(a, s2)
            c = (b - self._lo(a >> 16, 0x78F7A461)) & MASK32
            c = (self._lo(c >> 16, s0) - self._lo(a >> 16, 0x164D0000) - self._lo(b, 0x46930000)) & MASK32
            d = (self._lo(c >> 16, 0x257E1D83) + self._lo(c, 0x1D830000)) & MASK32

            e = (words[p - 1] + d) & MASK32
            f = self._lo(e, md1)
            g = (self._lo(f, 0x16F50000) - self._lo(f >> 16, 0x5D8BE90B)) & MASK32
            h = self._lo(g >> 16, s3)
            i = (self._lo(g, 0x69010000) + h) & MASK32
            j = self._lo(i, s1)
            k = (((0 - h) & MASK32) - self._lo(g, 0x69010000)) & MASK32
            k >>= 16
            m = (self._lo(k, 0x7C932B89) - j) & MASK32
            n = (self._lo(k, 0xF2310000) - self._lo(m >> 16, 0x405B6097)) & MASK32
            n = (n + self._lo(j, 0x60970000)) & MASK32

            acc = n
            total = (total + d + acc) & MASK32
            loops -= 1

        if remaining == 1:
            x = (words[p] + acc) & MASK32
            t = self._lo(x, md0)
            a = (self._lo(t, 0xB1110000) - self._lo(t >> 16, 0x30674EEF)) & MASK32
            b = self._lo(a, s2)
            c = (self._lo(a >> 16, 0xE9B30000) - self._lo(b, 0x46930000)
                 + self._lo(((b - self._lo(a >> 16, 0x78F7A461)) & MASK32) >> 16, s0)) & MASK32
            d = (self._lo(c >> 16, 0x257E1D83) + self._lo(c, 0x1D830000)) & MASK32

            e = self._lo(d, md1)
            f = (self._lo(e, 0x16F50000) - self._lo(e >> 16, 0x5D8BE90B)) & MASK32
            h = self._lo(f >> 16, s3)
            i = (self._lo(f, 0x69010000) + h) & MASK32
            j = self._lo(i, s1)
            k = (((0 - h) & MASK32) - self._lo(f, 0x69010000)) & MASK32
            k >>= 16
            m = (self._lo(k, 0x7C932B89) - j) & MASK32
            n = (self._lo(k, 0xF2310000) - self._lo(m >> 16, 0x405B6097)) & MASK32
            n = (n + self._lo(j, 0x60970000)) & MASK32

            acc = n
            total = (total + d + acc) & MASK32

        return [acc, total]


# ---------------------------------------------------------------- registry


LONG = ctypes.c_long
HKEY = wt.HKEY
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wt.DWORD), ("dwHighDateTime", wt.DWORD)]


advapi32.RegOpenKeyExW.argtypes = [HKEY, wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.POINTER(HKEY)]
advapi32.RegOpenKeyExW.restype = LONG
advapi32.RegCloseKey.argtypes = [HKEY]
advapi32.RegQueryInfoKeyW.restype = LONG
advapi32.RegQueryValueExW.argtypes = [HKEY, wt.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(wt.DWORD),
                                      ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]


class RegKey:
    def __init__(self, root, path, access=0x20019):
        self.handle = HKEY()
        rc = advapi32.RegOpenKeyExW(root, path, 0, access, ctypes.byref(self.handle))
        if rc != 0:
            raise OSError(rc, f"RegOpenKeyEx {path}")

    def value(self, name):
        size = wt.DWORD(0)
        type_ = wt.DWORD(0)
        rc = advapi32.RegQueryValueExW(self.handle, name, None, ctypes.byref(type_), None, ctypes.byref(size))
        if rc != 0 or size.value == 0:
            return None
        buf = ctypes.create_string_buffer(size.value)
        rc = advapi32.RegQueryValueExW(self.handle, name, None, ctypes.byref(type_), buf, ctypes.byref(size))
        if rc != 0:
            return None
        return buf.raw[:size.value].decode("utf-16-le").rstrip("\x00")

    def last_write(self):
        ft = FILETIME()
        rc = advapi32.RegQueryInfoKeyW(self.handle, None, None, None, None, None, None,
                                       None, None, None, None, ctypes.byref(ft))
        if rc != 0:
            return None
        return (ft.dwHighDateTime << 32) | ft.dwLowDateTime

    def close(self):
        advapi32.RegCloseKey(self.handle)


HKCU = 0x80000001
HKLM = 0x80000002


def machine_id():
    key = RegKey(HKLM, r"SOFTWARE\Microsoft\SQMClient")
    try:
        return key.value("MachineID")
    finally:
        key.close()


def sid_string():
    import subprocess
    out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                         capture_output=True, text=True).stdout.strip()
    return out.split(",")[-1].strip('"')


def target_base(target):
    if target.startswith("."):
        return r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts" + "\\" + target
    return r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations" + "\\" + target


def canonical(assoc, progid, timestamp_hex, mid, sid):
    trimmed = mid[1:-1] if mid.startswith("{") and mid.endswith("}") else mid
    mod = ord(trimmed[-1]) % 3
    salt = SALT_3822 if mod == 0 else (SALT_D185 if mod == 1 else SALT_97B6)
    if mod == 0:
        s = salt + assoc + timestamp_hex + trimmed + progid + sid
    elif mod == 1:
        s = salt + timestamp_hex + assoc + sid + trimmed + progid
    else:
        s = sid + timestamp_hex + salt + assoc + trimmed + progid
    return s, mod


def probe(target, hasher, mid, sid):
    base = target_base(target)
    latest = RegKey(HKCU, base + r"\UserChoiceLatest")
    try:
        registry_hash = latest.value("Hash")
        latest_lwt = latest.last_write()
    finally:
        latest.close()
    progid_key = RegKey(HKCU, base + r"\UserChoiceLatest\ProgId")
    try:
        progid = progid_key.value("ProgId")
        progid_lwt = progid_key.last_write()
    finally:
        progid_key.close()
    uc = RegKey(HKCU, base + r"\UserChoice")
    try:
        uc_progid = uc.value("ProgId") or uc.value("ProgID")
        uc_lwt = uc.last_write()
    finally:
        uc.close()

    candidates = []
    for label, pid, lwt in (("latest", progid, progid_lwt),
                             ("latest-uc", uc_progid, progid_lwt),
                             ("latest|uc-lwt", progid, uc_lwt),
                             ("uc", uc_progid, uc_lwt)):
        if not pid or not lwt:
            continue
        ts = f"{lwt >> 32:08x}{lwt & 0xFFFFFFFF:08x}"
        text, mod = canonical(target, pid, ts, mid, sid)
        candidates.append((label, pid, hasher.compute(text), mod))

    return registry_hash, candidates


def main():
    tables = load_tables()
    hasher = Hasher(tables)
    mid = machine_id()
    sid = sid_string()
    print(f"machineID={mid} sid={sid}")
    print(f"table sizes: " + ", ".join(f"{k}={len(v)}" for k, v in tables.items()))

    targets = sys.argv[1:] or [".html", ".htm", ".pdf", ".txt", ".log", "http", "https"]
    ok = 0
    for target in targets:
        registry_hash, candidates = probe(target, hasher, mid, sid)
        match = next((c for c in candidates if c[2] == registry_hash), None)
        status = "MATCH " + (match[0] if match else "")
        if match:
            ok += 1
        print(f"\n{target}: registry={registry_hash} {status}")
        for label, pid, computed, mod in candidates:
            flag = "  <== " if computed == registry_hash else "      "
            print(f"  [{label:<12}] {computed} mod={mod} progid={pid}{flag}")
    print(f"\nmatched {ok}/{len(targets)}")


if __name__ == "__main__":
    main()
