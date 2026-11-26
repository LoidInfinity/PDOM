"""Write a UserChoiceLatest association using the prototype algorithm."""
import sys
from pathlib import Path

import winreg

sys.path.insert(0, str(Path(__file__).resolve().parent))
from latest_hash import (Hasher, RegKey, HKCU, load_tables, machine_id, sid_string,
                         target_base, SALT_3822, SALT_97B6, SALT_D185)

HKCU_HANDLE = winreg.HKEY_CURRENT_USER
KEY_ALL = winreg.KEY_ALL_ACCESS


def build_canonical(target, progid, timestamp_ft, machine, sid):
    trimmed = machine[1:-1] if machine.startswith("{") and machine.endswith("}") else machine
    mod = ord(trimmed[-1]) % 3
    salt = SALT_3822 if mod == 0 else (SALT_D185 if mod == 1 else SALT_97B6)
    stamp = f"{(timestamp_ft // 10000 * 10000) >> 32:08x}{(timestamp_ft // 10000 * 10000) & 0xFFFFFFFF:08x}"
    if mod == 0:
        return salt + target + stamp + trimmed + progid + sid
    if mod == 1:
        return salt + stamp + target + sid + trimmed + progid
    return sid + stamp + salt + target + trimmed + progid


def read_lwt(path):
    key = RegKey(HKCU, path)
    try:
        return key.last_write()
    finally:
        key.close()


def write_latest(target, progid):
    base = target_base(target)
    with winreg.CreateKeyEx(HKCU_HANDLE, base + r"\UserChoiceLatest\ProgId", 0, KEY_ALL) as key:
        winreg.SetValueEx(key, "ProgId", 0, winreg.REG_SZ, progid)

    lwt = read_lwt(base + r"\UserChoiceLatest\ProgId")
    canonical = build_canonical(target, progid, lwt, machine_id(), sid_string())
    digest = Hasher(load_tables()).compute(canonical)

    with winreg.CreateKeyEx(HKCU_HANDLE, base + r"\UserChoiceLatest", 0, KEY_ALL) as key:
        winreg.SetValueEx(key, "Hash", 0, winreg.REG_SZ, digest)

    return digest, canonical


def main():
    if len(sys.argv) < 3:
        print("usage: write_latest.py <target> <progid>")
        return 1
    target, progid = sys.argv[1], sys.argv[2]
    digest, canonical = write_latest(target, progid)
    print(f"wrote {target} -> {progid}")
    print(f"hash: {digest}")
    print(f"canonical: {canonical}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
