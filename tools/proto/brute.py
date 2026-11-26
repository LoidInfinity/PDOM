"""Brute-force the canonical-input assumptions for UserChoiceLatest."""
import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from latest_hash import (Hasher, load_tables, machine_id, sid_string, RegKey, HKCU,
                         target_base, SALT_3822, SALT_97B6, SALT_D185)

SALTS = [SALT_3822, SALT_D185, SALT_97B6]
ORDERS = {
    0: lambda salt, assoc, ts, mid, pid, sid: salt + assoc + ts + mid + pid + sid,
    1: lambda salt, assoc, ts, mid, pid, sid: salt + ts + assoc + sid + mid + pid,
    2: lambda salt, assoc, ts, mid, pid, sid: sid + ts + salt + assoc + mid + pid,
}


def context(target):
    base = target_base(target)
    latest = RegKey(HKCU, base + r"\UserChoiceLatest")
    latest_hash = latest.value("Hash")
    latest_lwt = latest.last_write()
    latest.close()
    pk = RegKey(HKCU, base + r"\UserChoiceLatest\ProgId")
    pid = pk.value("ProgId")
    pid_lwt = pk.last_write()
    pk.close()
    uc = RegKey(HKCU, base + r"\UserChoice")
    uc_pid = uc.value("ProgId") or uc.value("ProgID")
    uc_lwt = uc.last_write()
    uc.close()
    return dict(hash=latest_hash, latest_lwt=latest_lwt, pid=pid, pid_lwt=pid_lwt,
                uc_pid=uc_pid, uc_lwt=uc_lwt)


def ts(ft):
    # Windows round-trips the key timestamp through SYSTEMTIME, which keeps
    # only millisecond precision (FILETIME unit is 100 ns).
    ft = (ft // 10000) * 10000
    return f"{ft >> 32:08x}{ft & 0xFFFFFFFF:08x}"


def main():
    hasher = Hasher(load_tables())
    mid_raw = machine_id()
    sid = sid_string()
    targets = sys.argv[1:] or [".html", ".txt", "http"]

    for target in targets:
        ctx = context(target)
        print(f"\n=== {target} registry={ctx['hash']}")
        found = 0
        mids = {"raw": mid_raw, "trim": mid_raw[1:-1], "lower": mid_raw.lower(),
                "trim-lower": mid_raw[1:-1].lower()}
        pids = {"latest": ctx["pid"], "uc": ctx["uc_pid"]}
        stamps = {"latest-progid": ctx["pid_lwt"], "latest": ctx["latest_lwt"],
                  "uc": ctx["uc_lwt"]}
        salt_options = list(zip(["3822", "d185", "97b6"], SALTS))
        for (mid_name, mid), (pid_name, pid), (st_name, ft), (order, fn), (salt_name, salt) in itertools.product(
                mids.items(), pids.items(), stamps.items(), ORDERS.items(), salt_options):
            if not pid or not ft:
                continue
            text = fn(salt, target, ts(ft), mid, pid, sid)
            computed = hasher.compute(text)
            if computed == ctx["hash"]:
                found += 1
                print(f"  MATCH mid={mid_name} pid={pid_name} ts={st_name} order={order} salt={salt_name}")
        if not found:
            print("  no match")


if __name__ == "__main__":
    main()
