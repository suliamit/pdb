#!/usr/bin/env python3
"""
Download every known ntoskrnl.exe and its PDB from the Microsoft symbol server.

The symbol server can't be enumerated, so build list comes from Winbindex
(timestamp + SizeOfImage per build). For each build:
  1. fetch ntoskrnl.exe from msdl by <TimeDateStamp><SizeOfImage>
  2. read the RSDS CodeView record (GUID, age, pdb name)
  3. fetch the PDB by <GUID><age>
  4. save the exe next to the PDB: OUT/<pdb>/<GUID><age>/{<pdb>,ntoskrnl.exe}

Finished builds are recorded in OUT/done.tsv, so a re-run skips them without
downloading anything.

usage: dl_ntoskrnl_pdbs.py [OUT] [-j WORKERS]
pip install requests pefile
"""
import argparse, gzip, json, os, threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import pefile
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

WINBINDEX = "https://winbindex.m417z.com/data/by_filename_compressed/ntoskrnl.exe.json.gz"
SYMSRV = "https://msdl.microsoft.com/download/symbols"
EXE = "ntoskrnl.exe"
HDRS = {"User-Agent": "Microsoft-Symbol-Server/10.0.0.0"}
CHUNK = 1 << 20

_tls = threading.local()
def sess():
    if not hasattr(_tls, "s"):
        s = requests.Session()
        s.headers.update(HDRS)
        retry = Retry(total=4, backoff_factor=1,
                      status_forcelist=(429, 500, 502, 503, 504))
        a = HTTPAdapter(max_retries=retry, pool_maxsize=4)
        s.mount("https://", a)
        s.mount("http://", a)
        _tls.s = s
    return _tls.s


def builds():
    r = requests.get(WINBINDEX, timeout=60)
    r.raise_for_status()
    data = json.loads(gzip.decompress(r.content))
    seen = set()
    for info in data.values():
        fi = info.get("fileInfo", {})
        ts, sz = fi.get("timestamp"), fi.get("virtualSize")
        if ts and sz and (ts, sz) not in seen:
            seen.add((ts, sz))
            yield ts, sz


def rsds(pe_bytes):
    pe = pefile.PE(data=pe_bytes, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        e = d.entry
        if e and getattr(e, "CvSignature", b"") == b"RSDS":
            guid = "%08X%04X%04X%s" % (
                e.Signature_Data1, e.Signature_Data2, e.Signature_Data3,
                (bytes([e.Signature_Data4, e.Signature_Data5]) + e.Signature_Data6).hex().upper())
            name = os.path.basename(e.PdbFileName.rstrip(b"\0").decode().replace("\\", "/"))
            return name, f"{guid}{e.Age:X}"
    return None


def save(dst, chunks):
    """Write chunks to dst atomically (no half-written files on Ctrl+C)."""
    tmp = dst + ".part"
    with open(tmp, "wb") as f:
        for c in chunks:
            f.write(c)
    os.replace(tmp, dst)


class Done:
    """Append-only record of finished builds: <build id>\t<status>\t<detail>."""
    FINAL = {"ok", "pe404", "norsds", "pdb404"}   # never worth retrying

    def __init__(self, path):
        self.path, self.lock, self.ids = path, threading.Lock(), set()
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    p = line.rstrip("\n").split("\t")
                    if len(p) >= 2 and p[1] in self.FINAL:
                        self.ids.add(p[0])

    def add(self, bid, status, detail=""):
        if status in self.FINAL:
            with self.lock, open(self.path, "a") as f:
                f.write(f"{bid}\t{status}\t{detail}\n")


def work(out, ts, sz):
    s = sess()
    bid = f"{ts:08X}{sz:X}"
    pe_url = f"{SYMSRV}/{EXE}/{bid}/{EXE}"
    r = s.get(pe_url, timeout=120)
    if r.status_code != 200:
        return bid, "pe404" if r.status_code == 404 else "pe_err", f"[pe {r.status_code}] {pe_url}"
    pe_bytes = r.content
    info = rsds(pe_bytes)
    if not info:
        return bid, "norsds", f"[no rsds] {pe_url}"
    name, key = info
    d = os.path.join(out, name, key)               # symstore layout
    os.makedirs(d, exist_ok=True)
    exe_dst, pdb_dst = os.path.join(d, EXE), os.path.join(d, name)
    if not os.path.exists(exe_dst):
        save(exe_dst, [pe_bytes])
    if os.path.exists(pdb_dst):
        return bid, "ok", f"[skip] {name}/{key}"
    with s.get(f"{SYMSRV}/{name}/{key}/{name}", timeout=300, stream=True) as r:
        if r.status_code != 200:
            return bid, "pdb404" if r.status_code == 404 else "pdb_err", f"[pdb {r.status_code}] {name}/{key}"
        save(pdb_dst, r.iter_content(CHUNK))
    return bid, "ok", f"[ok] {name}/{key}"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("out", nargs="?", default="ntoskrnl_pdbs")
    ap.add_argument("-j", "--workers", type=int, default=32)
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    done = Done(os.path.join(a.out, "done.tsv"))
    all_jobs = list(builds())
    jobs = [(ts, sz) for ts, sz in all_jobs if f"{ts:08X}{sz:X}" not in done.ids]
    print(f"{len(all_jobs)} unique ntoskrnl builds, {len(all_jobs) - len(jobs)} already done, "
          f"{len(jobs)} to fetch with {a.workers} workers")

    with ThreadPoolExecutor(a.workers) as ex:
        futs = {ex.submit(work, a.out, ts, sz): (ts, sz) for ts, sz in jobs}
        for i, f in enumerate(as_completed(futs), 1):
            try:
                bid, status, msg = f.result()
                done.add(bid, status, msg)
            except Exception as e:
                msg = f"[err] {futs[f][0]:08X}{futs[f][1]:X}: {e}"
            print(f"{i}/{len(jobs)} {msg}", flush=True)


if __name__ == "__main__":
    main()
