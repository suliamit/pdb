#!/usr/bin/env python3
"""
Download every known ntoskrnl.exe PDB from the Microsoft symbol server.

The symbol server can't be enumerated, so build list comes from Winbindex
(timestamp + SizeOfImage per build). For each build:
  1. fetch ntoskrnl.exe from msdl by <TimeDateStamp><SizeOfImage>
  2. read the RSDS CodeView record (GUID, age, pdb name)
  3. fetch the PDB by <GUID><age>

pip install requests pefile
"""
import gzip, json, os, sys, threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import pefile
import requests

WINBINDEX = "https://winbindex.m417z.com/data/by_filename_compressed/ntoskrnl.exe.json.gz"
SYMSRV = "https://msdl.microsoft.com/download/symbols"
OUT = sys.argv[1] if len(sys.argv) > 1 else "ntoskrnl_pdbs"
WORKERS = 8
HDRS = {"User-Agent": "Microsoft-Symbol-Server/10.0.0.0"}

_tls = threading.local()
def sess():
    if not hasattr(_tls, "s"):
        _tls.s = requests.Session()
        _tls.s.headers.update(HDRS)
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


def work(ts, sz):
    s = sess()
    pe_url = f"{SYMSRV}/ntoskrnl.exe/{ts:08X}{sz:X}/ntoskrnl.exe"
    r = s.get(pe_url, timeout=120)
    if r.status_code != 200:
        return f"[pe {r.status_code}] {pe_url}"
    info = rsds(r.content)
    if not info:
        return f"[no rsds] {pe_url}"
    name, key = info
    dst = os.path.join(OUT, name, key, name)   # symstore layout
    if os.path.exists(dst):
        return f"[skip] {name}/{key}"
    r = s.get(f"{SYMSRV}/{name}/{key}/{name}", timeout=300, stream=True)
    if r.status_code != 200:
        return f"[pdb {r.status_code}] {name}/{key}"
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = dst + ".part"
    with open(tmp, "wb") as f:
        for chunk in r.iter_content(1 << 20):
            f.write(chunk)
    os.replace(tmp, dst)
    return f"[ok] {name}/{key}"


def main():
    jobs = list(builds())
    print(f"{len(jobs)} unique ntoskrnl builds")
    with ThreadPoolExecutor(WORKERS) as ex:
        futs = [ex.submit(work, ts, sz) for ts, sz in jobs]
        for i, f in enumerate(as_completed(futs), 1):
            try:
                msg = f.result()
            except Exception as e:
                msg = f"[err] {e}"
            print(f"{i}/{len(jobs)} {msg}", flush=True)


if __name__ == "__main__":
    main()
