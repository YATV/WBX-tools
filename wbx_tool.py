#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MikroTik Winbox WBX editor (robust: stream + L2/L1/L0) with CSV preview/export/import

Features:
- Correctly parses WBX (signature 0F 10 C0 BE), records separated by 00 00.
- Supports 3 TLV layouts: L2 (2-byte total len), L1 (len+0x00), L0 (len).
- List records (pretty or raw hex), hide secrets option.
- Point edits by host: --set-login / --set-pass / --set-keep.
- Batch edits from CSV onto an existing WBX: --csv host,login,password,keep (updates existing hosts only).
- Mass replace by login across ALL records: --replace-login OLD NEWLOGIN NEWPASS
  *NEW*: --replace-mode replace|add (default: replace)
- CSV export: --export-csv path
- CSV import (build WBX from CSV): --import-csv path (requires --out)
- CSV preview/analysis without changing anything: --preview-csv path
  with --preview-limit N (0 = show all)

CSV columns supported (case-insensitive):
  group, host, login, password, keep, note, type, secure-mode

Notes:
- Import: if password is set and keep not provided, keep defaults to 1.
- Export: fields are the last non-empty value per key within each record.
- Preview: prints delimiter detection, total rows, missing-host count, and shows first rows.

WebSite: https://github.com/YATV/WBX-tools/
Autor: Taras Yanchuk
You can say thank you here: https://www.patreon.com/YATV

2025.09.17
"""

import argparse, csv, binascii
from typing import List, Tuple

SIG = b"\x0F\x10\xC0\xBE"
REC_SEP = b"\x00\x00"

# ---------------- TLV decoders (three layouts) ----------------

def _try_L2(b,i,n):
    if i+3>n: return None
    total = b[i] | (b[i+1]<<8)
    klen  = b[i+2]
    end   = (i+2)+total
    if end>n or klen==0 or klen>total-1: return None
    start = i+3
    key = b[start:start+klen]; val = b[start+klen:end]
    return (end,key,val)

def _try_L1(b,i,n):
    if i+3>n: return None
    total = b[i]
    if b[i+1]!=0x00 or i+1+total>n: return None
    klen  = b[i+2]
    start = i+3; end = i+1+total
    if klen==0 or klen>(end-start): return None
    key = b[start:start+klen]; val = b[start+klen:end]
    return (end,key,val)

def _try_L0(b,i,n):
    if i+2>n: return None
    total = b[i]
    end   = i+1+total
    if end>n: return None
    klen  = b[i+1]
    if klen==0 or klen>total-1: return None
    start = i+2
    key = b[start:start+klen]; val = b[start+klen:end]
    return (end,key,val)

# ---------------- parse/build ----------------

def parse_record(buf: bytes) -> List[Tuple[bytes,bytes]]:
    out=[]; i=0; n=len(buf)
    while i<n:
        r=None
        for probe in (_try_L2,_try_L1,_try_L0):
            r=probe(buf,i,n)
            if r: break
        if r:
            end,key,val=r
            out.append((key,val)); i=end
        else:
            if buf[i] in (0x00,0x0a,0x0d,0x09): i+=1
            else: i+=1
    return out

def parse_wbx(data: bytes):
    assert data.startswith(SIG), "WBX signature mismatch"
    body = data[len(SIG):]
    recs=[]; i=0; n=len(body); cur=[]
    while i<n:
        if i+1<n and body[i]==0x00 and body[i+1]==0x00:
            if cur: recs.append(cur); cur=[]
            i+=2; continue
        r=None
        for probe in (_try_L2,_try_L1,_try_L0):
            r=probe(body,i,n)
            if r: break
        if r:
            end,key,val=r
            cur.append((key,val)); i=end; continue
        if body[i] in (0x00,0x0a,0x0d,0x09): i+=1
        else: i+=1
    if cur: recs.append(cur)
    return recs

def build_record(kv):
    out=bytearray()
    for k,v in kv:
        if isinstance(k,str): k=k.encode('utf-8')
        if isinstance(v,str): v=v.encode('utf-8')
        total = 1 + len(k) + len(v)
        out += bytes((total & 0xFF, (total>>8)&0xFF, len(k)))
        out += k + v
    return bytes(out)

def build_wbx(recs):
    out=bytearray(SIG); first=True
    for kv in recs:
        if not first: out += REC_SEP
        first=False
        out += build_record(kv)
    out += REC_SEP
    return bytes(out)

# ---------------- helpers ----------------

def b2s(b):
    try: return b.decode('utf-8')
    except: return b.decode('latin1',errors='replace')

def list_records(recs, raw=False, hide=False):
    for idx,kv in enumerate(recs):
        print(f"[{idx}]")
        for k,v in kv:
            ks=b2s(k)
            if raw:
                print(f"  {ks:12} len={len(v):3} hex={binascii.hexlify(v).decode()}")
            else:
                vs=b2s(v)
                if hide and ks=='pwd': vs='<hidden>'
                print(f"  {ks:12} = {vs}")
        print()
    print(f"Total records: {len(recs)}")

def set_field(recs, host, field_key: bytes, new_val: bytes):
    if isinstance(new_val,str): new_val=new_val.encode('utf-8')
    changed=0
    for kv in recs:
        host_val=None
        for k,v in kv:
            if k==b'host': host_val=b2s(v); break
        if host_val==host:
            found=False
            for i,(k,v) in enumerate(kv):
                if k==field_key:
                    kv[i]=(k,new_val); found=True
            if not found:
                kv.append((field_key,new_val))
            changed+=1
    return changed

def apply_csv(recs, path):
    changes=0
    with open(path, newline='', encoding='utf-8') as f:
        rdr=csv.DictReader(f)
        use_pos = not rdr.fieldnames or not set(h.lower() for h in rdr.fieldnames)&{"host","login","password","keep"}
        if use_pos:
            f.seek(0)
            for row in csv.reader(f):
                if not row: continue
                host=row[0].strip() if len(row)>0 else ""
                login=row[1].strip() if len(row)>1 else ""
                pwd  =row[2].strip() if len(row)>2 else ""
                keep =row[3].strip() if len(row)>3 else ""
                if host:
                    if login: changes+=set_field(recs,host,b'login',login)
                    if pwd:   changes+=set_field(recs,host,b'pwd',pwd); changes+=set_field(recs,host,b'keep-pwd',b'\x01')
                    if keep!="":
                        flag=b'\x01' if keep.lower() in ("1","true","yes","y") else b""
                        changes+=set_field(recs,host,b'keep-pwd',flag)
        else:
            for row in rdr:
                host =(row.get("host") or "").strip()
                login=(row.get("login") or "").strip()
                pwd  =(row.get("password") or "").strip()
                keep =(row.get("keep") or "").strip()
                if host:
                    if login: changes+=set_field(recs,host,b'login',login)
                    if pwd:   changes+=set_field(recs,host,b'pwd',pwd); changes+=set_field(recs,host,b'keep-pwd',b'\x01')
                    if keep!="":
                        flag=b'\x01' if keep.lower() in ("1","true","yes","y") else b""
                        changes+=set_field(recs,host,b'keep-pwd',flag)
    return changes

# ---------- replace-by-login with mode (replace|add) ----------

def _dedupe_preserve_first(kv: List[Tuple[bytes,bytes]]):
    """Keep only the first occurrence of each key (preserve field order)."""
    seen=set(); out=[]
    for k,v in kv:
        if k in seen: continue
        seen.add(k); out.append((k,v))
    return out

def _clone_with_updates(kv: List[Tuple[bytes,bytes]], updates: dict) -> List[Tuple[bytes,bytes]]:
    """
    Return a new record based on kv, but applying updates to keys in 'updates'.
    Ensures single occurrence per key (dedupe), preserving original field order.
    """
    out=[]
    updated_keys=set()
    for k,v in kv:
        ks = k.decode('utf-8','ignore') if isinstance(k,bytes) else str(k)
        if ks in updates:
            nv = updates[ks]
            if isinstance(nv,str): nv = nv.encode('utf-8')
            out.append((k, nv))
            updated_keys.add(ks)
        else:
            out.append((k, v))
    # Append new keys that weren't present
    for ks, nv in updates.items():
        if ks not in updated_keys:
            kb = ks.encode('utf-8'); vb = nv.encode('utf-8') if isinstance(nv,str) else nv
            out.append((kb, vb))
    # Deduplicate keys (keep first)
    return _dedupe_preserve_first(out)

def replace_by_login(recs, old_login: str, new_login: str, new_pass: str, set_keep=True, mode="replace"):
    """
    For all records with login == old_login:
      - mode='replace' : modify in-place (update login/pwd/keep-pwd)
      - mode='add'     : append a *new* record cloned from the original but with updated fields
    Returns number of records affected (i.e., modified or added).
    """
    changed = 0
    for kv in list(recs):  # iterate over a snapshot; we may append
        cur_login = None
        for k,v in kv:
            if k == b'login':
                cur_login = b2s(v); break
        if cur_login != old_login:
            continue

        updates = {"login": new_login, "pwd": new_pass}
        if set_keep:
            updates["keep-pwd"] = b"\x01"

        if mode == "add":
            new_kv = _clone_with_updates(kv, updates)
            recs.append(new_kv)
            changed += 1
        else:  # replace (default)
            # in-place update: rewrite all existing occurrences, add if missing
            has_login = has_pwd = has_keep = False
            for i,(k,v) in enumerate(kv):
                if k == b'login':
                    kv[i] = (k, new_login.encode('utf-8')); has_login = True
                elif k == b'pwd':
                    kv[i] = (k, new_pass.encode('utf-8')); has_pwd = True
                elif k == b'keep-pwd' and set_keep:
                    kv[i] = (k, b"\x01"); has_keep = True
            if not has_login: kv.append((b'login', new_login))
            if not has_pwd:   kv.append((b'pwd',   new_pass))
            if set_keep and not has_keep: kv.append((b'keep-pwd', b"\x01"))
            # also dedupe keys to avoid duplicates left by weird source files
            deduped = _dedupe_preserve_first(kv)
            kv[:] = deduped
            changed += 1
    return changed

# ---------------- CSV import/export/preview ----------------

EXPORT_COLUMNS = ["group","host","login","password","keep","note","type","secure-mode"]

def export_csv(recs, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=EXPORT_COLUMNS)
        w.writeheader()
        for kv in recs:
            last={}
            for k,v in kv:
                ks=b2s(k)
                if v: last[ks]=v
                elif ks not in last: last[ks]=v
            row = {
                "group":       (last.get("group") or b"").decode("utf-8","ignore") if last.get("group") is not None else "",
                "host":        (last.get("host") or b"").decode("utf-8","ignore") if last.get("host") is not None else "",
                "login":       (last.get("login") or b"").decode("utf-8","ignore") if last.get("login") is not None else "",
                "password":    (last.get("pwd")   or b"").decode("utf-8","ignore") if last.get("pwd")   is not None else "",
                "keep":        "1" if (last.get("keep-pwd")==b"\x01") else ("0" if last.get("keep-pwd") is not None else ""),
                "note":        (last.get("note")  or b"").decode("utf-8","ignore") if last.get("note")  is not None else "",
                "type":        (last.get("type")  or b"").decode("utf-8","ignore") if last.get("type")  is not None else "",
                "secure-mode": (last.get("secure-mode") or b"").decode("utf-8","ignore") if last.get("secure-mode") is not None else "",
            }
            w.writerow(row)

def _clean_controls(s: str) -> str:
    return ''.join(ch for ch in s if ch >= ' ' or ch in '\t\r\n')

def _sniff_csv(path):
    with open(path, 'r', encoding='utf-8', newline='') as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=',;|\t')
        except Exception:
            class _D: delimiter = ','
            dialect = _D()
        rdr = csv.DictReader(f, dialect=dialect)
        headers = []
        if rdr.fieldnames:
            headers = [(h or '').lstrip('\ufeff').strip() for h in rdr.fieldnames]
        return dialect, headers

def import_csv(path):
    recs=[]
    with open(path, 'r', encoding='utf-8', newline='') as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=',;|\t')
        except Exception:
            class _D: delimiter = ','
            dialect = _D()
        rdr = csv.DictReader(f, dialect=dialect)
        if rdr.fieldnames:
            rdr.fieldnames = [(h or '').lstrip('\ufeff').strip().lower() for h in rdr.fieldnames]
        for row in rdr:
            r = { (k or '').strip().lower(): _clean_controls((v or '').strip())
                  for k, v in row.items() }
            host  = r.get('host','')
            if not host:
                continue
            group = r.get('group','')
            login = r.get('login','')
            pwd   = r.get('password','')
            keep  = r.get('keep','')
            note  = r.get('note','')
            typ   = r.get('type','')
            sec   = r.get('secure-mode','')

            kv = []
            if group: kv.append((b"group", group))
            kv.append((b"host", host))
            if login: kv.append((b"login", login))
            if note:  kv.append((b"note", note))
            if typ:   kv.append((b"type", typ))
            if sec != "": kv.append((b"secure-mode", sec))
            if pwd != "":
                kv.append((b"pwd", pwd))
                if keep == "":
                    keep = "1"
            if keep != "":
                flag = b"\x01" if keep.lower() in ("1","true","yes","y") else b""
                kv.append((b"keep-pwd", flag))
            recs.append(kv)
    return recs

def preview_csv(path, limit=20):
    dialect, headers = _sniff_csv(path)
    print(f"Detected delimiter: '{getattr(dialect,'delimiter',',')}'")
    print("Headers:", headers if headers else "(none)")
    total_rows = 0
    rows_missing_host = 0
    first_rows = []
    with open(path, 'r', encoding='utf-8', newline='') as f:
        rdr = csv.DictReader(f, dialect=dialect)
        if rdr.fieldnames:
            rdr.fieldnames = [(h or '').lstrip('\ufeff').strip().lower() for h in rdr.fieldnames]
        for row in rdr:
            total_rows += 1
            r = { (k or '').strip().lower(): _clean_controls((v or '').strip())
                  for k, v in row.items() }
            if not r.get('host'):
                rows_missing_host += 1
            if limit <= 0 or len(first_rows) < limit:
                first_rows.append(r)
    print(f"Rows (excluding header): {total_rows}")
    print(f"Rows missing 'host':    {rows_missing_host}")
    if first_rows:
        print("\nFirst rows:")
        for i, r in enumerate(first_rows, 1):
            print(f"#{i}  " + ", ".join(f"{k}={r.get(k,'')}" for k in
                  ["group","host","login","password","keep","note","type","secure-mode"]))

# ---------------- CLI ----------------

def main():
    ap=argparse.ArgumentParser(description="WBX editor (robust) with CSV preview/export/import")
    ap.add_argument("--in", dest="infile", help="Input WBX (for list/edit/export)")
    ap.add_argument("--list", action="store_true", help="List human-readable")
    ap.add_argument("--list-raw", action="store_true", help="List with lengths + hex")
    ap.add_argument("--hide-secrets", action="store_true", help="Hide pwd in --list")
    ap.add_argument("--out", dest="outfile", help="Output WBX when modifying or importing")
    ap.add_argument("--set-login", nargs=2, metavar=("HOST","NEW_LOGIN"))
    ap.add_argument("--set-pass",  nargs=2, metavar=("HOST","NEW_PWD"))
    ap.add_argument("--set-keep",  nargs=2, metavar=("HOST","0|1"))
    ap.add_argument("--csv",       dest="csvfile", help="Apply changes from CSV onto existing WBX")
    ap.add_argument("--replace-login", nargs=3, metavar=("OLDLOGIN","NEWLOGIN","NEWPASS"),
                    help="Mass replace: all records with login=OLDLOGIN get NEWLOGIN/NEWPASS and keep-pwd=1")
    ap.add_argument("--replace-mode", choices=["replace","add"], default="replace",
                    help="Behavior for --replace-login: 'replace' (modify in place) or 'add' (append new records)")
    ap.add_argument("--export-csv", dest="export_csv", help="Export current WBX to CSV")
    ap.add_argument("--import-csv", dest="import_csv", help="Build WBX from CSV (requires --out)")
    ap.add_argument("--preview-csv", dest="preview_csv", help="Preview CSV content/health without importing")
    ap.add_argument("--preview-limit", type=int, default=20,
                    help="How many rows to show in --preview-csv (0 = all)")
    args=ap.parse_args()

    # CSV preview (no file changes)
    if args.preview_csv:
        preview_csv(args.preview_csv, limit=args.preview_limit)
        return

    # CSV -> WBX import (no --in needed). Alias: --csv without --in means import-from-CSV.
    if args.import_csv or (args.csvfile and not args.infile):
        path = args.import_csv or args.csvfile
        assert args.outfile, "--out is required for CSV import"
        new_recs = import_csv(path)
        out_bytes = build_wbx(new_recs)
        with open(args.outfile, "wb") as f: f.write(out_bytes)
        print(f"Built WBX from CSV rows: {len(new_recs)}")
        print(f"Wrote: {args.outfile}")
        return

    # Everything else requires an input WBX
    assert args.infile, "--in is required unless using --import-csv/--preview-csv"

    data=open(args.infile,"rb").read()
    recs=parse_wbx(data)

    # listing/export only
    if args.export_csv and not any([args.set_login,args.set_pass,args.set_keep,args.csvfile,args.replace_login,args.outfile,args.list,args.list_raw]):
        export_csv(recs, args.export_csv)
        print(f"Exported CSV: {args.export_csv}")
        return

    if args.list or args.list_raw or not any([args.set_login,args.set_pass,args.set_keep,args.csvfile,args.replace_login,args.export_csv]):
        if args.export_csv:
            export_csv(recs, args.export_csv)
            print(f"Exported CSV: {args.export_csv}")
        list_records(recs, raw=args.list_raw, hide=args.hide_secrets)
        return

    # Modifications on existing WBX
    total_changes=0
    if args.csvfile and args.infile:
        total_changes += apply_csv(recs, args.csvfile)

    if args.replace_login:
        oldl,newl,newp = args.replace_login
        total_changes += replace_by_login(
            recs, oldl, newl, newp, set_keep=True, mode=args.replace_mode
        )

    if args.set_login:
        total_changes += set_field(recs, args.set_login[0], b'login', args.set_login[1])
    if args.set_pass:
        total_changes += set_field(recs, args.set_pass[0], b'pwd', args.set_pass[1])
        total_changes += set_field(recs, args.set_pass[0], b'keep-pwd', b'\x01')
    if args.set_keep:
        flag = b'\x01' if args.set_keep[1]=='1' else b""
        total_changes += set_field(recs, args.set_keep[0], b'keep-pwd', flag)

    assert args.outfile, "No output specified. Use --out out.WBX to write modified file."
    out_bytes=build_wbx(recs)
    with open(args.outfile,"wb") as f: f.write(out_bytes)
    print(f"Modified records: {total_changes}")
    print(f"Wrote: {args.outfile}")

if __name__=="__main__":
    main()
