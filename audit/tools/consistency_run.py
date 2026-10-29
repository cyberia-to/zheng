#!/usr/bin/env python3
"""Run (a) of audit/consistency-2026-10-27.md: a fresh stand executing the
README.md § build commands of origin/master exactly as written, then the
envelope SHA-256s. usage: consistency_run.py <n> <zheng-repo> [<out-dir>]
(<zheng-repo>: any clone with origin fetched; the run lands in
<out-dir>/zheng-run<n>, default /tmp, with its log beside it)"""
import os, re, subprocess, sys, time, hashlib
n = sys.argv[1]; repo = sys.argv[2]; base = os.path.join(sys.argv[3] if len(sys.argv) > 3 else "/tmp", f"zheng-run{n}")
subprocess.run(["rm", "-rf", base]); os.makedirs(base)
log = open(f"{base}.log", "w")
def sh(cmd, cwd):
    t = time.time(); log.write(f"\n$ {cmd}   (cwd {cwd})\n"); log.flush()
    r = subprocess.run(cmd, shell=True, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
    log.write(f"-> exit {r.returncode} in {time.time()-t:.1f} s\n"); log.flush()
    if r.returncode: print(f"run {n}: FAILED: {cmd}"); sys.exit(1)
# the README of origin/master, fetched raw, is the script
readme = subprocess.run(["git", "-C", repo, "show", "origin/master:README.md"], capture_output=True, text=True).stdout
build = readme.split("## build", 1)[1].split("\n## ", 1)[0]
blocks = re.findall(r"```\n(.*?)```", build, re.S)
assert len(blocks) == 2, blocks
log.write(f"run {n} start {time.strftime('%FT%TZ', time.gmtime())} load {os.getloadavg()}\n")
cwd = base
for line in blocks[0].strip().splitlines():
    if line.startswith("cd "): cwd = os.path.normpath(os.path.join(cwd, line[3:])); os.makedirs(cwd, exist_ok=True) if line.strip()=="cd zheng-stand" else None; log.write(f"\n$ {line}\n"); continue
    if line.startswith("mkdir "): os.makedirs(os.path.join(cwd, line[6:]), exist_ok=True); log.write(f"\n$ {line}\n"); continue
    sh(line, cwd)
head = subprocess.run(["git", "-C", cwd, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
log.write(f"\nzheng HEAD {head}\n")
envdir = f"{base}/env"; os.makedirs(envdir)
for line in blocks[1].strip().splitlines():
    if "envelope_profiles" in line: line = f"ZHENG_ENVELOPE_DIR={envdir} " + line
    sh(line, cwd)
for f in sorted(os.listdir(envdir)):
    h = hashlib.sha256(open(os.path.join(envdir, f), "rb").read()).hexdigest()
    log.write(f"sha256 {h} {f}\n")
log.write(f"run {n} end {time.strftime('%FT%TZ', time.gmtime())} load {os.getloadavg()}\n")
print(f"run {n}: ok, zheng {head[:7]}")
