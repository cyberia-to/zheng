import datetime, hashlib, json, os, pathlib, subprocess, time
root=pathlib.Path('/Users/master/cyber/.worktrees/selfhost-0.4-full-bootstrap')
out=root/'measurements/node-cost'; cwd=out/'family/zheng'; origin=root/'zheng-node-cost'
env=os.environ.copy(); env['CARGO_TARGET_DIR']=str(out/'target-clean')
rows=[]
def run(name,argv):
    row={'name':name,'argv':argv,'cwd':str(cwd),'env':{'CARGO_TARGET_DIR':env['CARGO_TARGET_DIR']},'start':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    start=time.monotonic(); log=out/(name+'.log')
    with log.open('xb') as f: row['exit_code']=subprocess.run(argv,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT).returncode
    raw=log.read_bytes()
    row.update(end=datetime.datetime.now(datetime.timezone.utc).isoformat(),wall_seconds=time.monotonic()-start,log=str(log),log_sha256=hashlib.sha256(raw).hexdigest())
    rows.append(row); (out/'clean-gates.json').write_text(json.dumps(rows,indent=2)+'\n')
    print(name,row['exit_code'],row['wall_seconds'],flush=True)
    return row['exit_code'],raw
# Confirm pre-existing default workspace example failure on unchanged clean base.
assert not subprocess.check_output(['git','status','--porcelain=v1'],cwd=cwd)
code,raw=run('clean-base-default',['cargo','test','--workspace','--release','--locked','--offline','--','--test-threads=4'])
assert code==101 and b'legacy_wire_cost.rs:29' in raw and b'TraceProof: serde::Serialize' in raw
frozen=json.loads((out/'frozen-source.json').read_text())
for name,digest in frozen['source_files'].items():
    raw=(origin/name).read_bytes(); assert hashlib.sha256(raw).hexdigest()==digest
    dest=cwd/name; dest.parent.mkdir(parents=True,exist_ok=True); dest.write_bytes(raw)
(out/'clean-source.json').write_text(json.dumps({'base':frozen['base_revision'],'source_files':frozen['source_files'],'family_path':str(cwd)},indent=2)+'\n')
commands=[
 ('clean-check-all',['cargo','check','--workspace','--all-targets','--all-features','--release','--locked','--offline']),
 ('clean-test-default-targets',['cargo','test','--workspace','--lib','--bins','--tests','--release','--locked','--offline','--','--test-threads=4']),
 ('clean-test-default-doc',['cargo','test','--workspace','--doc','--release','--locked','--offline']),
 ('clean-test-all-features',['cargo','test','--workspace','--release','--locked','--offline','--all-features','--','--test-threads=4']),
 ('clean-component-serde',['cargo','test','-p','zheng','--release','--locked','--offline','--features','serde','node_cost_tests','--','--nocapture']),
]
for name,argv in commands:
    code,_=run(name,argv)
    if code: break
