import datetime, hashlib, json, os, pathlib, subprocess, time
root=pathlib.Path('/Users/master/cyber/.worktrees/selfhost-0.4-full-bootstrap')
cwd=root/'zheng-node-cost'; out=root/'measurements/node-cost'
env=os.environ.copy(); env['CARGO_TARGET_DIR']=str(root/'target-node-cost')
commands=[
 ('check-all',['cargo','check','--workspace','--all-targets','--all-features','--release','--locked','--offline']),
 ('test-default',['cargo','test','--workspace','--release','--locked','--offline','--','--test-threads=4']),
 ('test-all-features',['cargo','test','--workspace','--release','--locked','--offline','--all-features','--','--test-threads=4']),
 ('component-serde',['cargo','test','-p','zheng','--release','--locked','--offline','--features','serde','node_cost_tests','--','--nocapture']),
]
rows=[]
for name,argv in commands:
    row={'name':name,'argv':argv,'cwd':str(cwd),'env':{'CARGO_TARGET_DIR':env['CARGO_TARGET_DIR']},'start':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    start=time.monotonic(); log=out/(name+'.log')
    with log.open('xb') as f: row['exit_code']=subprocess.run(argv,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT).returncode
    row.update(end=datetime.datetime.now(datetime.timezone.utc).isoformat(),wall_seconds=time.monotonic()-start,log=str(log),log_sha256=hashlib.sha256(log.read_bytes()).hexdigest())
    rows.append(row); (out/'gates.json').write_text(json.dumps(rows,indent=2)+'\n')
    print(name,row['exit_code'],row['wall_seconds'],flush=True)
    if row['exit_code']: break
