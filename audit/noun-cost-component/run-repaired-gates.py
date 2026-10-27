import datetime,hashlib,json,os,pathlib,subprocess,time
root=pathlib.Path('/Users/master/cyber/.worktrees/selfhost-0.4-full-bootstrap'); out=root/'measurements/node-cost'; origin=root/'zheng-node-cost'
frozen=json.loads((out/'frozen-source.json').read_text()); rows=[]
def snapshot():
 return {p.name:{'revision':subprocess.check_output(['git','-C',str(p),'rev-parse','HEAD'],text=True).strip(),'status':subprocess.check_output(['git','-C',str(p),'status','--porcelain=v1'],text=True)} for p in sorted((out/'family').iterdir()) if (p/'.git').is_file()}
def run(name,argv,cwd,target):
 before=snapshot(); assert all(not info['status'] for name,info in before.items() if name not in ['zheng','zheng-baseline'])
 env=os.environ.copy(); env['CARGO_TARGET_DIR']=str(target)
 row={'name':name,'argv':argv,'cwd':str(cwd),'env':{'CARGO_TARGET_DIR':str(target)},'family_before':before,'start':datetime.datetime.now(datetime.timezone.utc).isoformat()}
 start=time.monotonic(); log=out/(name+'.log')
 with log.open('xb') as f: row['exit_code']=subprocess.run(argv,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT).returncode
 raw=log.read_bytes(); after=snapshot(); assert before==after
 row.update(end=datetime.datetime.now(datetime.timezone.utc).isoformat(),wall_seconds=time.monotonic()-start,log=str(log),log_sha256=hashlib.sha256(raw).hexdigest(),family_after=after)
 rows.append(row); (out/'repaired-gates.json').write_text(json.dumps(rows,indent=2)+'\n'); print(name,row['exit_code'],row['wall_seconds'],flush=True)
 assert row['exit_code']==0,name
base=out/'family/zheng-baseline'; candidate=out/'family/zheng'
assert not subprocess.check_output(['git','status','--porcelain=v1'],cwd=base)
manifest=(origin/'rs/Cargo.toml').read_bytes(); (base/'rs/Cargo.toml').write_bytes(manifest)
(out/'manifest-repair.json').write_text(json.dumps({'base':frozen['base_revision'],'file':'rs/Cargo.toml','sha256':hashlib.sha256(manifest).hexdigest(),'diff':subprocess.check_output(['git','diff','--','rs/Cargo.toml'],cwd=base,text=True)},indent=2)+'\n')
check=['cargo','check','--workspace','--all-targets','--all-features','--release','--locked','--offline']
default=['cargo','test','--workspace','--release','--locked','--offline','--','--test-threads=4']
all_features=['cargo','test','--workspace','--release','--locked','--offline','--all-features','--','--test-threads=4']
run('repaired-base-check',check,base,out/'target-baseline')
run('repaired-base-default',default,base,out/'target-baseline')
# The first pre-repair clean test run remains untouched until its entire driver finishes.
while True:
 prior=json.loads((out/'clean-gates.json').read_text())
 if prior[-1]['name']=='clean-component-serde' and prior[-1]['exit_code']==0: break
 time.sleep(1)
for name,digest in frozen['source_files'].items():
 assert hashlib.sha256((candidate/name).read_bytes()).hexdigest()==digest
 assert hashlib.sha256((origin/name).read_bytes()).hexdigest()==digest
(candidate/'rs/Cargo.toml').write_bytes(manifest)
for name,argv in [('check',check),('default',default),('all-features',all_features)]: run('final-component-'+name,argv,candidate,out/'target-clean')
run('final-component-serde',['cargo','test','-p','zheng','--release','--locked','--offline','--features','serde','node_cost_tests','--','--nocapture'],candidate,out/'target-clean')
