from pathlib import Path
import subprocess,json
r=Path('/Users/master/cyber/.worktrees/selfhost-0.4-full-bootstrap'); old=r/'semantic-observer-integration'; out=r/'measurements/node-cost'; family=out/'family'; family.mkdir()
rows=[]
for name in ['strata','hemera','lens','nox','bbg','neuron','trident','joy','tade','zheng']:
 source=old/name
 if name=='tade': source=(r/name).resolve()
 if name=='zheng': source=r/'zheng-node-cost'
 revision=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
 argv=['git','-C',str(source),'worktree','add','--detach',str(family/name),revision]
 subprocess.run(argv,check=True)
 assert not subprocess.check_output(['git','-C',str(family/name),'status','--porcelain=v1'])
 rows.append({'name':name,'source':str(source),'revision':revision,'argv':argv,'initial_status':''})
(out/'family-created.json').write_text(json.dumps(rows,indent=2)+'\n')
