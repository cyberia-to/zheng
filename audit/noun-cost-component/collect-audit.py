from pathlib import Path
import gzip,hashlib,json,re,subprocess,platform
r=Path('/Users/master/cyber/.worktrees/selfhost-0.4-full-bootstrap');m=r/'measurements/node-cost';w=r/'zheng-node-cost';a=w/'audit/noun-cost-component'
sha=lambda b:hashlib.sha256(b).hexdigest()
frozen=json.loads((m/'frozen-source.json').read_text())
assert all(sha((w/p).read_bytes())==digest for p,digest in frozen['source_files'].items())
final=json.loads((m/'repaired-gates.json').read_text())
assert final[-1]['name']=='final-component-serde' and all(row['exit_code']==0 for row in final)
# Preserve each raw log exactly and bind both the compressed and raw forms.
files=[]
for p in sorted(m.glob('*.log')):
 raw=p.read_bytes();dest=a/(p.name+'.gz');dest.write_bytes(gzip.compress(raw,mtime=0))
 files.append({'name':dest.name,'raw_sha256':sha(raw),'raw_bytes':len(raw),'stored_sha256':sha(dest.read_bytes()),'stored_bytes':dest.stat().st_size})
for name in ['independent-review.json','frozen-source.json','final-source.json','exploratory-commands.json','family-created.json','clean-source.json','inputs.json','gates.json','clean-gates.json','repaired-gates.json','format-owned.json','manifest-repair.json','nox-formatting-recovery.json','tade-formatting-recovery.json','tade-formatting-reproduction.json','shared-checkouts-after-recovery.json','all-path-dependency-status.json','accidental-formatting-state.json','tade-prior-clean-receipt.md','run-gates.py','run-clean-gates.py','run-repaired-gates.py','prepare-family.py']:
 raw=(m/name).read_bytes();(a/name).write_bytes(raw);files.append({'name':name,'stored_sha256':sha(raw),'stored_bytes':len(raw)})
for name in ['nox-after-format.diff','tade-after-format.diff','lens-after-format.diff']:
 raw=(m/name).read_bytes();dest=a/(name+'.gz');dest.write_bytes(gzip.compress(raw,mtime=0));files.append({'name':dest.name,'raw_sha256':sha(raw),'raw_bytes':len(raw),'stored_sha256':sha(dest.read_bytes()),'stored_bytes':dest.stat().st_size})
prior=r/'trident/audit/self-hosting/bootstrap-results/run-36353842247/installation/receipt.json.gz'
raw=prior.read_bytes();assert sha(raw)==json.loads((m/'nox-formatting-recovery.json').read_text())['prior_receipt_sha256']
(a/'prior-clean-nox-receipt.json.gz').write_bytes(raw);files.append({'name':'prior-clean-nox-receipt.json.gz','stored_sha256':sha(raw),'stored_bytes':len(raw)})
# Summaries are derived from retained output, never substitute missing counters.
summaries=[]
for row in final:
 raw=Path(row['log']).read_bytes();assert sha(raw)==row['log_sha256']; text=raw.decode()
 counts=[tuple(map(int,x)) for x in re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)]
 assert not re.search(r'^warning:',text,re.M)
 summaries.append({'command':row['name'],'counts':dict(zip(['passed','failed','ignored'],map(sum,zip(*counts)))) if counts else None,'warning_lines':0})
log=(m/'final-component-serde.log').read_text()
footprint=re.search(r'node-cost-v1 rows_used=(\d+) ops_used=(\d+) padded_rows=(\d+) padded_columns=(\d+) nnz=(\d+) witness_bytes=(\d+)',log)
print(log) if footprint is None else None
assert footprint
metrics=dict(zip(['rows','operation_wires','padded_rows','padded_columns','sparse_entries','witness_bytes'],map(int,footprint.groups())))
timing=re.search(r'node-cost timing build_ns=(\d+) witness_ns=(\d+) prove_ns=(\d+) verify_ns=(\d+)',log);assert timing
metrics.update(dict(zip(['build_ns','witness_ns','prove_ns','verify_ns'],map(int,timing.groups()))))
size=re.search(r'postcard_proof_bytes=(\d+)',log);assert size;metrics['postcard_full_witness_proof_bytes']=int(size[1])
metrics['command']='final-component-serde';metrics['source_capture']='frozen-source.json plus manifest-repair.json';metrics['scope']='One local component, all six reads explicit public premises, existing full-witness CCS backend; single local timing observation'
(a/'receipt.json').write_text(json.dumps({'schema':1,'status':'local-component-gates-passed','base_revision':frozen['base_revision'],'source_capture':'frozen-source.json','manifest_repair':'manifest-repair.json','final_gate_receipt':'repaired-gates.json','gate_summaries':summaries,'measurement':metrics,'files':files,'platform':platform.platform(),'rustc':subprocess.check_output(['rustc','-Vv'],text=True),'cargo':subprocess.check_output(['cargo','-V'],text=True)},indent=2)+'\n')
# Independently round-trip every gzip mirror and check the immutable file index.
for row in files:
 raw=(a/row['name']).read_bytes();assert sha(raw)==row['stored_sha256']
 if 'raw_sha256' in row:assert sha(gzip.decompress(raw))==row['raw_sha256']
print(json.dumps({'metrics':metrics,'gates':summaries},indent=2))
