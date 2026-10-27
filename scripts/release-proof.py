# Release proof for a published lmaws release: python3 scripts/release-proof.py vX.Y.Z (repo root, tag checked out
# and built with mvn -q package). Downloads the release assets with gh, checks SHA256SUMS and the binaries (Windows may
# be missing only when the release notes say so), checks Linux linkage, runs the linux-x64 binary offline (--version,
# --self-test, --dsl-signatures --without-std equal to the local build of the same tag) and writes proof.json.
from pathlib import Path
import glob,hashlib,json,os,subprocess,sys,tempfile
tag=sys.argv[1] if len(sys.argv)>1 else ''
assert tag.startswith('v') and tag[1:].replace('.','').isdigit(),'usage: release-proof.py vX.Y.Z'
version=tag[1:]
root=Path(tempfile.mkdtemp(prefix='lmaws-release-'))
subprocess.run(['gh','release','download',tag,'--repo','lmctl-ai/lmaws','--dir',str(root)],check=True,timeout=300)
notes=subprocess.check_output(['gh','release','view',tag,'--repo','lmctl-ai/lmaws','--json','body','--jq','.body'],text=True,timeout=60)
expected={'lmaws-linux-x64','lmaws-linux-arm64','lmaws-macos-x64','lmaws-macos-arm64','lmaws-windows-x64.exe'}
records=[]
for line in (root/'SHA256SUMS').read_text().splitlines():
 digest,name=line.split();name=name.removeprefix('./');assert name in expected,name
 p=root/name;data=p.read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name
 records.append({'name':name,'bytes':len(data),'sha256':digest})
names={record["name"] for record in records}
missing=expected-names
assert not missing or (missing=={'lmaws-windows-x64.exe'} and 'no Windows binary' in notes),('missing assets',missing)
for name in ('lmaws-linux-x64','lmaws-linux-arm64'):
 subprocess.run(['python3','scripts/check-linux-linkage.py',str(root/name)],check=True,timeout=30)
binary=root/'lmaws-linux-x64';binary.chmod(0o755)
env={**os.environ,'LMAWS_LIVE':'0','LMAWS_SPEND_LIVE':'0','AWS_PROFILE':'default','CI':'true'}
assert subprocess.check_output([str(binary),'--version'],env=env,text=True,timeout=30).strip()=='lmaws '+version
checks=subprocess.check_output([str(binary),'--self-test'],env=env,text=True,timeout=300)
assert checks.count('PASS')>=10,checks
signatures=subprocess.check_output([str(binary),'--dsl-signatures','--without-std'],env=env,text=True,timeout=30)
jar=f'target/lmaws-{version}.jar'
assert os.path.exists(jar),'build the tag locally first (mvn -q package) so signatures can be compared'
local=subprocess.check_output(['java','-cp',jar,'ai.lmctl.lmaws.Main','--dsl-signatures','--without-std'],env=env,text=True,timeout=60)
assert signatures==local,'released signatures differ from the local build of '+tag
for signature in ['method Cloud.iam_role_get(string) -> Row','method Cloud.iam_role_put(string, string, bool) -> Row','method Cloud.iam_role_delete(string, bool) -> Row','method Lambda.wait_active(int) -> Row']:
 assert signature in signatures,signature
(root/'proof.json').write_text(json.dumps({'version':version,'assets':records,'windows_missing':bool(missing),'self_test_pass_lines':checks.count('PASS'),'own_signatures':len(signatures.splitlines()),'binary':str(binary)},indent=2)+'\n')
print('Proof:',root/'proof.json')
