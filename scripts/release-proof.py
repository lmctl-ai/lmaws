# Release proof for a published lmaws release (run from the repo root after the release is up):
# downloads the release assets with gh, checks SHA256SUMS and the five expected binaries, checks Linux linkage,
# runs the linux-x64 binary offline (--version, --self-test, --dsl-signatures --without-std) and writes proof.json.
# The version and the expected counts below are those of v0.1.18; update all three for the next release.
from pathlib import Path
import hashlib,json,os,subprocess,tempfile
root=Path(tempfile.mkdtemp(prefix='lmaws-spend-release-'))
subprocess.run(['gh','release','download','v0.1.18','--repo','lmctl-ai/lmaws','--dir',str(root)],check=True,timeout=300)
expected={'lmaws-linux-x64','lmaws-linux-arm64','lmaws-macos-x64','lmaws-macos-arm64','lmaws-windows-x64.exe'}
records=[]
for line in (root/'SHA256SUMS').read_text().splitlines():
 digest,name=line.split();name=name.removeprefix('./');assert name in expected,name
 p=root/name;data=p.read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name
 records.append({'name':name,'bytes':len(data),'sha256':digest})
assert len(records)==5 and {record["name"] for record in records}==expected
for name in ('lmaws-linux-x64','lmaws-linux-arm64'):
 subprocess.run(['python3','scripts/check-linux-linkage.py',str(root/name)],check=True,timeout=30)
binary=root/'lmaws-linux-x64';binary.chmod(0o755)
env={**os.environ,'LMAWS_LIVE':'0','LMAWS_SPEND_LIVE':'0','AWS_PROFILE':'default','CI':'true'}
assert subprocess.check_output([str(binary),'--version'],env=env,text=True,timeout=30).strip()=='lmaws 0.1.18'
checks=subprocess.check_output([str(binary),'--self-test'],env=env,text=True,timeout=120)
assert '188 spend arithmetic' in checks,checks
assert '38 Lambda role trust/boundary/ownership/diff/guard controls' in checks,checks
assert len(subprocess.check_output([str(binary),'--dsl-signatures','--without-std'],env=env,text=True,timeout=30).splitlines())==179
signatures=subprocess.check_output([str(binary),'--dsl-signatures','--without-std'],env=env,text=True,timeout=30)
for signature in ['method Cloud.iam_role_get(string) -> Row','method Cloud.iam_role_put(string, string, bool) -> Row','method Cloud.iam_role_delete(string, bool) -> Row','method Lambda.wait_active(int) -> Row']:
 assert signature in signatures,signature
(root/'proof.json').write_text(json.dumps({'version':'0.1.18','assets':records,'native_fake_assertions':188,'own_signatures':179,'binary':str(binary)},indent=2)+'\n')
print('Proof:',root/'proof.json')
