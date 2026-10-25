#!/usr/bin/env python3
"""Pin every resolved runtime JAR by content, independently of Maven's local cache."""
import hashlib,json,os,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
paths=Path(root/'target/dependency-classpath.txt').read_text(encoding="utf-8").strip().split(os.pathsep)
actual={Path(p).name:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths}
assert not any(x in name for name in actual for x in ['apache5-client','apache-client','netty','aws-crt']), 'unexpected native/default HTTP transport'
lock=root/'deps.lock';data=json.loads(lock.read_text(encoding="utf-8"))
if '--update' in sys.argv:
 data['runtime_jars_sha256']=dict(sorted(actual.items()));lock.write_text(json.dumps(data,indent=2)+'\n')
else: assert actual==data['runtime_jars_sha256'], 'dependency artifacts differ from deps.lock'
print('PASS',len(actual),'pinned runtime jars')
