#!/usr/bin/env python3
"""No AWS/CLI access: fresh-session lookup logic fails closed on every error."""
from unittest.mock import patch
from verify_absence import verify
resource=[{'kind':'queue','name':'lmaws_test_queue'}]
with patch('verify_absence._invoke',return_value={'exists':False,'requests':1,'estimated_usd':'0.0000004'}) as invoke:
 result=verify(resource);assert result[0]['absent'] and result[0]['profile']=='default' and result[0]['engine']=='lmaws via lmctl'
 assert invoke.call_args.args[0]==resource[0]
for error in ['AccessDenied','InvalidClientTokenId','InternalError','missing cost receipt']:
 with patch('verify_absence._invoke',side_effect=RuntimeError(error)):
  try:verify(resource)
  except RuntimeError as e:assert error in str(e)
  else:raise AssertionError('authorization/unknown error became absence')
with patch('verify_absence._invoke',return_value={'exists':True,'requests':1,'estimated_usd':'0.0000004'}):
 try:verify(resource,timeout_seconds=0)
 except RuntimeError as e:assert 'still finds' in str(e)
 else:raise AssertionError('existing resource reported absent')
for name in ['foreign','lmaws\0unsafe']:
 try:verify([{'kind':'queue','name':name}])
 except ValueError:pass
 else:raise AssertionError('foreign/invalid resource accepted')
print('PASS lmaws-only independent absence checks, default profile, accounting and fail-closed errors')
