#!/usr/bin/env python3
"""Independent cleanup checks must fail closed on denied/unknown responses."""
from unittest.mock import patch
from types import SimpleNamespace
from verify_absence import verify

def response(code,out='',err=''):
 return SimpleNamespace(returncode=code,stdout=out,stderr=err)
resource=[{'kind':'queue','name':'lmaws_test_queue'}]
with patch('verify_absence.subprocess.run',return_value=response(255,err='An error occurred (AWS.SimpleQueueService.NonExistentQueue) when calling GetQueueUrl')) as run:
 result=verify(resource);assert result[0]['absent']
 args=run.call_args;assert args.args[0][1:3]==['--profile','default'];assert args.kwargs['env']['AWS_PROFILE']=='default'
for error in ['AccessDenied','InvalidClientTokenId','InternalError']:
 with patch('verify_absence.subprocess.run',return_value=response(255,err='An error occurred ('+error+') when calling GetQueueUrl')):
  try:verify(resource)
  except RuntimeError as e:assert error in str(e)
  else:raise AssertionError('authorization/unknown error treated as absent')
with patch('verify_absence.subprocess.run',return_value=response(0,out='{"Parameters":[]}')):
 assert verify([{'kind':'parameter','name':'lmaws_test_parameter'}])[0]['absent']
try:verify([{'kind':'queue','name':'foreign'}])
except ValueError:pass
else:raise AssertionError('foreign prefix accepted')
print('PASS independent default-profile absence checks and authorization failures')
