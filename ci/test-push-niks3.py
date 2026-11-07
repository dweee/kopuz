#!/usr/bin/env python3
"""Credential-free Niks3 publication and OIDC isolation regression checks."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

CI=Path(__file__).parent

def load(name):
    spec=importlib.util.spec_from_file_location(name,CI/(name+'.py'))
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

publisher=load('push-niks3')

class Publication(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.manifest=self.root/'outputs'
        self.path='/nix/store/'+'a'*32+'-fixture';self.manifest.write_text(self.path+'\n')
        self.bin=self.root/'niks3';self.bin.write_text('#!/bin/sh\nexit 0\n');self.bin.chmod(0o700)
        self.env={'NIKS3_BIN':str(self.bin),'RUNNER_TEMP':str(self.root),'NIKS3_WRITE_TOKEN':'s'*64}
    def test_private_file_auth_integrity_and_cleanup(self):
        files=[]
        def inspect(args,**kw):
            self.assertIn('--verify-s3-integrity',args);self.assertEqual(args[-1],self.path)
            self.assertNotIn('NIKS3_WRITE_TOKEN',kw['env'])
            file=Path(args[args.index('--auth-token-path')+1]);files.append(file)
            self.assertEqual(file.read_text(),'s'*64);self.assertEqual(file.stat().st_mode&0o777,0o600)
            return subprocess.CompletedProcess(args,0,'','')
        with patch.dict(os.environ,self.env,clear=True),patch.object(publisher.subprocess,'run',side_effect=inspect):publisher.publish(self.manifest)
        self.assertTrue(files);self.assertTrue(all(not f.exists() for f in files))
    def test_oidc_without_static_secrets(self):
        env={k:v for k,v in self.env.items() if k!='NIKS3_WRITE_TOKEN'}
        env.update(GITHUB_SERVER_URL='https://github.com',GITHUB_EVENT_NAME='push')
        with patch.dict(os.environ,env,clear=True),patch.object(publisher.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')) as run:
            publisher.publish(self.manifest)
        self.assertIn('--auth-token-script',run.call_args.args[0]);self.assertNotIn('--auth-token-path',run.call_args.args[0])
    def test_github_pr_or_private_credentials_fail_closed(self):
        for extra in [{'GITHUB_EVENT_NAME':'pull_request'},{'GITHUB_EVENT_NAME':'push','NIKS3_READ_NETRC':'fixture'}]:
            env=self.env|{'GITHUB_SERVER_URL':'https://github.com'}|extra
            with patch.dict(os.environ,env,clear=True),patch.object(publisher.subprocess,'run') as run:
                with self.assertRaises(ValueError):publisher.publish(self.manifest)
                run.assert_not_called()
    def test_failure_never_succeeds(self):
        with patch.dict(os.environ,self.env,clear=True),patch.object(publisher.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','denied')):
            with self.assertRaises(publisher.PublicationFailure):publisher.publish(self.manifest)
    def test_bad_manifest_or_destination_never_runs(self):
        for text in ['',self.path+'.drv\n','/tmp/arbitrary\n']:
            self.manifest.write_text(text)
            with patch.dict(os.environ,self.env,clear=True),patch.object(publisher.subprocess,'run') as run:
                with self.assertRaises(ValueError):publisher.publish(self.manifest)
                run.assert_not_called()
    def test_diagnostics_classify_without_exposing_credentials(self):
        for message, category, retry in [
            ('Unauthorized bearer synthetic-secret', 'authentication-rejected', False),
            ('hash mismatch presigned-url', 'integrity-mismatch', False),
            ('HTTP 503 ServiceUnavailable', 'service-unavailable', True),
            ('connection reset token=synthetic-secret', 'transport', True),
            ('unknown error token=synthetic-secret', 'publisher-rejected', False),
        ]:
            self.assertEqual(publisher.failure_category(message), (category, retry))

    def test_missing_optional_summary_does_not_relabel_success(self):
        env=self.env|{'GITHUB_STEP_SUMMARY':str(self.root/'absent/summary')}
        with patch.dict(os.environ,env,clear=True),patch.object(publisher.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','')):
            publisher.publish(self.manifest)

    def test_oidc_json_protocol_and_audience(self):
        mod=load('niks3-oidc-token'); import base64
        value='header.'+base64.urlsafe_b64encode(json.dumps({'exp':2000000000}).encode()).decode().rstrip('=')+'.signature'
        from unittest.mock import MagicMock
        response=MagicMock();response.__enter__.return_value.read.return_value=json.dumps({'value':value}).encode()
        env={'GITHUB_SERVER_URL':'https://github.com','GITHUB_EVENT_NAME':'push','ACTIONS_ID_TOKEN_REQUEST_URL':'https://run.actions.githubusercontent.com/token?api-version=2','ACTIONS_ID_TOKEN_REQUEST_TOKEN':'fixture'}
        with patch.dict(os.environ,env,clear=True),patch.object(mod,'urlopen',return_value=response) as fetch:
            result=mod.token()
        self.assertEqual(result['token'],value);self.assertIn('expires_at',result)
        self.assertIn('audience=https%3A%2F%2Fniks3.monke.fail',fetch.call_args.args[0].full_url)

if __name__=='__main__':unittest.main()
