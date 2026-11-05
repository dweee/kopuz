#!/usr/bin/env python3
"""Token-source protocol for niks3; stdout is consumed only by the client."""
import base64
from datetime import datetime, timezone
import json
import os
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen


def token():
    if os.environ.get('GITHUB_SERVER_URL') != 'https://github.com' or os.environ.get('GITHUB_EVENT_NAME') not in {'push','workflow_dispatch','schedule'}:
        raise ValueError('Untrusted event')
    url=urlsplit(os.environ['ACTIONS_ID_TOKEN_REQUEST_URL'])
    if url.scheme != 'https' or not url.hostname or not url.hostname.endswith('.actions.githubusercontent.com') or url.username or url.password:
        raise ValueError('Unexpected token service')
    query=dict(parse_qsl(url.query)); query['audience']='https://niks3.monke.fail'
    request=Request(urlunsplit(url._replace(query=urlencode(query))), headers={'Authorization':'Bearer '+os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})
    with urlopen(request, timeout=30) as response:
        value=json.load(response)['value']
    if not isinstance(value,str) or len(value)>32768 or len(value.split('.'))!=3 or any(c.isspace() for c in value):
        raise ValueError('Invalid OIDC response')
    claims=json.loads(base64.urlsafe_b64decode(value.split('.')[1]+'='*(-len(value.split('.')[1])%4)))
    expires=datetime.fromtimestamp(claims['exp'],timezone.utc).isoformat().replace('+00:00','Z')
    return {'token':value,'expires_at':expires}


if __name__ == '__main__':
    try:
        print(json.dumps(token()))
    except Exception:
        print('GitHub OIDC acquisition failed; credentials withheld.',file=sys.stderr)
        sys.exit(1)
