"""Read-only all-label PC audit. Secret subscription/configuration remains RAM.

Uses an existing owned technical account and actual Windows device headers.
The main explicitly authorized implicit HWID enrollment for THIS owned probe
only, matching its normal subscription test; never creates another user,
changes panel objects, reloads an app, saves a subscription or accepts proofs.
Only safe per-label diagnostic outcomes are printed. Main owns publication.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

import operator_session as o
import preflight as p

REMOTE = r'''
import frontend_stage as f
api,_=p.load_file('pc_audit_read_api',p.ROOT.parent/'selfsteal-us3'/'panel_api.py').create_client()
user=p.probe_user(api,p.Store())
headers=json.load(sys.stdin)['headers']
devices=api('GET','/api/hwid/devices/'+user['uuid'])['devices']
device_preexisting=any(d.get('hwid')==headers['x-hwid'] for d in devices)
hosts=api('GET','/api/hosts/')
pending_ids={t['host'] for t in p.TARGETS if t['id'] in ('at','pl','cz','gbpower')}|{p.AUTOS[t] for t in ('at','pl','cz','gbpower') if p.AUTOS[t]}
pending=[h['remark'] for h in hosts if h['uuid'] in pending_ids]
sub=api('GET','/api/subscriptions/by-uuid/'+user['uuid'])
fresh=f.fetch_subscription(sub['subscriptionUrl'],headers,'mihomo')
print(json.dumps(dict(proxies=fresh['proxies'],pending_labels=pending,
    fetched_at=__import__('time').time(),device_preexisting=device_preexisting,
    available_labels=[h['remark'] for h in hosts if not h['isDisabled'] and not h['isHidden']])))
'''


def fresh(release):
    p.require(len(release) == 12 and all(c in '0123456789abcdef' for c in release), 'Exact deployed release required')
    headers = subprocess.run(['node', '-e', "process.stdout.write(JSON.stringify({headers:require('./ops/pc-outage-20260918/subscription_readback.cjs').deviceHeaders()}))"],
                             capture_output=True, timeout=20, check=True).stdout
    root = '/opt/hamvpn-cloud140-six/releases/' + release + '/ops/cloud140-six-20260918/'
    code = 'import sys,json;sys.path.insert(0,' + repr(root) + ');import preflight as p\n' + REMOTE
    return json.loads(o.transport.remote('panel', o.encoded_command(code), headers))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('schema', 'run'))
    parser.add_argument('--release', required=True)
    args = parser.parse_args()
    payload = fresh(args.release)
    payload['binaries'] = dict(mihomo='C:/Program Files/HamVPN PC/resources/sidecar/mihomo.exe',
                               curl='C:/Windows/System32/curl.exe')
    payload['action'] = args.action
    # Read safe JSON lines as they arrive; no command contains private input.
    child = subprocess.Popen(['node', str(Path(__file__).with_suffix('.cjs'))], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    child.stdin.write(p.encoded(payload)); child.stdin.close(); payload = None
    for line in child.stdout:
        value = json.loads(line)
        print(json.dumps(value, ensure_ascii=False), flush=True)
    child.wait()
    p.require(child.returncode == 0, 'Read-only PC audit incomplete; no automatic mutation')


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    try: main()
    except Exception:
        print('PC audit stopped safely; no credentials printed, no app settings changed', file=sys.stderr)
        sys.exit(1)
