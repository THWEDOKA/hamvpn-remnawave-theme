"""Per-server policy wrapper; isolated backups and timers for approved targets."""
import importlib.util
import json
from pathlib import Path
import sys

RELEASE=Path('/root/ham-koala-batch-release-20261108')
POLICY=Path('/root/ham-koala-batch-policy-20261108.json')


def configure(core,policy):
    if policy['ip'] not in {'143.246.217.145','143.246.217.54','145.223.69.212','146.103.41.233','196.251.122.149','81.180.92.179','62.60.226.36'}:
        raise ValueError('Target outside approved batch')
    core.ROOT=Path('/opt/remnanode')
    core.STATE=Path('/root/ham-koala-batch-core-20261108')
    core.OVERRIDE=core.ROOT/'docker-compose.override.yml'
    core.UNIT='ham-koala-batch-core-20261108'
    core.EXPECTED_IP=policy['ip']
    core.TAG=policy['tag']
    def target(config):
        found=[i for i in config['inbounds'] if i.get('tag')==policy['tag']]
        if len(found)!=1:raise ValueError('Dedicated inbound missing')
        i=found[0];stream=i.get('streamSettings',{})
        if i.get('protocol')!='vless' or i.get('port')!=443 or stream.get('security')!='reality':raise ValueError('Unexpected inbound identity')
        if stream['realitySettings'].get('serverNames')!=policy['serverNames']:raise ValueError('Client domain changed')
        return i
    core.target=target


if __name__=='__main__':
    policy=json.loads(POLICY.read_text())
    spec=importlib.util.spec_from_file_location('core',RELEASE/'core_rollback.py')
    core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
    configure(core,policy);core.__file__=__file__
    action=sys.argv[1]
    if action=='prepare':core.prepare(json.load(sys.stdin))
    elif action in {'apply','accept','rollback'}:getattr(core,action)()
    else:raise ValueError('Unsupported action')
