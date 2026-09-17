"""Own one source-restricted IPv4 backend rule on four selected exit servers.

No INPUT flush, policy changes, UFW edits, package installation or service
restart. Persistent dedicated unit reapplies only its exact jump and chain.
Root-only immutable snapshot precedes installation. Unknown state stops.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import preflight as p
import node_ops

ALLOWED={'at','pl','cz','gbpower'}
CHAIN='HAMC140SIX'
PORT=15444
UNIT=Path('/etc/systemd/system/ham-cloud140-six-backend.service')

def call(args, allowed=(0,)):
    r=subprocess.run(args,capture_output=True,text=True,timeout=20)
    p.require(r.returncode in allowed,'Scoped firewall command failed')
    return r

def ipt(*args,allowed=(0,)):
    return call(['iptables','-w','10',*args],allowed)

def rules():
    return [['-i','lo','-j','ACCEPT'],['-s',p.ENTRY+'/32','-j','ACCEPT'],['-j','REJECT','--reject-with','tcp-reset']]

def jump(ip):return ['-d',ip+'/32','-p','tcp','--dport',str(PORT),'-j',CHAIN]

def unit_text(identifier):
    return ('[Unit]\nDescription=HAMVPN restricted CLOUDru backend\nAfter=network.target ufw.service\nBefore=docker.service\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\nUMask=0077\n'
            'ExecStart=/usr/bin/python3 '+str(Path(__file__).resolve())+' ensure --id '+identifier+'\n'
            '[Install]\nWantedBy=multi-user.target\n')

def store(identifier):
    p.require(identifier in ALLOWED,'Withdrawn or unknown exit')
    return p.Store(Path('/root/hamvpn-cloud140-six-20260918/firewall')/identifier)

def inspect_chain():
    result=ipt('-S',CHAIN,allowed=(0,1))
    return result.stdout.splitlines() if result.returncode==0 else None

def expected_chain():
    return ['-N '+CHAIN,'-A '+CHAIN+' -i lo -j ACCEPT',
            '-A '+CHAIN+' -s '+p.ENTRY+'/32 -j ACCEPT',
            '-A '+CHAIN+' -j REJECT --reject-with tcp-reset']

def references():
    return [line for line in ipt('-S').stdout.splitlines() if ('-j '+CHAIN) in line or ('-g '+CHAIN) in line]

def ensure(identifier):
    s=store(identifier);before=s.get('before');ip=node_ops.TARGETS[identifier]['ip']
    p.require(before['id']==identifier and before['ip']==ip,'Foreign firewall state')
    p.require(UNIT.is_file() and not UNIT.is_symlink() and UNIT.read_text()==before['unit'],'Owned unit drift')
    chain=inspect_chain();wanted=expected_chain()
    if chain is None:
        p.require(not references(),'Missing chain has references')
        ipt('-N',CHAIN);chain=inspect_chain()
    p.require(chain==wanted[:len(chain)] and len(chain)<=len(wanted),'Foreign or reordered chain rules')
    for rule in rules()[len(chain)-1:]:ipt('-A',CHAIN,*rule)
    p.require(inspect_chain()==wanted,'Backend chain readback differs')
    expected='-A INPUT -d '+ip+'/32 -p tcp -m tcp --dport '+str(PORT)+' -j '+CHAIN
    refs=references();p.require(refs in ([],[expected]),'Unexpected chain reference')
    if not refs:ipt('-I','INPUT','1',*jump(ip))
    p.require(references()==[expected],'Backend jump readback differs')
    return dict(firewall_source=p.ENTRY,backend_port=PORT,only_entry_or_loopback=True,timestamp=time.time())

def install(identifier):
    s=store(identifier)
    if not s.exists('before'):
        runtime=node_ops.runtime(identifier)
        p.require(runtime['backend_port_free'],'Backend port is already occupied')
        p.require(not UNIT.exists() and not UNIT.is_symlink() and inspect_chain() is None and not references(),'Existing firewall scope')
        snapshot=call(['iptables-save']).stdout
        s.put('before',dict(id=identifier,ip=runtime['ip'],iptables=snapshot,
                           unit=unit_text(identifier),runtime=runtime,timestamp=time.time()))
    before=s.get('before')
    p.require(before['unit']==unit_text(identifier),'Release/unit change requires review')
    if not UNIT.exists():
        fd=os.open(UNIT,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,'w') as f:f.write(before['unit']);f.flush();os.fsync(f.fileno())
        call(['systemctl','daemon-reload'])
    result=ensure(identifier)
    call(['systemctl','enable','--now',UNIT.name])
    call(['systemctl','is-enabled',UNIT.name]);call(['systemctl','is-active',UNIT.name])
    if not s.exists('installed'):s.put('installed',result)
    return result

def rollback(identifier):
    s=store(identifier);before=s.get('before');ip=before['ip']
    p.require(UNIT.is_file() and not UNIT.is_symlink() and UNIT.read_text()==before['unit'],'Owned unit drift')
    p.require(inspect_chain()==expected_chain(),'Owned chain drift')
    expected='-A INPUT -d '+ip+'/32 -p tcp -m tcp --dport '+str(PORT)+' -j '+CHAIN
    p.require(references()==[expected],'Owned jump drift')
    p.require(node_ops.runtime(identifier)['backend_port_free'],'Detach backend before removing its guard')
    call(['systemctl','disable','--now',UNIT.name])
    ipt('-D','INPUT',*jump(ip))
    for rule in reversed(rules()):ipt('-D',CHAIN,*rule)
    ipt('-X',CHAIN);UNIT.unlink();call(['systemctl','daemon-reload'])
    p.require(inspect_chain() is None and not references(),'Firewall rollback not confirmed')
    s.put('rolled-back',dict(timestamp=time.time()))
    return dict(owned_backend_guard_removed=True)

def main():
    import fcntl
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['install','ensure','rollback']);parser.add_argument('--id',required=True,choices=sorted(ALLOWED));args=parser.parse_args()
    s=store(args.id);s.secure()
    fd=os.open(s.path/'operation.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'rb') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX);print(json.dumps(globals()[args.action](args.id)))

if __name__=='__main__':
    try:main()
    except Exception as e:
        print(json.dumps(dict(error=type(e).__name__,message='Backend guard stopped; inspect protected state')),file=sys.stderr);sys.exit(1)
