"""Restore the exact original Docker network after watchdog/start collision."""
from ops import *

def main():
    guard('entry');before=read('node-before')
    old=next(c for c in before['containers'] if c['Name']=='/'+OLD_CONTAINER)
    current=json.loads(run('docker','inspect',OLD_CONTAINER))[0]
    require(current['Id']==old['Id'],'Original container identity changed')
    original=old['NetworkSettings']['Networks']
    require(list(original)==['remnanode-ham-shared_default'],'Unexpected baseline network')
    require(not current['NetworkSettings']['Networks'],'Only missing network recovery is allowed')
    network=next(iter(original));ip=original[network]['IPAddress']
    require(ip=='172.20.0.2','Baseline address changed')
    run('systemctl','stop','rw-core-watchdog-ham-shared.timer','rw-core-watchdog-ham-shared.service')
    run('docker','stop','--time','10',OLD_CONTAINER,timeout=25)
    run('docker','network','connect','--ip',ip,network,OLD_CONTAINER)
    run('docker','start',OLD_CONTAINER)
    for _ in range(30):
        if run('ss','-H','-lnt','sport = :2083').strip():break
        time.sleep(1)
    require(run('ss','-H','-lnt','sport = :2083').strip(),'Legacy port not restored')
    run('systemctl','start','rw-core-watchdog-ham-shared.timer')
    save('network-restored',{'original_network':network,'original_ip':ip,'time':time.time()})
    return {'original_network_restored':True,'legacy_listener_restored':True}

if __name__=='__main__':
    try:print(json.dumps(main()))
    except Exception as e:print(json.dumps({'failed':True,'error':type(e).__name__,'detail':str(e) if isinstance(e,RuntimeError) else 'Inspect private state'}));sys.exit(1)
