"""Archive an unused/restored frontend attempt; never alter panel resources.

An explicit retry must take fresh runtime, permissions and client evidence.
The immutable old before/plan/operation are retained in root-only history.
Run under the same global frontend lock as deployment and rollback.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import time

import frontend_stage as f


def eligible(worker, route_id):
    before, plan, record = worker._load(route_id)
    f.require('finished' not in record, 'Completed frontend cannot be reset')
    prepared_only = not any(k in record for k in
        ('arm_intent', 'apply_intent', 'binding_intent', 'staged', 'published',
         'rollback_intent', 'rolled_back', 'front', 'profile'))
    f.require('rolled_back' in record or prepared_only, 'Roll back live/uncertain frontend first')
    if prepared_only:
        f.require(not record['grants'] and not record['host_intents'], 'Preparation has mutation intents')
    # All original host/profile/binding identities must still be present.
    # _guard deliberately does not require unrelated historical squad grants:
    # another operation may have safely removed its own rolled-back grants.
    profile, front, node = worker._guard(before, plan, record)
    f.require(profile['config'] == before['profile']['config'] and
              f.c.metadata(profile) == f.c.metadata(before['profile']) and
              f.c.binding(node) == f.c.binding(before['entry']), 'Entry not exactly restored/unused')
    tag = f.model.route_tags(route_id)['front']
    f.require(tag not in f.c.metadata(profile), 'Owned frontend still exists')
    if front:
        squads = worker.api('GET', '/api/internal-squads/')['internalSquads']
        f.require(all(front not in f.c.ids(s['inbounds']) for s in squads), 'Owned frontend grant remains')
        for host in worker.api('GET', '/api/hosts/'):
            f.require(f.c.host_binding(host)['configProfileInboundUuid'] != front,
                      'Owned frontend host reference remains')
    return before, plan, record


def archive(worker, route_id):
    before, plan, record = eligible(worker, route_id)
    source = worker.store.path
    f.require(source == f.STATE / route_id and not source.is_symlink(), 'Wrong retry source')
    names = {'before.json', 'plan.json', 'operation.json'}
    f.require({p.name for p in source.iterdir()} == names, 'Unexpected/partial frontend state files')
    history = f.p.Store(f.STATE.parent / 'frontend-history')
    history.secure()
    token = route_id + '-' + f.checksum(record)[:20]
    destination = history.path / token
    f.require(not destination.exists() and not destination.is_symlink(), 'Retry archive already exists')
    intent_name = 'retry-' + token
    f.require(not history.exists(intent_name), 'Prior uncertain retry needs inspection')
    history.put(intent_name, dict(id=route_id, timestamp=time.time(), source=str(source),
        destination=str(destination), records={n: f.checksum(v) for n, v in
            [('before', before), ('plan', plan), ('operation', record)]}))
    worker.timer.cancel(route_id)
    # Recheck after cancellation; no API writes are made by this helper.
    f.require(eligible(worker, route_id) == (before, plan, record), 'State changed before archive')
    source.rename(destination)
    info = destination.lstat()
    f.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
              stat.S_IMODE(info.st_mode) == 0o700, 'Unsafe archived state')
    archived = f.p.Store(destination)
    f.require(all(archived.get(n) == v for n, v in
        [('before', before), ('plan', plan), ('operation', record)]) and
        not source.exists(), 'Archive readback failed')
    for path in (source.parent, destination.parent):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    history.put('done-' + token, dict(id=route_id, timestamp=time.time(), archived=True))
    return dict(id=route_id, old_attempt_archived=True, panel_unchanged=True,
                fresh_prepare_and_all_proofs_required=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--id', required=True, choices=tuple(f.PORTS))
    args = parser.parse_args()
    os.umask(0o077)
    store = f.RootStore(args.id)
    with store.locked():
        api, _ = f.p.load_file('retry_panel_api', f.p.ROOT.parent / 'selfsteal-us3/panel_api.py').create_client()
        core = f.c.Coordinator(api, f.c.RootStore(args.id), f.c.SystemdTimer())
        worker = f.Frontend(api, store, core, f.Timers())
        print(json.dumps(archive(worker, args.id)))


if __name__ == '__main__':
    main()
