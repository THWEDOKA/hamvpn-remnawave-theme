"""Build three isolated client-side fragmentation variants; no profile writes."""
from copy import deepcopy

FINAL_MASK = {'tcp': [{'type': 'fragment', 'settings': {'length': '10-20', 'packets': 'tlshello', 'delay': '10-20'}}]}
SOURCE_UUIDS = ['4cc859aa-2af9-4021-bf95-0c8bee12cd6d', '2bb732dd-02f6-4045-9755-4a90357d2083', '3c1f0125-7d4e-4c46-bc48-45a1b3075f19']
NAMES = ['🇩🇪 Тест фрагментации — DE', '🇵🇱 Тест фрагментации — PL', '🇸🇪 Тест фрагментации — SE']


def clone_payload(host, remark):
    if host.get('isDisabled') or host.get('isHidden') or host.get('port') != 443:
        raise ValueError('Expected an enabled visible TCP/443 source')
    if host.get('fingerprint') != 'firefox' or not host.get('inbound', {}).get('configProfileInboundUuid'):
        raise ValueError('Firefox and a concrete inbound are required')
    if host.get('finalMask'):
        raise ValueError('Do not replace an existing mask')
    payload = deepcopy(host)
    for key in ['uuid', 'viewPosition']: payload.pop(key, None)
    payload.update(remark=remark, finalMask=deepcopy(FINAL_MASK), fingerprint='firefox')
    payload['tags'] = [tag for tag in payload.get('tags', []) if tag not in {'AUTO_BASE_POOL', 'AUTO_WHITE_POOL'}]
    # No experimental variants in clients that cannot apply Xray FinalMask.
    payload['excludeFromSubscriptionTypes'] = sorted(set(payload.get('excludeFromSubscriptionTypes') or []) | {'MIHOMO', 'CLASH', 'STASH', 'SINGBOX', 'XRAY_BASE64'})
    return payload
