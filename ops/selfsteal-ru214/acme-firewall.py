"""Add only RU214 to the existing persistent SSH set; never reload a firewall."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

IP = '161.104.90.214'
SOURCE = Path('/etc/nftables.d/hamvpn-firewall.nft')
STATE = Path('/root/selfsteal-ru214-firewall')


def candidate(original):
    pattern = r'(set ssh_admin4\s*\{\s*type ipv4_addr\s*flags interval\s*elements\s*=\s*\{)([^}]+)(\}\s*\})'
    matches = list(re.finditer(pattern, original))
    assert len(matches) == 1, 'Unexpected persistent SSH set layout'
    match = matches[0]
    addresses = [value.strip() for value in match[2].split(',')]
    assert IP not in addresses
    assert all(re.fullmatch(r'[0-9.]+(?:/[0-9]+)?', value) for value in addresses)
    content = match[2].rstrip() + ',\n            ' + IP + '\n        '
    return original[:match.start(2)] + content + original[match.end(2):]


def runtime():
    return json.loads(subprocess.check_output(['nft', '-j', 'list', 'table', 'inet', 'hamvpn_filter']))


def normalized(value):
    result = copy.deepcopy(value)
    result['nftables'] = [row for row in result['nftables'] if 'metainfo' not in row]
    def walk(node):
        if isinstance(node, dict):
            for key, child in node.items():
                if key == 'counter' and isinstance(child, dict):
                    child.pop('packets', None); child.pop('bytes', None)
                else: walk(child)
        elif isinstance(node, list):
            for child in node: walk(child)
    walk(result)
    return result


def ssh_set(value):
    return next(row['set'] for row in value['nftables'] if row.get('set', {}).get('name') == 'ssh_admin4')


def atomic_write(path, data, mode):
    temporary = path.with_name(path.name + '.ru214-tmp')
    assert not temporary.exists()
    temporary.write_bytes(data); temporary.chmod(mode); temporary.replace(path)


def main():
    assert os.geteuid() == 0 and not STATE.exists()
    os.umask(0o077)
    original = SOURCE.read_bytes()
    proposed = candidate(original.decode()).encode()
    before = runtime()
    assert IP not in ssh_set(before).get('elem', [])
    STATE.mkdir(mode=0o700)
    (STATE / 'before.nft').write_bytes(original)
    (STATE / 'runtime-before.json').write_text(json.dumps(before))
    (STATE / 'candidate.nft').write_bytes(proposed)
    digest = hashlib.sha256(original).hexdigest()
    (STATE / 'original-sha256').write_text(digest + '\n')
    # Validate in an isolated network namespace with no production rules or interfaces.
    subprocess.run(['unshare', '--net', 'nft', '--check', '-f', str(STATE / 'candidate.nft')], check=True)
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == digest, 'Concurrent persistent firewall edit'
    assert normalized(runtime()) == normalized(before), 'Concurrent runtime firewall edit'
    mode = SOURCE.stat().st_mode & 0o777
    atomic_write(SOURCE, proposed, mode)
    inserted = False
    try:
        subprocess.run(['nft', 'add', 'element', 'inet', 'hamvpn_filter', 'ssh_admin4', '{', IP, '}'], check=True)
        inserted = True
        after = runtime()
        current_set = ssh_set(after)
        assert set(current_set['elem']) == set(ssh_set(before)['elem']) | {IP}
        comparable = copy.deepcopy(after)
        ssh_set(comparable)['elem'] = ssh_set(before)['elem']
        assert normalized(comparable) == normalized(before), 'Unexpected unrelated runtime change'
        assert SOURCE.read_bytes() == proposed
        (STATE / 'verified.json').write_text(json.dumps({'source': IP, 'only_ssh_set_changed': True,
                                                       'persistent_sha256': hashlib.sha256(proposed).hexdigest()}))
    except Exception:
        if inserted: subprocess.run(['nft', 'delete', 'element', 'inet', 'hamvpn_filter', 'ssh_admin4', '{', IP, '}'], check=True)
        if SOURCE.read_bytes() == proposed: atomic_write(SOURCE, original, mode)
        raise
    print(json.dumps({'ssh_source_added': IP, 'runtime_and_persistent_verified': True,
                      'other_rules_and_sets_preserved': True, 'whole_firewall_reload': False}))


if __name__ == '__main__': main()
