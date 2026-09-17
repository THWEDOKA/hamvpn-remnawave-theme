"""One LE lineage and its ACME account, binary SSH stdout -> stdin.

Export stdout is SECRET. Capture with subprocess.run(capture_output=True), pass
result.stdout unchanged as receive input. Never decode/print/save the archive
on the operator machine. Use scripts from the verified published release only.
"""
import argparse
import configparser
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import sys
import tarfile
import tempfile
from entry244_common import NODES, STATE, exists, save

LE = Path('/etc/letsencrypt')
DOMAIN = NODES[0]['domain']
DOMAINS = {n['domain'] for n in NODES}
ACCOUNT_BASE = 'accounts/acme-v02.api.letsencrypt.org/directory/'
RENEWAL = 'renewal/' + DOMAIN + '.conf'
LIMIT = 1024 * 1024
KINDS = ('cert', 'chain', 'fullchain', 'privkey')
ACCOUNT_FILES = ('meta.json', 'private_key.json', 'regr.json')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(*args, data=None):
    result = subprocess.run(args, input=data, capture_output=True)
    require(result.returncode == 0, 'Certificate validation command failed (output suppressed)')
    return result.stdout


def verify_server(ip):
    require(ip + '/' in command('ip', '-4', 'addr', 'show').decode(), 'Wrong transfer server')


def account_from_renewal(data):
    config = configparser.RawConfigParser()
    config.read_string('[certificate]\n' + data.decode('utf-8'))
    require(set(config.sections()) == {'certificate', 'renewalparams', '[webroot_map]'}, 'Unexpected renewal sections')
    require(not config.defaults(), 'Unexpected renewal defaults')
    top, params, mapping = config['certificate'], config['renewalparams'], config['[webroot_map]']
    require(set(top) == {'version', 'archive_dir', *KINDS}, 'Unexpected certificate settings')
    require(top['archive_dir'] == '/etc/letsencrypt/archive/' + DOMAIN, 'Wrong archive lineage')
    for kind in KINDS:
        require(top[kind] == '/etc/letsencrypt/live/' + DOMAIN + '/' + kind + '.pem', 'Wrong live lineage')
    require(set(params) == {'account', 'authenticator', 'server', 'key_type', 'webroot_path'}, 'Unexpected renewal settings')
    require(params['authenticator'] == 'webroot', 'Only webroot renewal is allowed')
    require(params['server'] == 'https://acme-v02.api.letsencrypt.org/directory', 'Wrong ACME directory')
    require(params['key_type'] in {'ecdsa', 'rsa'}, 'Unsupported key type')
    require(params['webroot_path'].rstrip(', ') == '/var/www/acme', 'Unexpected webroot')
    require(set(mapping) == DOMAINS and all(v == '/var/www/acme' for v in mapping.values()), 'Unexpected webroot map')
    account = params['account']
    require(re.fullmatch(r'[a-f0-9]{32}', account) is not None, 'Invalid account identifier')
    return ACCOUNT_BASE + account


def bundle_members(raw):
    require(0 < len(raw) <= LIMIT, 'Archive size rejected')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        require(0 < len(members) <= 128, 'Too many archive members')
        names = [m.name for m in members]
        require(len(names) == len(set(names)), 'Duplicate archive members')
        require(sum(m.size for m in members) <= LIMIT, 'Expanded archive size rejected')
        for m in members:
            require(m.name == str(PurePosixPath(m.name)) and not m.name.startswith('/')
                    and '..' not in PurePosixPath(m.name).parts and '\\' not in m.name, 'Unsafe archive path')
            require(m.isfile() or m.isdir() or m.issym(), 'Unsupported archive member type')
        renewal = next((m for m in members if m.name == RENEWAL), None)
        require(renewal is not None and renewal.isfile(), 'Missing renewal file')
        account = account_from_renewal(archive.extractfile(renewal).read())
        directories = {'live/' + DOMAIN, 'archive/' + DOMAIN, account}
        regular = {RENEWAL, 'live/' + DOMAIN + '/README', *(account + '/' + n for n in ACCOUNT_FILES)}
        symlinks = {'live/' + DOMAIN + '/' + k + '.pem' for k in KINDS}
        data, links = {}, {}
        for m in members:
            name = m.name
            if m.isdir():
                require(name in directories, 'Unexpected archive directory')
            elif m.issym():
                require(name in symlinks, 'Unexpected symlink')
                kind = PurePosixPath(name).stem
                require(re.fullmatch(r'\.\./\.\./archive/' + re.escape(DOMAIN) + '/' + kind + r'[1-9][0-9]*\.pem', m.linkname)
                        is not None, 'Symlink escapes selected certificate')
                links[name] = m.linkname
            else:
                valid = re.fullmatch('archive/' + re.escape(DOMAIN) + r'/(cert|chain|fullchain|privkey)[1-9][0-9]*\.pem', name)
                require(name in regular or valid is not None, 'Unexpected certificate archive file')
                require(not m.issparse(), 'Sparse files rejected')
                data[name] = archive.extractfile(m).read()
        require(set(links) == symlinks, 'Incomplete certificate lineage')
        require(all(account + '/' + n in data for n in ACCOUNT_FILES), 'Incomplete ACME account')
        for link, target in links.items():
            require(posixpath.normpath(posixpath.join(posixpath.dirname(link), target)) in data,
                    'Certificate symlink target is not a regular archive file')
        return account, data, links


def certificate_details(base):
    live = Path(base) / 'live' / DOMAIN
    details = command('openssl', 'x509', '-in', str(live / 'cert.pem'), '-noout', '-dates', '-ext', 'subjectAltName').decode()
    require(set(re.findall(r'DNS:([^,\s]+)', details)) == DOMAINS, 'Certificate SAN mismatch')
    command('openssl', 'x509', '-in', str(live / 'cert.pem'), '-checkend', '86400', '-noout')
    command('openssl', 'verify', '-CApath', '/etc/ssl/certs', '-untrusted', str(live / 'chain.pem'), str(live / 'cert.pem'))
    public = command('openssl', 'x509', '-in', str(live / 'cert.pem'), '-pubkey', '-noout')
    require(public == command('openssl', 'pkey', '-in', str(live / 'privkey.pem'), '-pubout'), 'Certificate/key mismatch')
    require((live / 'fullchain.pem').read_bytes() == (live / 'cert.pem').read_bytes() + (live / 'chain.pem').read_bytes(),
            'Fullchain mismatch')
    return details


def export():
    verify_server('162.141.185.208')
    account = account_from_renewal((LE / RENEWAL).read_bytes())
    certificate_details(LE)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for root in ('live/' + DOMAIN, 'archive/' + DOMAIN, account):
            path = LE / root
            require(path.is_dir() and not path.is_symlink(), 'Unsafe source directory')
            archive.add(path, arcname=root, recursive=False)
            for child in sorted(path.iterdir()):
                archive.add(child, arcname=root + '/' + child.name, recursive=False)
        require(not (LE / RENEWAL).is_symlink(), 'Unsafe renewal source')
        archive.add(LE / RENEWAL, arcname=RENEWAL, recursive=False)
    raw = buffer.getvalue()
    bundle_members(raw)
    sys.stdout.buffer.write(raw)


def ensure_directory(path):
    path = Path(path)
    for ancestor in [*reversed(path.parents), path]:
        require(not ancestor.is_symlink(), 'Symlink destination ancestor rejected')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(path.is_dir(), 'Destination is not a directory')


def receive():
    verify_server('193.233.222.244')
    require(exists('prepared') and not exists('imported-certificate'), 'Prepare first; do not repeat import blindly')
    raw = sys.stdin.buffer.read(LIMIT + 1)
    account, data, links = bundle_members(raw)
    targets = ('archive/' + DOMAIN, 'live/' + DOMAIN, RENEWAL)
    for relative in targets:
        path = LE / relative
        require(not path.exists() and not path.is_symlink(), 'Existing certificate destination')
    ensure_directory(LE)
    ensure_directory(STATE)
    STATE.chmod(0o700)
    with tempfile.TemporaryDirectory(prefix='cert244-', dir=STATE) as temporary:
        stage = Path(temporary)
        for name, contents in data.items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with target.open('xb') as handle:
                target.chmod(0o600)
                handle.write(contents)
        for name, target in links.items():
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.symlink_to(target)
        details = certificate_details(stage)
        existing = LE / account
        ensure_directory(existing.parent)
        if existing.exists() or existing.is_symlink():
            require(existing.is_dir() and not existing.is_symlink(), 'Unsafe existing account')
            require(set(x.name for x in existing.iterdir()) == set(ACCOUNT_FILES), 'Existing account differs')
            for name in ACCOUNT_FILES:
                p = existing / name
                require(p.is_file() and not p.is_symlink() and p.read_bytes() == data[account + '/' + name],
                        'Existing ACME account differs; refusing overwrite')
        promote = list(targets) + ([] if existing.exists() else [account])
        for relative in promote:
            ensure_directory((LE / relative).parent)
            require(not (LE / relative).exists() and not (LE / relative).is_symlink(), 'Destination appeared during import')
        promoted = []
        try:
            for relative in promote:
                (stage / relative).rename(LE / relative)
                promoted.append(relative)
            certificate_details(LE)
            save('imported-certificate', {'sha256': hashlib.sha256(raw).hexdigest(), 'details': details})
        except Exception:
            for relative in reversed(promoted):
                (LE / relative).rename(stage / relative)
            raise
    print(json.dumps({'four_name_certificate_transferred': True, 'sha256': hashlib.sha256(raw).hexdigest(), 'details': details}))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['export', 'receive'])
    args = parser.parse_args()
    try:
        globals()[args.action]()
    except Exception:
        print('Certificate operation failed; sensitive diagnostics suppressed', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
