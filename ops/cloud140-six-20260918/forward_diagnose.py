"""Read-only PL failed-identity diagnostic, Linux root, <=75 seconds total.

Run from the published release: python3 -B forward_diagnose.py --id pl
No stdin, keys, passwords or other arguments are needed. No file/record writes,
account mutations, service operations, SSH connections, or package installs.
The quarantined policy is included at its exact lexical position ONLY in an
in-memory candidate supplied to sshd -t/-T -f /dev/stdin. A live-vs-original-
stdin control guards the interpretation of Include paths. A nested/missing/
ambiguous Include is rejected rather than guessed. Output contains field names
and public context identifiers, never effective values or key/config contents.
"""
import argparse
import fnmatch
import glob
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import signal
import stat
import subprocess
import time

import forward as f

LIMIT = 75


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def glob_matches_path(target, pattern):
    """An ordinary glob '*' cannot consume a directory separator."""
    left, right = PurePosixPath(target).parts, PurePosixPath(pattern).parts
    require('..' not in right and '**' not in right, 'Unsupported Include glob')
    return len(left) == len(right) and all(fnmatch.fnmatchcase(a, b) for a, b in zip(left, right))


def reconstruct(original, target, quarantined, lookup=glob.glob):
    """Pure except injected read-only glob lookup. Preserve non-target lines."""
    require(isinstance(original, str) and target.startswith('/') and quarantined.startswith('/'), 'Invalid candidate inputs')
    output = []; replacements = 0
    for line in original.splitlines(keepends=True):
        words = shlex.split(line, comments=True, posix=True)
        if not words or words[0].lower() != 'include':
            output.append(line); continue
        patterns = [x if x.startswith('/') else '/etc/ssh/' + x for x in words[1:]]
        if not any(glob_matches_path(target, pattern) for pattern in patterns):
            output.append(line); continue
        for pattern in patterns:
            matched = sorted(lookup(pattern))
            require(len(matched) == len(set(matched)), 'Duplicate glob result')
            if glob_matches_path(target, pattern):
                require(target not in matched, 'Live target policy already exists')
                matched = sorted(matched + [target])
            for filename in matched:
                if filename == target:
                    filename = quarantined; replacements += 1
                require(re.fullmatch(r'[A-Za-z0-9_./@+-]+', filename) is not None, 'Unsupported Include filename')
                output.append('Include ' + filename + '\n')
    require(replacements == 1, 'Expected exactly one direct Include location')
    return ''.join(output)


def fields(text):
    return dict(line.split(' ', 1) for line in text.splitlines() if ' ' in line)


def changed(left, right):
    a, b = fields(left), fields(right)
    return sorted(k for k in a.keys() | b.keys() if a.get(k) != b.get(k))


def error_summary(result):
    return dict(rc=result.returncode, bad_option_names=re.findall(
        r'Bad configuration option:\s*([A-Za-z][A-Za-z0-9]*)', result.stderr, re.I),
        disallowed_directives=re.findall(r'Directive\s+[\'\"]?([A-Za-z][A-Za-z0-9]*)', result.stderr),
        stderr_sha256=f.sha(result.stderr.encode()))


class Commands:
    def __init__(self, deadline): self.deadline = deadline

    def __call__(self, args, data=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError('Diagnostic deadline')
        return subprocess.run(args, input=data, text=True, capture_output=True, timeout=min(6, remaining))


def effective(run, n, user, address, text=None):
    args = ['/usr/sbin/sshd', '-T']
    if text is not None: args += ['-f', '/dev/stdin']
    args += ['-C', 'user=' + user + ',addr=' + address + ',host=' + address + ',laddr=' + n['ip'] + ',lport=22']
    return run(args, text)


def private_record(path):
    """Read without Store.secure(), which is allowed to create directories."""
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'Unsafe state ancestor')
    require(stat.S_IMODE(path.parent.stat().st_mode) == 0o700, 'Non-private state directory')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                'Unsafe immutable record')
        value = json.load(stream)
    require(set(value) == {'sha256', 'value'} and value['sha256'] == f.p.digest(value['value']), 'Record checksum differs')
    return value['value']


def restrictions(n, text):
    actual = fields(text); differences = []
    for name, expected in f.policy(n).items():
        value = actual.get(name.lower())
        if expected in ('yes', 'no'): value = {'true': 'yes', 'false': 'no'}.get(value, value)
        if value != expected: differences.append(name)
    if actual.get('disableforwarding') not in ('no', 'false'): differences.append('DisableForwarding')
    return differences


def diagnose(run, result):
    n = f.route('pl'); loc = f.paths(n); state = f.STATE / 'pl' / 'exit'
    result.update(id='pl', read_only=True, completed=False, phase='scope')
    require(os.name == 'posix' and os.geteuid() == 0, 'Linux root required')
    addresses = run(['ip', '-j', '-4', 'addr', 'show'])
    require(addresses.returncode == 0 and n['ip'] in {
        a['local'] for i in json.loads(addresses.stdout) for a in i.get('addr_info', [])}, 'Wrong server')
    before = private_record(state / 'identity-intent.json')
    failed = state / 'failed-policy.conf'; f.secure(failed, 0o600)
    require(not (state / 'identity-ready.json').exists() and not (state / 'identity-ready.json').is_symlink(), 'Identity is already ready')
    require(not loc['policy'].exists() and not loc['policy'].is_symlink(), 'Live policy exists')
    require(before.get('id') == 'pl' and failed.read_text() == before['policy'] == f.policy_text(n), 'Quarantine ownership differs')
    original = Path('/etc/ssh/sshd_config').read_text()
    result['phase'] = 'reconstruct'
    candidate = reconstruct(original, str(loc['policy']), str(failed))
    result['candidate_include_replacements'] = 1
    result['phase'] = 'syntax'
    syntax = run(['/usr/sbin/sshd', '-t', '-f', '/dev/stdin'], candidate)
    result['syntax'] = error_summary(syntax)
    pending = loc['home'] / '.ssh/authorized_keys.pending'
    result.update(ssh_files_preserved=f.ssh_manifest(loc['policy']) == before['ssh_manifest'],
        existing_accounts_preserved=f.p.digest(f.account_rows(n)) == before['account_rows_sha256'],
        pending_key_matches_intent=pending.is_file() and not pending.is_symlink() and pending.read_text() == before['authorized'],
        openssl_available=shutil.which('openssl') is not None, chpasswd_available=shutil.which('chpasswd') is not None,
        restriction_diffs=[], existing_policy_diffs=[], existing_contexts_checked=0)
    if syntax.returncode == 0:
        result['phase'] = 'restrictions'
        for address in before['contexts']:
            check = effective(run, n, n['user'], address, candidate)
            row = dict(source=address, **error_summary(check))
            if check.returncode == 0: row['fields'] = restrictions(n, check.stdout)
            result['restriction_diffs'].append(row)
        result['phase'] = 'existing-policy-preservation'
        for user in before['users']:
            for address in before['contexts']:
                baseline = before['policies'][user][address]
                live = effective(run, n, user, address)
                control = effective(run, n, user, address, original)
                proposed = effective(run, n, user, address, candidate)
                require(live.returncode == control.returncode == 0 and live.stdout == control.stdout,
                        'Original-stdin control differs from actual configuration')
                row = dict(user=user, source=address, live_vs_snapshot=changed(baseline, live.stdout),
                    candidate_vs_live=changed(live.stdout, proposed.stdout) if proposed.returncode == 0 else ['PARSE_ERROR'],
                    candidate_rc=proposed.returncode)
                result['existing_contexts_checked'] += 1
                if row['live_vs_snapshot'] or row['candidate_vs_live']: result['existing_policy_diffs'].append(row)
    result.update(phase='complete', completed=True)


def expire(_signum, _frame): raise TimeoutError('Diagnostic deadline')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--id', required=True, choices=['pl']); parser.parse_args()
    result = dict(read_only=True, completed=False)
    if os.name != 'posix':
        print(json.dumps(dict(result, error='LinuxRootRequired'))); return 1
    started = time.monotonic()
    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, LIMIT)
    try:
        diagnose(Commands(started + LIMIT), result)
        status = 0
    except Exception as error:
        result.update(error=type(error).__name__, deadline_exceeded=isinstance(error, (TimeoutError, subprocess.TimeoutExpired)))
        status = 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    result['elapsed_seconds'] = round(time.monotonic() - started, 3)
    print(json.dumps(result))
    return status


if __name__ == '__main__': raise SystemExit(main())
