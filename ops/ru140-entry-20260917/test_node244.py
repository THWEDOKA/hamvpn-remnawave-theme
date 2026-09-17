"""No network or production writes: entry244 staging and archive safety tests."""
import io
import contextlib
import hashlib
import json
import re
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import cert244 as cert
import node244 as node


def renewal():
    return ('version = 2.9.0\narchive_dir = /etc/letsencrypt/archive/' + cert.DOMAIN + '\n'
            + ''.join(k + ' = /etc/letsencrypt/live/' + cert.DOMAIN + '/' + k + '.pem\n' for k in cert.KINDS)
            + '[renewalparams]\naccount = ' + 'a' * 32
            + '\nauthenticator = webroot\nserver = https://acme-v02.api.letsencrypt.org/directory\n'
            + 'key_type = ecdsa\nwebroot_path = /var/www/acme,\n[[webroot_map]]\n'
            + ''.join(d + ' = /var/www/acme\n' for d in sorted(cert.DOMAINS))).encode()


def fixture(extra=None, mutate=None, renewal_data=None):
    entries = [(cert.RENEWAL, renewal_data or renewal(), None)]
    entries += [(cert.ACCOUNT_BASE + 'a' * 32 + '/' + n, b'unit-test-placeholder', None) for n in cert.ACCOUNT_FILES]
    for kind in cert.KINDS:
        entries.append(('archive/' + cert.DOMAIN + '/' + kind + '1.pem', b'unit-test-placeholder', None))
        entries.append(('live/' + cert.DOMAIN + '/' + kind + '.pem', b'', '../../archive/' + cert.DOMAIN + '/' + kind + '1.pem'))
    if extra:
        entries.append(extra)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as archive:
        for name, data, link in entries:
            member = tarfile.TarInfo(name)
            if link:
                member.type, member.linkname = tarfile.SYMTYPE, link
            else:
                member.size = len(data)
            if mutate:
                mutate(member)
            archive.addfile(member, io.BytesIO(data) if member.isfile() else None)
    return buffer.getvalue()


class ArchiveTests(unittest.TestCase):
    def test_valid_bundle_is_exact_account_and_lineage(self):
        account, data, links = cert.bundle_members(fixture())
        self.assertEqual(account, cert.ACCOUNT_BASE + 'a' * 32)
        self.assertEqual(len(links), 4)
        self.assertEqual(len(data), 8)

    def test_rejects_unrelated_secrets_and_account(self):
        for path in ('cloudflare.ini', 'live/other/privkey.pem', 'renewal/' + cert.DOMAIN + '.conf/extra',
                     cert.ACCOUNT_BASE + 'b' * 32 + '/private_key.json', '.ssh/id_ed25519',
                     '/etc/shadow', '../etc/shadow', 'archive/' + cert.DOMAIN + '/token.txt'):
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                cert.bundle_members(fixture(extra=(path, b'unit-test-placeholder', None)))

    def test_rejects_duplicates(self):
        with self.assertRaises(RuntimeError):
            cert.bundle_members(fixture(extra=(cert.RENEWAL, renewal(), None)))

    def test_rejects_escaping_symlinks(self):
        for target in ('/etc/shadow', '../../archive/other/privkey1.pem', '../../../etc/shadow',
                       '../../archive/' + cert.DOMAIN + '/privkey999.pem'):
            def mutate(member):
                if member.name.endswith('/privkey.pem'):
                    member.linkname = target
            with self.subTest(target=target), self.assertRaises(RuntimeError):
                cert.bundle_members(fixture(mutate=mutate))

    def test_rejects_hardlinks_and_devices(self):
        for kind in (tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE):
            def mutate(member):
                if member.name.endswith('/privkey.pem'):
                    member.type = kind
            with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                cert.bundle_members(fixture(mutate=mutate))

    def test_rejects_hooks_credentials_and_wrong_renewal_paths(self):
        for content in (renewal().replace(b'authenticator = webroot', b'authenticator = dns-cloudflare'),
                        renewal().replace(b'[renewalparams]', b'[renewalparams]\ndeploy_hook = bad'),
                        renewal().replace(b'[renewalparams]', b'[renewalparams]\ndns_cloudflare_credentials = bad'),
                        renewal().replace(b'/var/www/acme', b'/root/other')):
            with self.subTest(content_hash=hash(content)), self.assertRaises(RuntimeError):
                cert.bundle_members(fixture(renewal_data=content))

    def test_rejects_empty_oversized_compressed(self):
        for content in (b'', b'x' * (cert.LIMIT + 1)):
            with self.assertRaises(RuntimeError):
                cert.bundle_members(content)
        import gzip
        with self.assertRaises(tarfile.ReadError):
            cert.bundle_members(gzip.compress(fixture()))

    def test_command_failure_never_exposes_output(self):
        with patch.object(cert.subprocess, 'run', return_value=MagicMock(returncode=1, stdout=b'PRIVATE', stderr=b'PRIVATE')):
            with self.assertRaisesRegex(RuntimeError, 'output suppressed') as error:
                cert.command('openssl')
        self.assertNotIn('PRIVATE', str(error.exception))


class StagingTests(unittest.TestCase):
    def test_templates_use_only_http_and_loopback_tls(self):
        http, tls = node.site_config(), node.site_config(tls=True)
        self.assertEqual(re.findall(r'listen\s+([^;]+);', http), ['80'])
        self.assertEqual(re.findall(r'listen\s+([^;]+);', tls), ['80', '127.0.0.1:9443 ssl http2'])
        for domain in cert.DOMAINS:
            self.assertIn(domain, http)
            self.assertIn(domain, tls)
        for stale in ('ham-entry140', 'ham-entry208', ':8443', '162.141.185.208'):
            self.assertNotIn(stale, tls)
        self.assertIn('root /var/www/ham-entry244', tls)
        self.assertNotIn('return 301', http)

    def test_package_plan_never_upgrades_and_restores_policy(self):
        for simulation, succeeds in (('0 upgraded\nInst nginx (1.24)\n', True),
                                    ('Inst libc6 [2.39] (2.40)\n', False), ('Remv libc6\n', False)):
            with self.subTest(simulation=simulation), tempfile.TemporaryDirectory() as temp:
                policy = Path(temp) / 'policy-rc.d'
                calls = []
                def run(*args):
                    self.assertTrue(policy.exists())
                    calls.append(args)
                    return simulation if '--simulate' in args else ''
                with patch.object(node, 'POLICY', policy), patch.object(node, 'run', side_effect=run):
                    if succeeds:
                        node.install_packages()
                    else:
                        with self.assertRaises(RuntimeError):
                            node.install_packages()
                self.assertFalse(policy.exists())
                installs = [c for c in calls if '-y' in c]
                self.assertEqual(bool(installs), succeeds)
                for call in installs:
                    self.assertIn('--no-upgrade', call)
                    self.assertIn('NEEDRESTART_SUSPEND=1', call)
                self.assertFalse(any('restart' in c for c in calls))

    def test_existing_policy_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            policy = Path(temp) / 'policy-rc.d'
            policy.write_text('existing')
            with patch.object(node, 'POLICY', policy), patch.object(node, 'run') as run:
                with self.assertRaises(RuntimeError):
                    node.install_packages()
            self.assertEqual(policy.read_text(), 'existing')
            run.assert_not_called()

    def test_tls_checks_each_sni_with_verification_and_h2(self):
        context = MagicMock()
        secure = context.wrap_socket.return_value.__enter__.return_value
        secure.version.return_value = 'TLSv1.3'
        secure.selected_alpn_protocol.return_value = 'h2'
        with patch.object(node.ssl, 'create_default_context', return_value=context), patch.object(node.socket, 'create_connection'):
            results = node.local_tls()
        self.assertEqual({r['sni'] for r in results}, cert.DOMAINS)
        self.assertEqual(context.minimum_version, node.ssl.TLSVersion.TLSv1_3)
        self.assertEqual(context.set_alpn_protocols.call_count, 4)

    def test_renew_gate_blocks_acme_before_dns(self):
        with patch.object(node, 'exists', return_value=True), patch.object(node, 'run', return_value='162.141.185.208\n') as run:
            with self.assertRaises(RuntimeError):
                node.renew()
        self.assertFalse(any(c.args[0] == 'certbot' for c in run.call_args_list))

    def test_renew_disables_random_sleep_after_dns(self):
        def run(*args):
            if args[0] == 'dig':
                return node.ENTRY + '\n' if 'A' in args else ''
            if args == ('certbot', '--help', 'all'):
                return '--no-random-sleep-on-renew'
            return ''
        with patch.object(node, 'exists', return_value=True), patch.object(node, 'run', side_effect=run) as call, patch.object(node, 'save'):
            node.renew()
        renew = next(c.args for c in call.call_args_list if c.args[:2] == ('certbot', 'renew'))
        self.assertIn('--no-random-sleep-on-renew', renew)
        self.assertIn('--dry-run', renew)

    def test_firewall_is_scoped_and_has_persistent_checks(self):
        content = (node.ROOT / 'firewall244.sh').read_text()
        self.assertIn('64.225.109.248/32', content)
        self.assertIn('-i lo', content)
        self.assertIn('--dport 2222', content)
        self.assertNotRegex(content, r'--dport (22|443|80)\b')
        self.assertNotIn('-F INPUT', content)
        self.assertNotIn('-P INPUT', content)
        self.assertIn('apply_family ip6tables', content)
        with patch.object(node, 'write') as write, patch.object(node, 'run') as run:
            node.install_firewall()
        unit = write.call_args_list[1].args[1]
        self.assertIn('Before=docker.service nginx.service', unit)
        self.assertIn('ExecStartPost=', unit)
        self.assertTrue(any('is-enabled' in c.args for c in run.call_args_list))


class RollbackGateTests(unittest.TestCase):
    def arm_state(self):
        candidate = {'outbounds': []}
        checksum = hashlib.sha256(json.dumps(candidate, sort_keys=True).encode()).hexdigest()
        return {'candidate': candidate, 'xray-config-test': {'passed': True, 'sha256': checksum},
                'certificate': {'site_sha256': 'site'},
                'backend-probes': {'all_passed': True, 'timestamp': 10000, 'candidate_sha256': checksum,
                                   'tests': [{'id': n['id'], 'passed': True} for n in node.NODES]}}

    def test_arm_accepts_only_fresh_complete_candidate_bound_proof(self):
        cases = ('valid', 'expired', 'future', 'missing', 'failed', 'changed_candidate', 'changed_proof')
        for case in cases:
            state = self.arm_state()
            proof = state['backend-probes']
            if case == 'expired': proof['timestamp'] = 1
            if case == 'future': proof['timestamp'] = 10001
            if case == 'missing': proof['tests'].pop()
            if case == 'failed': proof['tests'][0]['passed'] = False
            if case == 'changed_candidate': state['candidate']['drift'] = True
            if case == 'changed_proof': proof['candidate_sha256'] = 'drift'
            with self.subTest(case=case), contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(node, 'exists', side_effect=lambda name: name == 'certificate'))
                stack.enter_context(patch.object(node, 'read', side_effect=lambda name: state[name]))
                stack.enter_context(patch.object(node.time, 'time', return_value=10000))
                stack.enter_context(patch.object(node, 'digest', return_value='site'))
                stack.enter_context(patch.object(node, 'local_tls', return_value=[]))
                run = stack.enter_context(patch.object(node, 'run'))
                if case == 'valid':
                    self.assertTrue(node.arm()['entry_rollback_armed'])
                    run.assert_called_once()
                else:
                    with self.assertRaises(RuntimeError): node.arm()
                    run.assert_not_called()

    def test_finish_requires_exact_inactive_codes_and_rechecks_state(self):
        for codes, success in (([3, 3], True), ([1, 3], False), ([3, 0], False), ([3, 1], False), ([4, 3], False)):
            with self.subTest(codes=codes), contextlib.ExitStack() as stack:
                stream = MagicMock()
                stream.is_file.return_value = True
                stack.enter_context(patch.object(node, 'STREAM', stream))
                states = {'renewal': {'passed': True}, 'stream-intent': {'sha256': 'stream'}, 'certificate': {'site_sha256': 'site'}}
                stack.enter_context(patch.object(node, 'read', side_effect=lambda name: states[name]))
                marker = stack.enter_context(patch.object(node, 'exists', return_value=False))
                stack.enter_context(patch.object(node, 'digest', side_effect=lambda path: 'stream' if path is stream else 'site'))
                run = stack.enter_context(patch.object(node, 'run'))
                status = stack.enter_context(patch.object(node.subprocess, 'run', side_effect=[MagicMock(returncode=c) for c in codes]))
                tls = stack.enter_context(patch.object(node, 'local_tls', return_value=[]))
                save = stack.enter_context(patch.object(node, 'save'))
                if success:
                    self.assertTrue(node.finish()['entry_rollback_service_inactive'])
                    self.assertEqual(status.call_count, 2)
                    self.assertEqual(marker.call_count, 3)
                    tls.assert_called_once()
                    save.assert_called_once()
                else:
                    with self.assertRaises(RuntimeError): node.finish()
                    save.assert_not_called()
                self.assertEqual(run.call_args_list[0].args, ('systemctl', 'stop', node.TIMER + '.timer'))

    def test_finish_rejects_racing_rollback_marker(self):
        with patch.object(node, 'read', side_effect=lambda name: {'passed': True} if name == 'renewal' else {'sha256': 'stream'}), \
             patch.object(node, 'STREAM') as stream, patch.object(node, 'digest', return_value='stream'), \
             patch.object(node, 'exists', side_effect=[False, True]), patch.object(node, 'run'), \
             patch.object(node.subprocess, 'run', return_value=MagicMock(returncode=3)), \
             patch.object(node, 'save') as save:
            stream.is_file.return_value = True
            with self.assertRaisesRegex(RuntimeError, 'raced'):
                node.finish()
            save.assert_not_called()


if __name__ == '__main__':
    unittest.main()
