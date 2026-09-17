"""Offline contract/lifecycle tests. No DNS, SSH, ACME or service operations."""
from contextlib import contextmanager, ExitStack
import copy
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# 'site' is Python's startup module; load this operation under a unique name.
spec = importlib.util.spec_from_file_location('cloud140_kz245_site', Path(__file__).with_name('site.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


@contextmanager
def memory(initial=None):
    values = copy.deepcopy(initial or {})
    with patch.object(s, 'guard'), patch.object(s, 'private_file'), \
         patch.object(s, 'exists', side_effect=lambda key: key in values), \
         patch.object(s, 'read', side_effect=lambda key: copy.deepcopy(values[key])), \
         patch.object(s, 'save', side_effect=lambda key, value: values.update({key: copy.deepcopy(value)})):
        yield values


def ready_and_proof():
    token = 'ham-cloud140-' + 'a' * 32
    checksum = s.digest((token + '\n').encode())
    ready = {'entry': s.ENTRY, 'domains': list(s.DOMAINS), 'token': token, 'sha256': checksum, 'timestamp': 100}
    proof = {'entry': s.ENTRY, 'token': token, 'observed_at': 110,
             'checks': [{'domain': d, 'status': 200, 'sha256': checksum} for d in s.DOMAINS]}
    return ready, proof


@contextmanager
def fake_site(initial=None):
    with tempfile.TemporaryDirectory() as temporary, memory(initial) as values, ExitStack() as stack:
        root = Path(temporary)
        for name, relative in {'STATE': 'state', 'NGINX': 'nginx', 'SITE': 'nginx/sites-available/owned.conf',
                               'WEB': 'web', 'ACME': 'acme', 'LE': 'letsencrypt', 'BACKUP': 'state/before.tar.gz',
                               'HOOK': 'letsencrypt/renewal-hooks/deploy/owned-hook'}.items():
            stack.enter_context(patch.object(s, name, root / relative))
        for directory in (s.STATE, s.NGINX, s.SITE.parent, s.ACME, s.LE):
            directory.mkdir(parents=True, exist_ok=True)
        (s.NGINX / 'nginx.conf').write_text('fixture nginx configuration')
        enabled = MagicMock()
        link = {'exists': False}
        enabled.is_symlink.side_effect = lambda: link['exists']
        enabled.exists.side_effect = lambda: link['exists']
        enabled.resolve.return_value = s.SITE
        enabled.symlink_to.side_effect = lambda target: link.update(exists=True)
        enabled.unlink.side_effect = lambda: link.update(exists=False)
        stack.enter_context(patch.object(s, 'ENABLED', enabled))
        before = {'nginx_files': {'fixture': 'unchanged'}, 'nginx_master': '123', 'vpn': 'fixture true host',
                  'legacy_listeners': {str(p): ['*:' + str(p)] for p in (80, 443, 8443)}}
        stack.enter_context(patch.object(s, 'baseline', return_value=before))
        commands = stack.enter_context(patch.object(s, 'run', return_value=''))
        stack.enter_context(patch.object(s, 'listeners', return_value=[]))
        def response(domain, path='/', address='127.0.0.1'):
            if path == '/':
                return (s.WEB / 'index.html').read_bytes()
            return (values['http-intent']['token'] + '\n').encode()
        stack.enter_context(patch.object(s, 'http_get', side_effect=response))
        yield values, commands, link


class DNSTests(unittest.TestCase):
    def provider(self, values, initial=None):
        rows = copy.deepcopy(initial or {d: [] for d in s.DOMAINS})
        calls = []
        def request(method, suffix='', body=None):
            calls.append((method, suffix, body))
            if method == 'POST':
                index = s.DOMAINS.index(body['name'])
                self.assertIn('dns-attempt-' + str(index), values)
                row = {**body, 'id': 'fixture-' + str(index)}
                rows[body['name']] = [row]
                return row
            if method == 'DELETE':
                for domain in rows:
                    rows[domain] = [r for r in rows[domain] if '/' + r['id'] != suffix]
                return {}
            name = s.urllib.parse.parse_qs(s.urllib.parse.urlparse(suffix).query)['name'][0]
            return copy.deepcopy(rows[name])
        return request, rows, calls

    def test_two_exact_records_intent_before_post_and_idempotent_readback(self):
        with memory() as values:
            request, rows, calls = self.provider(values)
            with patch.object(s, 'client', return_value=request):
                self.assertTrue(s.dns()['dns_only'])
                s.dns()
            self.assertEqual(sum(c[0] == 'POST' for c in calls), 2)
            self.assertEqual(set(rows), set(s.DOMAINS))
            self.assertTrue(all(r[0]['content'] == s.ENTRY and not r[0]['proxied'] for r in rows.values()))

    def test_existing_second_domain_prevents_any_create(self):
        for kind in ('A', 'AAAA', 'CNAME', 'TXT'):
            with self.subTest(kind=kind), memory() as values:
                request, _, calls = self.provider(values, {s.DOMAINS[0]: [], s.DOMAINS[1]: [{'type': kind}]})
                with patch.object(s, 'client', return_value=request), self.assertRaises(RuntimeError):
                    s.dns()
                self.assertTrue(all(c[0] == 'GET' for c in calls))

    def test_lost_post_is_never_repeated_even_if_absent(self):
        with memory() as values:
            request, rows, calls = self.provider(values)
            def uncertain(method, suffix='', body=None):
                if method == 'POST':
                    raise RuntimeError('uncertain fixture response')
                return request(method, suffix, body)
            with patch.object(s, 'client', return_value=uncertain), self.assertRaises(RuntimeError):
                s.dns()
            self.assertIn('dns-attempt-0', values)
            with patch.object(s, 'client', return_value=request), self.assertRaises(RuntimeError):
                s.dns()
            self.assertTrue(all(c[0] == 'GET' for c in calls))

    def test_partial_success_resumes_only_never_attempted_domain(self):
        with memory() as values:
            request, rows, calls = self.provider(values)
            def interrupted(method, suffix='', body=None):
                if method == 'POST' and body['name'] == s.DOMAINS[0]:
                    request(method, suffix, body)
                    raise RuntimeError('lost response after successful creation')
                return request(method, suffix, body)
            with patch.object(s, 'client', return_value=interrupted), self.assertRaises(RuntimeError):
                s.dns()
            with patch.object(s, 'client', return_value=request):
                s.dns()
            self.assertEqual(sum(c[0] == 'POST' for c in calls), 2)
            self.assertIn('dns-owned-0', values)
            self.assertIn('dns-owned-1', values)

    def test_dns_rollback_preflights_both_records_before_any_delete(self):
        with memory() as values:
            request, rows, calls = self.provider(values)
            with patch.object(s, 'client', return_value=request):
                s.dns()
                rows[s.DOMAINS[1]][0]['content'] = 'fixture-other-address'
                with self.assertRaises(RuntimeError):
                    s.dns_rollback()
            self.assertFalse(any(c[0] == 'DELETE' for c in calls))

    def test_dns_rollback_deletes_only_owned_records_and_readbacks(self):
        with memory() as values:
            request, rows, calls = self.provider(values)
            with patch.object(s, 'client', return_value=request):
                s.dns()
                self.assertTrue(s.dns_rollback()['owned_dns_removed'])
            self.assertFalse(any(rows.values()))
            self.assertEqual([c[1] for c in calls if c[0] == 'DELETE'], ['/fixture-0', '/fixture-1'])

    def test_two_resolvers_both_names_and_reject_aaaa_cname_servfail(self):
        def answer(*args, **kwargs):
            domain, kind = args[2:4]
            return ';; status: NOERROR,\n' + (domain + '. 300 IN A ' + s.ENTRY + '\n' if kind == 'A' else '')
        with patch.object(s, 'run', side_effect=answer) as run:
            s.converged()
            self.assertEqual(run.call_count, 8)
            self.assertEqual({c.args[1] for c in run.call_args_list}, {'@1.1.1.1', '@8.8.8.8'})
        for text in ('status: SERVFAIL,', 'status: NXDOMAIN,', 'status: NOERROR,\nwrong.invalid. 3 IN A ' + s.ENTRY,
                     'status: NOERROR,\n' + s.DOMAIN + '. 3 IN CNAME other.invalid.'):
            with patch.object(s, 'run', return_value=text), self.assertRaises(RuntimeError):
                s.converged()
        with patch.object(s, 'run', side_effect=[answer('dig', '@x', s.DOMAIN, 'A'),
             'status: NOERROR,\n' + s.DOMAIN + '. 300 IN AAAA ::1\n']), self.assertRaises(RuntimeError):
            s.converged()

    def test_provider_errors_do_not_disclose_credentials(self):
        credential = MagicMock()
        credential.read_text.return_value = json.dumps({'zone_id': 'a' * 32, 'token': 'FIXTURE_SECRET'})
        with patch.object(s, 'CREDENTIALS', credential), patch.object(s, 'private_file'), \
             patch.object(s.urllib.request, 'urlopen', side_effect=RuntimeError('FIXTURE_SECRET')):
            with self.assertRaises(RuntimeError) as error:
                s.client()('GET')
        self.assertNotIn('FIXTURE_SECRET', str(error.exception))


class HTTPAndProofTests(unittest.TestCase):
    def test_configuration_scopes_names_webroot_certificate_and_ports(self):
        self.assertEqual(s.DOMAINS, ('in-kz2.torcalc.ru', 'in-de245.torcalc.ru'))
        self.assertEqual(s.ENTRY, '176.108.245.140')
        self.assertEqual(re.findall(r'listen ([^;]+);', s.site_config()), ['80'])
        self.assertEqual(re.findall(r'listen ([^;]+);', s.site_config(True)), ['80', '127.0.0.1:9443 ssl http2'])
        for domain in s.DOMAINS:
            self.assertIn(domain, s.site_config(True))
        self.assertIn('/var/www/ham-cloud140-kz245', s.site_config())
        self.assertIn('/etc/letsencrypt/live/in-kz2.torcalc.ru/privkey.pem', s.site_config(True))
        self.assertNotIn('8443', s.site_config(True))
        self.assertNotIn('default_server', s.site_config())

    def test_http_backup_before_mutation_and_safe_resume(self):
        with fake_site() as (values, commands, link):
            result = s.http()
            checksum = values['http-backup']['sha256']
            self.assertEqual(result['domains'], list(s.DOMAINS))
            self.assertTrue(link['exists'])
            s.http()
            self.assertEqual(checksum, values['http-backup']['sha256'])
            self.assertEqual(checksum, s.digest(s.BACKUP.read_bytes()))
            self.assertEqual(s.SITE.read_text(), s.site_config())
            self.assertFalse(any('restart' in c.args or 'stop' in c.args for c in commands.call_args_list))

    def test_http_rejects_changed_asset_on_resume_without_overwriting(self):
        with fake_site() as (values, commands, link):
            s.http()
            target = s.WEB / 'index.html'
            target.write_text('unrelated concurrent edit')
            commands.reset_mock()
            with self.assertRaisesRegex(RuntimeError, 'Asset changed'):
                s.http()
            self.assertEqual(target.read_text(), 'unrelated concurrent edit')
            self.assertFalse(any('reload' in c.args for c in commands.call_args_list))

    def test_http_rejects_corrupt_backup_before_any_reload(self):
        with fake_site() as (values, commands, link):
            s.http()
            s.BACKUP.write_bytes(b'fixture-corrupted')
            commands.reset_mock()
            with self.assertRaisesRegex(RuntimeError, 'integrity'):
                s.http()
            commands.assert_not_called()

    def test_http_failure_never_creates_ready_marker_and_restores_old_nginx(self):
        with fake_site() as (values, commands, link), patch.object(s, 'http_get', side_effect=RuntimeError('fixture failure')):
            with self.assertRaises(RuntimeError):
                s.http()
            self.assertNotIn('http-ready', values)
            self.assertFalse(s.SITE.exists())
            self.assertFalse(link['exists'])
            self.assertTrue(s.BACKUP.exists())

    def test_resume_refuses_changed_legacy_baseline(self):
        with fake_site() as (values, commands, link):
            s.http()
            with patch.object(s, 'baseline', return_value={'changed': True}), self.assertRaisesRegex(RuntimeError, 'drift'):
                s.http()

    def test_existing_nginx_name_blocks_before_backup_or_site_creation(self):
        with fake_site() as (values, commands, link):
            commands.side_effect = lambda *args, **kwargs: ('server_name ' + s.DOMAINS[1] + ';' if '-T' in args else '')
            with self.assertRaisesRegex(RuntimeError, 'already occurs'):
                s.http()
            self.assertNotIn('http-intent', values)
            self.assertFalse(s.BACKUP.exists())
            self.assertFalse(s.SITE.exists())

    def test_external_proof_requires_both_fresh_names_exact_body(self):
        ready, proof = ready_and_proof()
        for kind in ('good', 'missing', 'duplicate', 'bad_hash', 'bad_status', 'old', 'future', 'wrong_entry', 'wrong_token'):
            candidate = copy.deepcopy(proof)
            if kind == 'missing': candidate['checks'].pop()
            if kind == 'duplicate': candidate['checks'][1] = copy.deepcopy(candidate['checks'][0])
            if kind == 'bad_hash': candidate['checks'][0]['sha256'] = 'bad'
            if kind == 'bad_status': candidate['checks'][0]['status'] = 301
            if kind == 'old': candidate['observed_at'] = 1
            if kind == 'future': candidate['observed_at'] = 121
            if kind == 'wrong_entry': candidate['entry'] = 'other'
            if kind == 'wrong_token': candidate['token'] = 'other'
            with self.subTest(kind=kind), memory({'http-ready': ready}), patch.object(s.time, 'time', return_value=120):
                if kind == 'good': s.check_external(candidate)
                else:
                    with self.assertRaises(RuntimeError): s.check_external(candidate)

    def test_external_probe_cannot_run_on_entry(self):
        ready, _ = ready_and_proof()
        with patch.object(s.subprocess, 'run', return_value=MagicMock(stdout=s.ENTRY + '/32')), \
             patch.object(s, 'http_get') as get, self.assertRaises(RuntimeError):
            s.external_proof(ready)
        get.assert_not_called()

    def test_external_probe_uses_public_entry_and_each_host(self):
        ready, _ = ready_and_proof()
        with patch.object(s.subprocess, 'run', return_value=MagicMock(stdout='fixture external host')), \
             patch.object(s, 'converged'), patch.object(s, 'http_get', return_value=(ready['token'] + '\n').encode()) as get:
            proof = s.external_proof(ready)
        self.assertEqual({r['domain'] for r in proof['checks']}, set(s.DOMAINS))
        self.assertEqual([c.args[2] for c in get.call_args_list], [s.ENTRY, s.ENTRY])


class CertificateTests(unittest.TestCase):
    def test_missing_external_proof_blocks_before_acme(self):
        with fake_site() as (values, commands, link):
            s.http()
            commands.reset_mock()
            with self.assertRaises(RuntimeError):
                s.certificate(None)
            self.assertFalse(any(c.args[0] == 'certbot' for c in commands.call_args_list))

    def test_uncertain_acme_is_never_reissued(self):
        with fake_site() as (values, commands, link):
            s.http()
            values['cert-intent'] = {'domains': list(s.DOMAINS)}
            commands.reset_mock()
            with self.assertRaisesRegex(RuntimeError, 'do not repeat issuance'):
                s.certificate()
            self.assertFalse(any(c.args[0] == 'certbot' for c in commands.call_args_list))

    def test_certificate_issue_uses_one_lineage_two_domains_and_durable_intent(self):
        with fake_site() as (values, commands, link):
            s.http()
            def run(*args, **kwargs):
                if args[:2] == ('certbot', 'certonly'):
                    self.assertIn('cert-intent', values)
                    live = s.LE / 'live' / s.DOMAIN
                    live.mkdir(parents=True)
                    (live / 'cert.pem').write_text('fixture cert')
                return ''
            with patch.object(s, 'check_external'), patch.object(s, 'converged'), \
                 patch.object(s, 'certbot_features', return_value='certbot 2.9.0'), \
                 patch.object(s, 'account_for_issue', return_value='a' * 32), \
                 patch.object(s, 'certificate_details', return_value={'domains': list(s.DOMAINS)}), \
                 patch.object(s, 'run', side_effect=run) as call:
                self.assertTrue(s.certificate({})['certificate_valid'])
            issue = next(c.args for c in call.call_args_list if c.args[:2] == ('certbot', 'certonly'))
            self.assertEqual([issue[i + 1] for i, arg in enumerate(issue) if arg == '-d'], list(s.DOMAINS))
            self.assertEqual(issue[issue.index('--cert-name') + 1], s.DOMAIN)
            self.assertNotIn('--force-renewal', issue)

    def test_certbot_capability_probe_is_parse_only(self):
        with patch.object(s, 'run', return_value='certbot 2.9.0\n') as run:
            self.assertEqual(s.certbot_features(), 'certbot 2.9.0')
        self.assertTrue(all('--version' in c.args for c in run.call_args_list))
        self.assertIn('--run-deploy-hooks', run.call_args_list[-1].args)
        self.assertIn('--no-random-sleep-on-renew', run.call_args_list[-1].args)

    def test_tls_failed_handshake_restores_http_without_success_marker(self):
        with fake_site() as (values, commands, link):
            s.http()
            values['certificate'] = {'domains': list(s.DOMAINS)}
            with patch.object(s, 'certificate_details'), patch.object(s, 'local_tls', side_effect=RuntimeError('fixture handshake')):
                with self.assertRaises(RuntimeError):
                    s.tls()
            self.assertNotIn('tls-ready', values)
            self.assertEqual(s.SITE.read_text(), s.site_config())
            self.assertTrue(link['exists'])

    def test_tls_both_names_require_verified_tls13_h2_and_loopback(self):
        context = MagicMock()
        secure = context.wrap_socket.return_value.__enter__.return_value
        secure.version.return_value = 'TLSv1.3'
        secure.selected_alpn_protocol.return_value = 'h2'
        with patch.object(s, 'listeners', return_value=['127.0.0.1:9443']), \
             patch.object(s.ssl, 'create_default_context', return_value=context), patch.object(s.socket, 'create_connection'):
            result = s.local_tls()
        self.assertEqual({c['sni'] for c in result['checks']}, set(s.DOMAINS))
        self.assertEqual(context.minimum_version, s.ssl.TLSVersion.TLSv1_3)
        for listeners in ([], ['0.0.0.0:9443'], ['127.0.0.1:9443', '[::]:9443']):
            with patch.object(s, 'listeners', return_value=listeners), self.assertRaises(RuntimeError):
                s.local_tls()

    def test_renew_only_after_dns_proof_and_scoped_dryrun(self):
        with fake_site({'tls-ready': {}}) as (values, commands, link):
            renewal = s.LE / 'renewal' / (s.DOMAIN + '.conf')
            renewal.parent.mkdir()
            renewal.write_text('[renewalparams]\nauthenticator = webroot\nserver = ' + s.ACME_SERVER
                               + '\nwebroot_path = ' + str(s.ACME) + ',\n[[webroot_map]]\n'
                               + ''.join(d + ' = ' + str(s.ACME) + '\n' for d in s.DOMAINS))
            with patch.object(s, 'verify'), patch.object(s, 'check_external'), patch.object(s, 'converged'), \
                 patch.object(s, 'certbot_features', return_value='certbot 2.9.0'):
                self.assertTrue(s.renew({})['renewal_dry_run_passed'])
            renewal_call = next(c.args for c in commands.call_args_list if c.args[:2] == ('certbot', 'renew'))
            for flag in ('--dry-run', '--run-deploy-hooks', '--no-directory-hooks', '--no-random-sleep-on-renew'):
                self.assertIn(flag, renewal_call)
            self.assertEqual(renewal_call[renewal_call.index('--cert-name') + 1], s.DOMAIN)
            self.assertTrue(values['renewal']['passed'])

    def test_renew_failure_keeps_intent_no_success_and_no_timer_enable(self):
        with memory({'tls-ready': {}, 'renew-intent': {'timestamp': 1}}), patch.object(s, 'run') as run:
            with self.assertRaises(RuntimeError):
                s.renew({})
        run.assert_not_called()


class SafetyTests(unittest.TestCase):
    def test_private_file_requires_root_owner_and_no_group_world_access(self):
        for uid, mode, allowed in ((0, 0o100600, True), (0, 0o100640, False), (1000, 0o100600, False)):
            path = MagicMock()
            path.is_file.return_value = True
            path.is_symlink.return_value = False
            path.stat.return_value = MagicMock(st_uid=uid, st_mode=mode)
            with self.subTest(uid=uid, mode=mode), patch.object(s, 'safe_ancestors'):
                if allowed: s.private_file(path)
                else:
                    with self.assertRaises(RuntimeError): s.private_file(path)

    def test_root_guard_rejects_unprivileged_before_commands(self):
        with patch.object(s.os, 'geteuid', return_value=1000, create=True), patch.object(s, 'run') as run:
            with self.assertRaises(RuntimeError): s.guard()
        run.assert_not_called()

    def test_rollback_requires_coordinator_unused_target_confirmation(self):
        with memory(), patch.object(s, 'write') as write, patch.object(s, 'run') as run:
            with self.assertRaises(RuntimeError): s.rollback_site()
        write.assert_not_called()
        run.assert_not_called()

    def test_scoped_rollback_keeps_webroot_certificates_and_old_configuration(self):
        with fake_site() as (values, commands, link):
            s.http()
            self.assertTrue(s.rollback_site(True)['owned_vhost_removed'])
            self.assertFalse(s.SITE.exists())
            self.assertFalse(link['exists'])
            self.assertTrue((s.WEB / 'index.html').exists())
            self.assertEqual((s.NGINX / 'nginx.conf').read_text(), 'fixture nginx configuration')
            self.assertIn('site-rolled-back', values)

    def test_rollback_refuses_foreign_site_edit(self):
        with fake_site() as (values, commands, link):
            s.http()
            s.SITE.write_text('foreign edit')
            with self.assertRaises(RuntimeError): s.rollback_site(True)
            self.assertEqual(s.SITE.read_text(), 'foreign edit')
            self.assertTrue(link['exists'])

    def test_command_failure_keeps_diagnostics_private(self):
        with memory() as values, patch.object(s.subprocess, 'run', return_value=MagicMock(returncode=1, stdout='FIXTURE_SECRET', stderr='error')):
            with self.assertRaises(RuntimeError) as error: s.run('fixture')
            self.assertEqual(values['command-error']['stdout'], 'FIXTURE_SECRET')
        self.assertNotIn('FIXTURE_SECRET', str(error.exception))

    def test_write_refuses_pending_file_and_preserves_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'file'
            path.write_text('original')
            path.with_name(path.name + '.cloud140-pending').write_text('interrupted')
            with self.assertRaises(FileExistsError): s.write(path, 'replacement')
            self.assertEqual(path.read_text(), 'original')


if __name__ == '__main__':
    unittest.main()
