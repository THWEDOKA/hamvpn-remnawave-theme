"""Offline USA sidecar contracts; no credentials, DNS calls or service changes."""
from contextlib import contextmanager
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import usa244site as s


@contextmanager
def memory_state(initial=None):
    state = copy.deepcopy(initial or {})
    with patch.object(s, 'guard'), patch.object(s, 'exists', side_effect=lambda n: n in state), \
         patch.object(s, 'read', side_effect=lambda n: copy.deepcopy(state[n])), \
         patch.object(s, 'save', side_effect=lambda n, v: state.update({n: copy.deepcopy(v)})):
        yield state


class USASiteTests(unittest.TestCase):
    def test_config_has_only_one_new_name_and_separate_certificate(self):
        for tls in (False, True):
            text = s.site_config(tls)
            self.assertIn('server_name in-us2.torcalc.ru;', text)
            self.assertIn('listen 80;', text)
            self.assertIn('location ^~ /.well-known/acme-challenge/', text)
            for prohibited in ('listen 443', 'listen [::]', ':9443 ', 'ssl_preread', 'stream {', 'in-de3', 'in-pl2'):
                self.assertNotIn(prohibited, text)
        text = s.site_config(True)
        self.assertIn('listen 127.0.0.1:19443 ssl http2;', text)
        self.assertIn('/etc/letsencrypt/live/in-us2.torcalc.ru/privkey.pem;', text)
        self.assertIn('shared:HAMUSA244TLS:', text)
        self.assertNotIn('ssl_certificate ', s.site_config())

    def test_dns_writes_intent_before_single_post(self):
        with memory_state() as state:
            posted = []
            def request(method, suffix='', body=None):
                if method == 'POST':
                    self.assertIn('dns-intent', state)
                    posted.append({**body, 'id': 'owned-id'}); return posted[0]
                return list(posted)
            with patch.object(s, 'client', return_value=request): result = s.dns()
            self.assertEqual(len(posted), 1)
            self.assertEqual(state['dns-created']['created_id'], 'owned-id')
            self.assertEqual(result['ttl'], 300); self.assertTrue(result['dns_only'])

    def test_existing_record_is_not_adopted_or_overwritten(self):
        for kind in ('A', 'AAAA', 'CNAME', 'TXT'):
            with self.subTest(kind=kind), memory_state():
                request = MagicMock(return_value=[{'type': kind}])
                with patch.object(s, 'client', return_value=request), self.assertRaises(RuntimeError): s.dns()
                self.assertEqual([c.args[0] for c in request.call_args_list], ['GET'])

    def test_lost_post_response_is_not_repeated(self):
        with memory_state() as state:
            request = MagicMock(side_effect=[[], RuntimeError('uncertain')])
            with patch.object(s, 'client', return_value=request), self.assertRaises(RuntimeError): s.dns()
            self.assertIn('dns-intent', state)
            request = MagicMock(return_value=[])
            with patch.object(s, 'client', return_value=request), self.assertRaises(RuntimeError): s.dns()
            self.assertEqual([c.args[0] for c in request.call_args_list], ['GET'])

    def test_uncertain_response_can_reconcile_exact_marker_only(self):
        wanted = s.wanted_record('owned-marker')
        initial = {'dns-intent': {'wanted': wanted}}
        for marker in ('foreign', 'owned-marker'):
            with memory_state(initial) as state:
                request = MagicMock(return_value=[{**wanted, 'id': 'one', 'comment': marker}])
                with patch.object(s, 'client', return_value=request):
                    if marker == 'foreign':
                        with self.assertRaises(RuntimeError): s.dns()
                    else: s.dns(); self.assertEqual(state['dns-created']['created_id'], 'one')
                self.assertTrue(all(c.args[0] == 'GET' for c in request.call_args_list))

    def test_dns_changed_id_or_duplicate_rejected(self):
        wanted = s.wanted_record('own')
        for rows in [[{**wanted, 'id': 'other'}], [{**wanted, 'id': 'one'}] * 2]:
            with memory_state({'dns-intent': {'wanted': wanted}, 'dns-created': {'created_id': 'one'}}):
                with patch.object(s, 'client', return_value=MagicMock(return_value=rows)), self.assertRaises(RuntimeError): s.dns()

    def test_rollback_will_not_delete_changed_dns(self):
        wanted = s.wanted_record('own')
        with memory_state({'dns-intent': {'wanted': wanted}, 'dns-created': {'created_id': 'one'}}):
            request = MagicMock(return_value=[{**wanted, 'id': 'one', 'content': '192.0.2.1'}])
            with patch.object(s, 'client', return_value=request), self.assertRaises(RuntimeError): s.dns_rollback()
            self.assertFalse(any(c.args[0] == 'DELETE' for c in request.call_args_list))

    def test_dns_two_resolvers_and_no_aaaa_required(self):
        a = ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n' + s.DOMAIN + '. 300 IN A ' + s.ENTRY + '\n'
        empty = ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n'
        with patch.object(s, 'run', side_effect=[a, empty, a, empty]) as run:
            s.converged()
            self.assertEqual(run.call_count, 4)
            self.assertEqual({c.args[1] for c in run.call_args_list}, {'@1.1.1.1', '@8.8.8.8'})
        for responses in [[a, empty + s.DOMAIN + '. 300 IN AAAA ::1\n'], [a, 'status: SERVFAIL,'], ['status: NXDOMAIN,']]:
            with patch.object(s, 'run', side_effect=responses), self.assertRaises(RuntimeError): s.converged()

    def test_wrong_or_old_external_proof_cannot_request_certificate(self):
        for proof, stamp in [('wrong', 100), ('good', 0)]:
            with memory_state({'http-ready': {'sha256': 'good', 'timestamp': stamp}}), \
                 patch.object(s.time, 'time', return_value=1900), patch.object(s, 'run') as run:
                with self.assertRaises(RuntimeError): s.certificate(proof)
                run.assert_not_called()

    def test_uncertain_acme_never_requests_second_issuance(self):
        with tempfile.TemporaryDirectory() as temporary, memory_state({
                'http-ready': {'sha256': 'good', 'timestamp': 100}, 'cert-intent': {'domain': s.DOMAIN}}):
            site = Path(temporary) / 'site'; site.write_text(s.site_config())
            enabled = MagicMock(); enabled.is_symlink.return_value = True; enabled.resolve.return_value = site
            with patch.object(s, 'SITE', site), patch.object(s, 'ENABLED', enabled), \
                 patch.object(s, 'LE', Path(temporary) / 'letsencrypt'), patch.object(s, 'converged'), \
                 patch.object(s.time, 'time', return_value=110), patch.object(s, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'do not repeat issuance'): s.certificate('good')
                run.assert_called_once_with('certbot', '--no-random-sleep-on-renew', '--version')

    def test_no_renewal_loop_no_help_parsing_or_vpn_mutation(self):
        source = Path(s.__file__).read_text()
        for prohibited in ('--dry-run', '--force-renewal', '--help', "'restart'", "'stop'", "'docker', 'restart'", 'nodes.json'):
            self.assertNotIn(prohibited, source)
        self.assertIn("'--no-random-sleep-on-renew', '--version'", source)
        self.assertIn("'systemctl', 'reload', 'nginx'", source)

    def test_root_guard(self):
        with patch.object(s.os, 'geteuid', return_value=1000, create=True), patch.object(s, 'run') as run:
            with self.assertRaises(RuntimeError): s.guard()
            run.assert_not_called()

    def test_root_only_archive_and_scoped_rollback_guards_present(self):
        source = Path(s.__file__).read_text()
        self.assertIn("(STATE / 'nginx-before.tar.gz').open('xb')", source)
        self.assertIn("os.chmod(stream.name, 0o600)", source)
        self.assertIn('Before-archive integrity failed', source)
        self.assertIn('Unsafe certificate private key', source)
        self.assertIn("HOOK.read_text() == HOOK_TEXT", source)
        self.assertIn("'certificates_and_shared_timer_retained': True", source)

    def test_tls_refuses_unverified_certificate_before_changes(self):
        with memory_state(), patch.object(s, 'write') as write, patch.object(s, 'run') as run:
            with self.assertRaises(RuntimeError): s.tls()
            write.assert_not_called(); run.assert_not_called()

    def test_dns_api_failure_never_exposes_token(self):
        credential = MagicMock()
        credential.is_symlink.return_value = False
        credential.stat.return_value = MagicMock(st_uid=0, st_mode=0o100600)
        credential.read_text.return_value = json.dumps({'zone_id': 'a' * 32, 'token': 'unit-test-not-a-real-secret'})
        with patch.object(s, 'CREDENTIALS', credential), patch.object(s.urllib.request, 'urlopen', side_effect=RuntimeError('unit-test-not-a-real-secret')):
            request = s.client()
            with self.assertRaises(RuntimeError) as error: request('GET')
            self.assertNotIn('unit-test-not-a-real-secret', str(error.exception))

    def test_command_error_output_is_only_saved_privately(self):
        result = MagicMock(returncode=1, stdout='private-test-output', stderr='private-test-error')
        with memory_state() as state, patch.object(s.subprocess, 'run', return_value=result):
            with self.assertRaises(RuntimeError) as raised: s.run('nginx', '-t')
            self.assertNotIn('private-test-output', str(raised.exception))
            self.assertEqual(state['command-error']['stdout'], 'private-test-output')


if __name__ == '__main__': unittest.main()
