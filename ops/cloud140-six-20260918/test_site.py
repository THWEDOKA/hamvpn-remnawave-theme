"""Offline six-name scope contracts plus shared safety/lifecycle regressions."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import MagicMock, patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


wrapper = load('six_site_under_test', Path(__file__).with_name('site.py'))
s = wrapper.s
shared_tests = load('six_shared_test_fixtures', wrapper.SHARED_PATH.with_name('test_site.py'))
original = shared_tests.s
shared_tests.s = s


class SharedSafetyTests(unittest.TestCase):
    """Run domain-count-independent old lifecycle tests against the SIX engine."""


EXCLUDED = {
    'test_two_exact_records_intent_before_post_and_idempotent_readback',
    'test_existing_second_domain_prevents_any_create',
    'test_partial_success_resumes_only_never_attempted_domain',
    'test_dns_rollback_deletes_only_owned_records_and_readbacks',
    'test_two_resolvers_both_names_and_reject_aaaa_cname_servfail',
    'test_configuration_scopes_names_webroot_certificate_and_ports',
    'test_external_probe_uses_public_entry_and_each_host',
    'test_tls_both_names_require_verified_tls13_h2_and_loopback',
}
SharedSafetyTests.provider = shared_tests.DNSTests.provider
for cls in (shared_tests.DNSTests, shared_tests.HTTPAndProofTests,
            shared_tests.CertificateTests, shared_tests.SafetyTests):
    for name, method in vars(cls).items():
        if name.startswith('test_') and name not in EXCLUDED:
            setattr(SharedSafetyTests, name, method)
del cls, name, method


class SixScopeTests(unittest.TestCase):
    provider = shared_tests.DNSTests.provider

    def test_exact_scope_and_no_original_module_mutation(self):
        self.assertEqual(s.DOMAINS, ('in-at38.torcalc.ru', 'in-pl141.torcalc.ru', 'in-cz85.torcalc.ru',
                                   'in-gb216.torcalc.ru', 'in-us1.torcalc.ru', 'in-gb225.torcalc.ru'))
        self.assertEqual(original.DOMAINS, ('in-kz2.torcalc.ru', 'in-de245.torcalc.ru'))
        self.assertEqual(original.PORT, 9443)
        self.assertEqual(s.PORT, 9444)
        self.assertEqual(s.ENTRY, '176.108.245.140')
        for name in ('SITE', 'ENABLED', 'WEB', 'STATE', 'BACKUP', 'HOOK'):
            self.assertNotEqual(getattr(s, name), getattr(original, name))
            self.assertIn('cloud140-six', str(getattr(s, name)))
        self.assertEqual(s.ROOT, Path(__file__).resolve().parent)

    def test_shared_revision_is_pinned_fail_closed(self):
        self.assertEqual(hashlib.sha256(wrapper.SHARED_PATH.read_text(encoding='utf-8').encode()).hexdigest(),
                         wrapper.SHARED_SHA256)
        with patch.object(wrapper, 'SHARED_SHA256', '0' * 64), self.assertRaises(RuntimeError):
            wrapper.load_shared()

    def test_config_only_own_names_lineage_loopback_cache(self):
        config = s.site_config(True)
        self.assertEqual(re.findall(r'listen ([^;]+);', config), ['80', '127.0.0.1:9444 ssl http2'])
        for domain in s.DOMAINS:
            self.assertEqual(config.count(domain), 4 if domain == s.DOMAIN else 2)
        for foreign in ('in-kz2', 'in-de245', 'ham-cloud140-kz245', 'HAMCloud140KZ245', ':443', ':8443', ':9443'):
            self.assertNotIn(foreign, config)
        self.assertIn('shared:HAMCloud140Six:10m', config)
        self.assertIn('/etc/letsencrypt/live/in-at38.torcalc.ru/privkey.pem', config)
        self.assertNotIn('default_server', config)
        self.assertEqual(re.findall(r'listen ([^;]+);', s.site_config()), ['80'])

    def test_hook_is_lineage_scoped_and_no_old_names(self):
        self.assertIn('test "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/in-at38.torcalc.ru || exit 0', s.HOOK_TEXT)
        self.assertNotIn('in-kz2', s.HOOK_TEXT)
        self.assertNotIn('restart', s.HOOK_TEXT)
        self.assertIn('/usr/sbin/nginx -t', s.HOOK_TEXT)
        self.assertIn('/usr/bin/systemctl reload nginx', s.HOOK_TEXT)

    def test_all_six_dns_exact_idempotent_owned(self):
        with shared_tests.memory() as values:
            request, rows, calls = self.provider(values)
            with patch.object(s, 'client', return_value=request):
                s.dns()
                s.dns()
                self.assertEqual(sum(c[0] == 'POST' for c in calls), 6)
                self.assertTrue(all(re.fullmatch('ham-cloud140-six-[a-f0-9]{32}', r[0]['comment']) for r in rows.values()))
                self.assertTrue(all(r[0]['content'] == s.ENTRY and r[0]['proxied'] is False for r in rows.values()))
                s.dns_rollback()
            self.assertEqual([c[1] for c in calls if c[0] == 'DELETE'], ['/fixture-' + str(i) for i in range(6)])
            self.assertFalse(any(rows.values()))

    def test_conflict_in_sixth_name_stops_before_intent_or_writes(self):
        for kind in ('A', 'AAAA', 'CNAME', 'TXT'):
            with self.subTest(kind=kind), shared_tests.memory() as values:
                initial = {d: [] for d in s.DOMAINS}
                initial[s.DOMAINS[-1]] = [{'type': kind}]
                request, _, calls = self.provider(values, initial)
                with patch.object(s, 'client', return_value=request), self.assertRaises(RuntimeError):
                    s.dns()
                self.assertNotIn('dns-intent', values)
                self.assertTrue(all(c[0] == 'GET' for c in calls))

    def test_lost_response_reconciles_then_creates_only_remaining_five(self):
        with shared_tests.memory() as values:
            request, rows, calls = self.provider(values)
            def uncertain(method, suffix='', body=None):
                result = request(method, suffix, body)
                if method == 'POST':
                    raise RuntimeError('fixture lost response')
                return result
            with patch.object(s, 'client', return_value=uncertain), self.assertRaises(RuntimeError):
                s.dns()
            with patch.object(s, 'client', return_value=request):
                s.dns()
            self.assertEqual(sum(c[0] == 'POST' for c in calls), 6)
            self.assertTrue(all('dns-owned-' + str(i) in values for i in range(6)))

    def test_foreign_scope_intent_stops_without_provider_mutation(self):
        with shared_tests.memory() as values:
            request, _, calls = self.provider(values)
            with patch.object(s, 'client', return_value=request):
                s.dns()
                values['dns-intent']['wanted'][s.DOMAIN]['comment'] = 'ham-cloud140-kz245-' + 'a' * 32
                calls.clear()
                with self.assertRaises(RuntimeError):
                    s.dns()
                self.assertFalse(calls)

    def test_both_resolvers_verify_all_six_a_and_aaaa(self):
        def answer(*args, **kwargs):
            domain, kind = args[2:4]
            return ';; status: NOERROR,\n' + (domain + '. 300 IN A ' + s.ENTRY + '\n' if kind == 'A' else '')
        with patch.object(s, 'run', side_effect=answer) as run:
            s.converged()
        self.assertEqual(run.call_count, 24)
        self.assertEqual({c.args[2] for c in run.call_args_list}, set(s.DOMAINS))

    def test_external_probe_each_name_and_missing_sixth_rejected(self):
        ready, proof = shared_tests.ready_and_proof()
        with patch.object(s.subprocess, 'run', return_value=MagicMock(stdout='different host')), \
             patch.object(s, 'converged'), patch.object(s, 'http_get', return_value=(ready['token'] + '\n').encode()) as get:
            result = s.external_proof(ready)
        self.assertEqual([c.args[2] for c in get.call_args_list], [s.ENTRY] * 6)
        self.assertEqual({c['domain'] for c in result['checks']}, set(s.DOMAINS))
        proof['checks'].pop()
        with shared_tests.memory({'http-ready': ready}), patch.object(s.time, 'time', return_value=120), self.assertRaises(RuntimeError):
            s.check_external(proof)

    def test_tls_all_six_verified_names_and_no_public_listener(self):
        context = MagicMock()
        secure = context.wrap_socket.return_value.__enter__.return_value
        secure.version.return_value = 'TLSv1.3'
        secure.selected_alpn_protocol.return_value = 'h2'
        with patch.object(s, 'listeners', return_value=['127.0.0.1:9444']), \
             patch.object(s.ssl, 'create_default_context', return_value=context), patch.object(s.socket, 'create_connection'):
            result = s.local_tls()
        self.assertEqual({c['sni'] for c in result['checks']}, set(s.DOMAINS))
        self.assertEqual(context.minimum_version, s.ssl.TLSVersion.TLSv1_3)
        for listeners in ([], ['0.0.0.0:9444'], ['127.0.0.1:9444', '[::]:9444'], ['127.0.0.1:9443']):
            with patch.object(s, 'listeners', return_value=listeners), self.assertRaises(RuntimeError):
                s.local_tls()

    def test_baseline_includes_9443_and_other_nginx_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            old = folder / 'old-kz245.conf'
            old.write_text('fixture existing site')
            with patch.object(s, 'NGINX', folder), patch.object(s, 'run', return_value='fixture'), \
                 patch.object(s, 'listeners', side_effect=lambda port: ['127.0.0.1:' + str(port)]):
                value = s.baseline()
            self.assertEqual(set(value['legacy_listeners']), {'80', '443', '8443', '9443'})
            self.assertIn(str(old), value['nginx_files'])

    def test_9443_drift_blocks_without_reloading(self):
        before = {'legacy_listeners': {'9443': ['127.0.0.1:9443']}}
        after = copy.deepcopy(before)
        after['legacy_listeners']['9443'] = []
        with shared_tests.memory({'http-intent': {'before': before}}), patch.object(s, 'baseline', return_value=after), \
             patch.object(s, 'run') as run, self.assertRaises(RuntimeError):
            s.preserved()
        run.assert_not_called()

    def test_assets_reused_without_remote_resources_forms_or_history(self):
        manifest = s.asset_manifest()
        self.assertEqual(set(manifest), {'index.html', 'style.css'})
        page = (s.ROOT / 'assets/index.html').read_text(encoding='utf-8')
        self.assertNotRegex(page, r'https?://|<script|<form|tel:|mailto:')
        self.assertIn('Справочная страница', page)
        self.assertIn('viewport', page)
        for name in manifest:
            self.assertEqual((s.ROOT / 'assets' / name).read_text(encoding='utf-8'),
                             (original.ROOT / 'assets' / name).read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
