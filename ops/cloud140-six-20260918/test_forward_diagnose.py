"""Pure reconstruction/format tests: no SSH, server access or file writes."""
import subprocess
import unittest
from unittest.mock import Mock, patch

import forward_diagnose as d

TARGET = '/etc/ssh/sshd_config.d/73-ham-c1406-pl.conf'
FAILED = '/root/hamvpn-cloud140-six-20260918/forward/pl/exit/failed-policy.conf'
PATTERN = '/etc/ssh/sshd_config.d/*.conf'


class ReconstructTests(unittest.TestCase):
    def build(self, original, files=()):
        return d.reconstruct(original, TARGET, FAILED, lookup=Mock(return_value=list(files)))

    def test_default_include_inserts_only_failed_policy(self):
        self.assertEqual(self.build('Include ' + PATTERN + '\n'), 'Include ' + FAILED + '\n')

    def test_lexical_order_is_exact_not_appended(self):
        files = ['/etc/ssh/sshd_config.d/90-last.conf', '/etc/ssh/sshd_config.d/50-first.conf']
        result = self.build('Include ' + PATTERN + '\n', files)
        self.assertEqual(result.splitlines(), ['Include ' + files[1], 'Include ' + FAILED, 'Include ' + files[0]])

    def test_relative_include_resolves_under_etc_ssh(self):
        lookup = Mock(return_value=[])
        result = d.reconstruct('Include sshd_config.d/*.conf\n', TARGET, FAILED, lookup)
        self.assertEqual(result, 'Include ' + FAILED + '\n')
        lookup.assert_called_once_with(PATTERN)

    def test_quotes_case_and_comment_supported(self):
        self.assertEqual(self.build('  iNcLuDe "' + PATTERN + '" # local\n'), 'Include ' + FAILED + '\n')

    def test_non_target_lines_and_matches_remain_exact(self):
        before = '# comment\nPort 22\n'; after = 'Match User another\n    PermitTTY no\nMatch all\n'
        original = before + 'Include ' + PATTERN + '\n' + after
        self.assertEqual(self.build(original), before + 'Include ' + FAILED + '\n' + after)

    def test_multiple_patterns_preserve_pattern_order(self):
        lookup = Mock(side_effect=[['/etc/ssh/first.conf'], [], ['/etc/ssh/last.conf']])
        result = d.reconstruct('Include /etc/ssh/first.conf ' + PATTERN + ' /etc/ssh/last.conf\n', TARGET, FAILED, lookup)
        self.assertEqual(result.splitlines(), ['Include /etc/ssh/first.conf', 'Include ' + FAILED, 'Include /etc/ssh/last.conf'])

    def test_missing_or_nested_location_rejected(self):
        for original in ('Port 22\n', 'Include /etc/ssh/outer.conf\n', '# Include ' + PATTERN + '\n'):
            with self.subTest(original=original), self.assertRaises(RuntimeError): self.build(original)

    def test_duplicate_location_rejected(self):
        with self.assertRaises(RuntimeError): self.build(('Include ' + PATTERN + '\n') * 2)

    def test_existing_live_policy_rejected(self):
        with self.assertRaises(RuntimeError): self.build('Include ' + PATTERN + '\n', [TARGET])

    def test_glob_star_does_not_cross_directories(self):
        self.assertFalse(d.glob_matches_path(TARGET, '/etc/ssh/*'))
        with self.assertRaises(RuntimeError): self.build('Include /etc/ssh/*\n')

    def test_unsafe_included_filename_rejected(self):
        for filename in ('/etc/ssh/name with space.conf', '/etc/ssh/line\nbreak.conf'):
            with self.subTest(filename=filename), self.assertRaises(RuntimeError): self.build('Include ' + PATTERN + '\n', [filename])

    def test_unrelated_include_preserved_verbatim(self):
        head = 'Include "/etc/ssh/other.conf" # do not rewrite\n'
        self.assertEqual(self.build(head + 'Include ' + PATTERN + '\n'), head + 'Include ' + FAILED + '\n')

    def test_bad_syntax_or_recursive_glob_rejected(self):
        with self.assertRaises(ValueError): self.build('Include "unterminated\n')
        with self.assertRaises(RuntimeError): self.build('Include /etc/ssh/**/*.conf\n')


class DiagnosticTests(unittest.TestCase):
    def test_errors_output_names_not_raw_config(self):
        result = subprocess.CompletedProcess([], 255, 'PRIVATE', 'Bad configuration option: PubkeyAcceptedAlgorithms\nPRIVATE')
        summary = d.error_summary(result)
        self.assertEqual(summary['bad_option_names'], ['PubkeyAcceptedAlgorithms'])
        self.assertNotIn('PRIVATE', str(summary)); self.assertEqual(len(summary['stderr_sha256']), 64)

    def test_field_diffs_never_output_values(self):
        self.assertEqual(d.changed('password SECRET_A\nport 22\n', 'password SECRET_B\nport 22\n'), ['password'])

    def test_effective_candidate_uses_stdin_not_shell(self):
        run = Mock()
        n = d.f.route('pl')
        d.effective(run, n, 'root', '127.0.0.1', 'PRIVATE CONFIG')
        args, data = run.call_args.args
        self.assertEqual(args[:4], ['/usr/sbin/sshd', '-T', '-f', '/dev/stdin'])
        self.assertEqual(data, 'PRIVATE CONFIG'); self.assertNotIn('PRIVATE CONFIG', args)

    @patch.object(d.subprocess, 'run')
    @patch.object(d.time, 'monotonic', return_value=10)
    def test_deadline_bounds_subprocess(self, clock, run):
        d.Commands(12)(['readonly'], 'memory')
        self.assertEqual(run.call_args.kwargs['timeout'], 2)
        self.assertFalse(run.call_args.kwargs.get('shell', False))
        with self.assertRaises(TimeoutError): d.Commands(10)(['readonly'])
        self.assertEqual(run.call_count, 1)

    def test_restrictions_report_only_names(self):
        n = d.f.route('pl')
        text = '\n'.join(k.lower() + ' ' + v for k, v in d.f.policy(n).items()) + '\ndisableforwarding no'
        self.assertEqual(d.restrictions(n, text), [])
        self.assertEqual(d.restrictions(n, text.replace('maxsessions 0', 'maxsessions 1')), ['MaxSessions'])


if __name__ == '__main__': unittest.main()
