from pathlib import Path
import unittest

ROOT = Path(__file__).parent


class DeploymentTests(unittest.TestCase):
    def test_linux_release_has_explicit_lf_policy(self):
        self.assertIn('* text eol=lf', (ROOT / '.gitattributes').read_text())
        for name in ['Dockerfile', 'compose.yaml', 'openflux.patch']:
            self.assertNotIn(b'\r', (ROOT / name).read_bytes())

    def test_container_is_unprivileged_and_does_not_publish_ports(self):
        config = (ROOT / 'compose.yaml').read_text()
        for required in ['network_mode: bridge', 'user: "65534:65534"',
                         'read_only: true', 'cap_drop: [ALL]', 'no-new-privileges:true',
                         'create_host_path: false', 'mem_limit: 768m', 'pids_limit: 128']:
            self.assertIn(required, config)
        for forbidden in ['privileged:', 'cap_add:', 'network_mode: host', 'ports:', 'docker.sock']:
            self.assertNotIn(forbidden, config)

    def test_build_is_pinned_tested_and_uses_proxy(self):
        dockerfile = (ROOT / 'Dockerfile').read_text()
        self.assertEqual(dockerfile.count('7835b7155e193242d03c46ea6f3cf2b528aaa685'), 2)
        self.assertIn('go test -p 2 ./...', dockerfile)
        self.assertIn('"--mode", "proxy"', dockerfile)
        self.assertIn('"--url-file", "/run/secrets/document-url"', dockerfile)
        self.assertNotIn('entrypoint.sh', dockerfile)

    def test_secret_is_not_in_build_context(self):
        ignore = (ROOT / '.dockerignore').read_text().splitlines()
        self.assertEqual(ignore[0], '*')
        self.assertEqual(set(ignore[1:]), {'!Dockerfile', '!openflux.patch',
                                         '!exit_policy.go', '!exit_policy_test.go'})


if __name__ == '__main__':
    unittest.main()
