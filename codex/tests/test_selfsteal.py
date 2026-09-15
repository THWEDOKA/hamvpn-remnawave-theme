import importlib.util
import json
from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/selfsteal"
SPEC = importlib.util.spec_from_file_location("selfsteal_render", SKILL / "scripts/render.py")
RENDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDER)


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.ids, self.links = [], set(), []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append(tag)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if "href" in attrs:
            self.links.append(attrs["href"])


class SelfstealTests(unittest.TestCase):
    def test_different_nodes_are_independent_and_deterministic(self):
        first = RENDER.render("DE5.example.com", "203.0.113.20")
        second = RENDER.render("fr7.example.net", "198.51.100.19", tls_port=9443, vpn_port=7443)
        self.assertEqual(first, RENDER.render("de5.example.com", "203.0.113.20"))
        self.assertEqual(first["hostname"], "de5.example.com")
        self.assertEqual(second["site_url"], "https://fr7.example.net:7443/")
        self.assertEqual(second["local_tls_target"], "127.0.0.1:9443")
        self.assertNotIn("de5.example.com", json.dumps(second))
        for result in (first, second):
            dns = json.loads(result["files"]["dns-record.json"])
            self.assertEqual(dns, {"type": "A", "name": result["hostname"],
                                  "content": result["ipv4"], "ttl": 300, "proxied": False})
            self.assertEqual(result["mode"], "templates-only")

    def test_unicode_hostname_is_ascii_in_config(self):
        result = RENDER.render("ремонт.рф", "203.0.113.20")
        self.assertEqual(result["hostname"], "xn--e1aoddhq.xn--p1ai")
        self.assertEqual(result["hostname"].encode("ascii").decode("idna"), "ремонт.рф")
        self.assertIn(f"server_name {result['hostname']};", result["files"]["nginx-tls.conf"])

    def test_hostname_injection_and_ambiguous_values_rejected(self):
        for value in ["", "localhost", "*.example.com", "example.com.", "a..com", ".a.com",
                      "https://example.com", "example.com:443", "example.com/path", "../etc/passwd",
                      "a.com;include /tmp/x", "a.com\nlisten 22", "$host.example.com", "a_b.com",
                      "-a.com", "a-.com", "a" * 64 + ".com", "203.0.113.20", " a.com", "a.com ",
                      "a\u200b.com"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                RENDER.render(value, "203.0.113.20")

    def test_ipv4_validation(self):
        for value in ["::1", "999.1.1.1", "1.1.1", "1.1.1.1;id", "203.0.113.020", 12, None]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                RENDER.render("de5.example.com", value)

    def test_conflicting_or_invalid_ports(self):
        for kwargs in [{"tls_port": 443}, {"vpn_port": 8443}, {"tls_port": 80},
                       {"vpn_port": 80}, {"tls_port": 0}, {"vpn_port": 65536},
                       {"tls_port": True}, {"tls_port": "8443;id"}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                RENDER.render("de5.example.com", "203.0.113.20", **kwargs)

    def test_title_is_escaped_and_has_no_control_characters(self):
        result = RENDER.render("de5.example.com", "203.0.113.20", '<script>alert("x")</script> & ремонт')
        page = Page()
        page.feed(result["files"]["site/index.html"])
        self.assertNotIn("script", page.tags)
        self.assertIn("&lt;script&gt;", result["files"]["site/index.html"])
        for title in ["", "  ", "a" * 101, "a\n", "abc\u202edef", "a\0"]:
            with self.subTest(title=title), self.assertRaises(ValueError):
                RENDER.render("de5.example.com", "203.0.113.20", title)

    def test_nginx_challenge_redirect_and_namespace_safety(self):
        for tls_port, vpn_port in [(8443, 443), (9443, 7443)]:
            result = RENDER.render("de5.example.com", "203.0.113.20", tls_port=tls_port, vpn_port=vpn_port)
            files = result["files"]
            for name in ["nginx-http.conf", "nginx-tls.conf"]:
                listeners = re.findall(r"listen\s+([^;]+);", files[name])
                self.assertTrue(set(listeners) <= {"80", f"127.0.0.1:{tls_port} ssl http2"})
                self.assertIn("location ^~ /.well-known/acme-challenge/", files[name])
                self.assertIn("try_files $uri =404;", files[name])
            self.assertIn("return 301 " + result["site_url"].rstrip("/") + "$request_uri;", files["nginx-tls.conf"])
            self.assertIn("/etc/letsencrypt/live/de5.example.com/fullchain.pem", files["nginx-tls.conf"])
            self.assertIn("TLSv1.3", files["nginx-tls.conf"])
            hook = files["renew-nginx.sh"]
            self.assertIn("set -eu", hook)
            self.assertLess(hook.index("nginx -t"), hook.index("systemctl reload nginx"))

    def test_static_page_and_all_links_resolve(self):
        files = RENDER.render("de5.example.com", "203.0.113.20")["files"]
        parser = Page()
        parser.feed(files["site/index.html"])
        self.assertEqual(parser.tags.count("h1"), 1)
        self.assertIn("main", parser.tags)
        self.assertFalse(set(parser.tags) & {"script", "iframe", "form", "input"})
        for href in parser.links:
            if href.startswith("#"):
                self.assertIn(href[1:], parser.ids)
            else:
                self.assertIn("site" + href, files)
        for value in files.values():
            self.assertNotIn("\r", value)
        self.assertNotIn("{{SITE_TITLE}}", files["site/index.html"])

    def test_render_never_connects_or_launches_a_process(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                patch("subprocess.Popen", side_effect=AssertionError("process forbidden")), \
                patch.object(Path, "write_text", side_effect=AssertionError("write forbidden")), \
                patch.object(Path, "write_bytes", side_effect=AssertionError("write forbidden")):
            self.assertEqual(RENDER.render("de5.example.com", "203.0.113.20")["mode"], "templates-only")

    def test_cli_json_and_error_exit(self):
        base = [sys.executable, "-X", "utf8", str(SKILL / "scripts/render.py")]
        good = subprocess.run(base + ["--hostname", "de5.example.com", "--ipv4", "203.0.113.20"],
                              capture_output=True, text=True, encoding="utf-8", timeout=10)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertEqual(json.loads(good.stdout)["hostname"], "de5.example.com")
        bad = subprocess.run(base + ["--hostname", "de5.example.com;id", "--ipv4", "203.0.113.20"],
                             capture_output=True, text=True, encoding="utf-8", timeout=10)
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(bad.stdout, "")

    def test_palette_contrast(self):
        def luminance(color):
            channels = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
            return sum((c / 12.92 if c <= .04045 else ((c + .055) / 1.055) ** 2.4) * w
                       for c, w in zip(channels, (.2126, .7152, .0722)))
        for fg, bg in [("#242424", "#fffce8"), ("#242424", "#d0d0ba"), ("#242424", "#ece9d4"),
                       ("#152f73", "#fffce8"), ("#152f73", "#ece9d4"), ("#fffce8", "#152f73")]:
            low, high = sorted([luminance(fg), luminance(bg)])
            self.assertGreaterEqual((high + .05) / (low + .05), 4.5)


if __name__ == "__main__":
    unittest.main()
