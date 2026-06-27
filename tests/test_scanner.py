"""
Unit tests for OmniAdminFinder core modules.
"""

from __future__ import annotations

import pytest

from omnifinder.analyzer import WordlistGenerator
from omnifinder.fingerprint import ResponseClassifier
from omnifinder.reporter import ScanStats
from omnifinder.scanner import ProbeResult
from omnifinder.utils import domain_mutations, md5_preview, validate_url

# ---------------------------------------------------------------------------
# ResponseClassifier tests
# ---------------------------------------------------------------------------

class TestResponseClassifier:
    clf = ResponseClassifier()

    def test_extract_title_basic(self):
        body = "<html><head><title>Admin Dashboard</title></head></html>"
        assert self.clf.extract_title(body) == "Admin Dashboard"

    def test_extract_title_missing(self):
        assert self.clf.extract_title("<html><body>no title</body></html>") == ""

    def test_extract_title_multiline(self):
        body = "<title>\n  Spaces   Around  \n</title>"
        assert self.clf.extract_title(body) == "Spaces Around"

    def test_count_forms_zero(self):
        assert self.clf.count_forms("<html><body>no forms</body></html>") == 0

    def test_count_forms_one(self):
        body = '<form action="/login"><input type="text"/></form>'
        assert self.clf.count_forms(body) == 1

    def test_count_forms_multiple(self):
        body = "<form><input/></form><form><input/></form><form />"
        assert self.clf.count_forms(body) == 3

    def test_has_login_inputs_true(self):
        body = '<input type="password" name="password"/>'
        assert self.clf.has_login_inputs(body) is True

    def test_has_login_inputs_false(self):
        body = '<input type="text" name="search"/>'
        assert self.clf.has_login_inputs(body) is False

    def test_detect_technologies_wordpress(self):
        body = '<link rel="stylesheet" href="/wp-content/themes/main.css"/>'
        techs = self.clf.detect_technologies(body, {})
        assert "WordPress" in techs

    def test_detect_technologies_django(self):
        body = '<input type="hidden" name="csrfmiddlewaretoken" value="abc"/>'
        techs = self.clf.detect_technologies(body, {})
        assert "Django" in techs

    def test_detect_technologies_server_header(self):
        techs = self.clf.detect_technologies("", {"Server": "nginx/1.25.0"})
        assert "Nginx" in techs

    def test_detect_technologies_empty(self):
        assert self.clf.detect_technologies("generic page content", {}) == []

    # --- Scoring ---

    def test_score_404_returns_zero(self):
        assert self.clf.score(404, "", "", "", 0, [], False) == 0

    def test_score_500_returns_zero(self):
        assert self.clf.score(500, "", "", "", 0, [], False) == 0

    def test_score_401_high(self):
        score = self.clf.score(401, "", "", "", 0, [], False)
        assert score >= 30

    def test_score_200_with_admin_title(self):
        score = self.clf.score(200, "Admin Dashboard", "", "", 0, [], False)
        assert score >= 40

    def test_score_redirect_to_login(self):
        score = self.clf.score(302, "", "", "https://example.com/login.php", 0, [], False)
        assert score >= 20

    def test_score_login_form(self):
        score = self.clf.score(200, "Login", "", "", 1, [], True)
        assert score >= 35

    def test_score_capped_at_100(self):
        score = self.clf.score(
            401, "Admin Dashboard", "admin panel manage users", "", 3,
            ["WordPress", "PHP", "Apache"], True
        )
        assert score <= 100

    def test_score_200_no_signals(self):
        score = self.clf.score(200, "Home", "Welcome to our website", "", 0, [], False)
        assert score == 20  # just status code contribution


# ---------------------------------------------------------------------------
# WordlistGenerator tests
# ---------------------------------------------------------------------------

class TestWordlistGenerator:

    def test_generate_returns_list(self):
        gen = WordlistGenerator(target_url="https://example.com")
        paths = gen.generate()
        assert isinstance(paths, list)
        assert len(paths) > 0

    def test_generate_contains_common_paths(self):
        gen = WordlistGenerator(target_url="https://example.com")
        paths = gen.generate()
        assert any("admin" in p for p in paths)
        assert any("login" in p for p in paths)

    def test_generate_no_duplicates(self):
        gen = WordlistGenerator(target_url="https://example.com")
        paths = gen.generate()
        assert len(paths) == len(set(paths))

    def test_generate_custom_extensions(self):
        gen = WordlistGenerator(
            target_url="https://example.com",
            extensions=[".php", ".asp"],
        )
        paths = gen.generate()
        assert any(p.endswith(".php") for p in paths)
        assert any(p.endswith(".asp") for p in paths)
        assert not any(p.endswith(".jsp") for p in paths)

    def test_generate_domain_mutations(self):
        gen = WordlistGenerator(target_url="https://acme.example.com")
        paths = gen.generate()
        assert any("acme" in p for p in paths)

    def test_generate_custom_wordlist(self, tmp_path):
        wl = tmp_path / "paths.txt"
        wl.write_text("custom-path\nanother-path\n")
        gen = WordlistGenerator(
            target_url="https://example.com",
            custom_wordlist=str(wl),
        )
        paths = gen.generate()
        assert any("custom-path" in p for p in paths)
        assert any("another-path" in p for p in paths)

    def test_generate_custom_wordlist_missing(self):
        gen = WordlistGenerator(
            target_url="https://example.com",
            custom_wordlist="/nonexistent/file.txt",
        )
        # Should not raise; returns empty
        paths = gen.generate()
        assert isinstance(paths, list)


# ---------------------------------------------------------------------------
# Utility tests
# ---------------------------------------------------------------------------

class TestUtils:

    def test_validate_url_adds_scheme(self):
        assert validate_url("example.com") == "https://example.com"

    def test_validate_url_strips_trailing_slash(self):
        assert validate_url("https://example.com/") == "https://example.com"

    def test_validate_url_preserves_https(self):
        assert validate_url("https://example.com") == "https://example.com"

    def test_validate_url_preserves_http(self):
        assert validate_url("http://example.com") == "http://example.com"

    def test_validate_url_invalid(self):
        with pytest.raises(SystemExit):
            validate_url("https://")  # no hostname → should raise

    def test_domain_mutations_standard(self):
        mutations = domain_mutations("https://acme.example.com")
        assert "acme-admin" in mutations
        assert "admin-acme" in mutations
        assert "acmeadmin" in mutations

    def test_domain_mutations_empty_host(self):
        assert domain_mutations("https://") == []

    def test_md5_preview_consistent(self):
        data = b"hello world"
        assert md5_preview(data) == md5_preview(data)

    def test_md5_preview_length(self):
        result = md5_preview(b"test")
        assert len(result) == 32  # hex MD5


# ---------------------------------------------------------------------------
# ProbeResult / ScanStats tests
# ---------------------------------------------------------------------------

class TestModels:

    def test_probe_result_to_dict(self):
        r = ProbeResult(url="https://example.com/admin", status=200, confidence=80)
        d = r.to_dict()
        assert d["url"] == "https://example.com/admin"
        assert d["status"] == 200
        assert d["confidence"] == 80
        assert "technologies" in d

    def test_scan_stats_defaults(self):
        stats = ScanStats(target="https://example.com", timestamp="2026-01-01 00:00:00 UTC")
        assert stats.total_probed == 0
        assert stats.total_found == 0
        assert stats.concurrency == 50
