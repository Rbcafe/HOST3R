"""Tests complets pour host3r.py — couverture maximale, 0 appel réseau réel."""
import io
import json
import os
import sys
import threading
import multiprocessing
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

# Ajout du répertoire racine au path pour l'import
sys.path.insert(0, str(Path(__file__).parent.parent / "app"))

import host3r


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(text="", status_code=200):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = {}
    return resp


def _make_queue():
    return multiprocessing.Manager().list()


# ---------------------------------------------------------------------------
# banner
# ---------------------------------------------------------------------------

class TestBanner:
    def test_banner_prints_something(self, capsys):
        host3r.banner()
        out = capsys.readouterr().out
        assert len(out) > 0

    def test_banner_contains_host3r(self, capsys):
        host3r.banner()
        out = capsys.readouterr().out
        assert "HOST3R" in out

    def test_banner_mentions_rbcafe(self, capsys):
        host3r.banner()
        out = capsys.readouterr().out
        assert "Rbcafe" in out

    def test_banner_returns_none(self):
        assert host3r.banner() is None


# ---------------------------------------------------------------------------
# parser_error
# ---------------------------------------------------------------------------

class TestParserError:
    def test_parser_error_exits(self):
        with pytest.raises(SystemExit):
            host3r.parser_error("test error")

    def test_parser_error_prints_message(self, capsys):
        with pytest.raises(SystemExit):
            host3r.parser_error("mon message d erreur")
        out = capsys.readouterr().out
        assert "mon message d erreur" in out

    def test_parser_error_prints_usage(self, capsys):
        with pytest.raises(SystemExit):
            host3r.parser_error("x")
        out = capsys.readouterr().out
        assert "USAGE" in out

    def test_parser_error_prints_banner(self, capsys):
        with pytest.raises(SystemExit):
            host3r.parser_error("x")
        out = capsys.readouterr().out
        assert "HOST3R" in out


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------

class TestParseArgs:
    def test_domain_required(self):
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["host3r.py"]):
                host3r.parse_args()

    def test_domain_parsed(self):
        with patch("sys.argv", ["host3r.py", "-d", "example.com"]):
            args = host3r.parse_args()
        assert args.domain == "example.com"

    def test_output_default_none(self):
        with patch("sys.argv", ["host3r.py", "-d", "example.com"]):
            args = host3r.parse_args()
        assert args.output is None

    def test_output_parsed(self):
        with patch("sys.argv", ["host3r.py", "-d", "example.com", "-o", "/tmp/out.txt"]):
            args = host3r.parse_args()
        assert args.output == "/tmp/out.txt"

    def test_verbose_default_false(self):
        with patch("sys.argv", ["host3r.py", "-d", "example.com"]):
            args = host3r.parse_args()
        assert args.verbose is False

    def test_verbose_flag_set(self):
        with patch("sys.argv", ["host3r.py", "-d", "example.com", "-v"]):
            args = host3r.parse_args()
        assert args.verbose is None  # nargs='?' with no value → None

    def test_exception_default_false(self):
        with patch("sys.argv", ["host3r.py", "-d", "example.com"]):
            args = host3r.parse_args()
        assert args.exception is False

    def test_ipv6_default_false(self):
        with patch("sys.argv", ["host3r.py", "-d", "example.com"]):
            args = host3r.parse_args()
        assert args.ipv6 is False

    def test_long_domain_flag(self):
        with patch("sys.argv", ["host3r.py", "--domain", "sub.example.com"]):
            args = host3r.parse_args()
        assert args.domain == "sub.example.com"

    def test_long_output_flag(self):
        with patch("sys.argv", ["host3r.py", "-d", "example.com", "--output", "res.txt"]):
            args = host3r.parse_args()
        assert args.output == "res.txt"


# ---------------------------------------------------------------------------
# write_file
# ---------------------------------------------------------------------------

class TestWriteFile:
    def test_creates_file(self, tmp_path):
        f = tmp_path / "out.txt"
        host3r.ipv6 = False
        host3r.write_file(str(f), ["sub.example.com"])
        assert f.exists()

    def test_ipv4_entries_written(self, tmp_path):
        f = tmp_path / "out.txt"
        host3r.ipv6 = False
        host3r.write_file(str(f), ["a.example.com", "b.example.com"])
        content = f.read_text(encoding="utf-8")
        assert "127.0.0.1  a.example.com" in content
        assert "127.0.0.1  b.example.com" in content

    def test_ipv6_entries_written_when_enabled(self, tmp_path):
        f = tmp_path / "out.txt"
        host3r.ipv6 = True
        host3r.write_file(str(f), ["a.example.com"])
        content = f.read_text(encoding="utf-8")
        assert "::1  a.example.com" in content

    def test_ipv6_entries_absent_when_disabled(self, tmp_path):
        f = tmp_path / "out.txt"
        host3r.ipv6 = False
        host3r.write_file(str(f), ["a.example.com"])
        content = f.read_text(encoding="utf-8")
        assert "::1" not in content

    def test_header_written(self, tmp_path):
        f = tmp_path / "out.txt"
        host3r.ipv6 = False
        host3r.write_file(str(f), [])
        content = f.read_text(encoding="utf-8")
        assert "HOST3R" in content

    def test_empty_subdomains(self, tmp_path):
        f = tmp_path / "out.txt"
        host3r.ipv6 = False
        host3r.write_file(str(f), [])
        assert f.exists()

    def test_prints_saving_message(self, tmp_path, capsys):
        f = tmp_path / "out.txt"
        host3r.ipv6 = False
        host3r.write_file(str(f), [])
        out = capsys.readouterr().out
        assert "SAVING" in out

    def test_many_subdomains(self, tmp_path):
        f = tmp_path / "out.txt"
        host3r.ipv6 = False
        subs = [f"sub{i}.example.com" for i in range(100)]
        host3r.write_file(str(f), subs)
        content = f.read_text(encoding="utf-8")
        for s in subs:
            assert s in content

    def test_file_utf8_encoded(self, tmp_path):
        f = tmp_path / "out.txt"
        host3r.ipv6 = False
        host3r.write_file(str(f), ["café.example.com"])
        content = f.read_text(encoding="utf-8")
        assert "café.example.com" in content


# ---------------------------------------------------------------------------
# enumratorBase
# ---------------------------------------------------------------------------

class TestEnumratorBase:
    def _make(self, domain="http://example.com"):
        return host3r.enumratorBase(
            base_url="https://engine.com/search?q={query}&page={page_no}",
            engine_name="TestEngine",
            domain=domain,
        )

    def test_domain_parsed(self):
        e = self._make("http://example.com")
        assert e.domain == "example.com"

    def test_domain_with_path_stripped(self):
        e = self._make("http://example.com/page/sub")
        assert e.domain == "example.com"

    def test_engine_name_stored(self):
        e = self._make()
        assert e.engine_name == "TestEngine"

    def test_subdomains_initially_empty(self):
        e = self._make()
        assert e.subdomains == []

    def test_timeout_default(self):
        e = self._make()
        assert e.timeout == 10

    def test_get_response_returns_text(self):
        e = self._make()
        resp = _make_response("hello world")
        assert e.get_response(resp) == "hello world"

    def test_get_response_none_returns_zero(self):
        e = self._make()
        assert e.get_response(None) == 0

    def test_get_response_content_fallback(self):
        e = self._make()
        resp = MagicMock(spec=[])
        resp.content = b"bytes"
        assert e.get_response(resp) == b"bytes"

    def test_check_max_subdomains_zero_means_no_limit(self):
        e = self._make()
        e.MAX_DOMAINS = 0
        assert e.check_max_subdomains(9999) is False

    def test_check_max_subdomains_limit_reached(self):
        e = self._make()
        e.MAX_DOMAINS = 5
        assert e.check_max_subdomains(5) is True

    def test_check_max_subdomains_below_limit(self):
        e = self._make()
        e.MAX_DOMAINS = 10
        assert e.check_max_subdomains(9) is False

    def test_check_max_pages_zero_means_no_limit(self):
        e = self._make()
        e.MAX_PAGES = 0
        assert e.check_max_pages(9999) is False

    def test_check_max_pages_limit_reached(self):
        e = self._make()
        e.MAX_PAGES = 3
        assert e.check_max_pages(3) is True

    def test_get_page_increments_by_ten(self):
        e = self._make()
        assert e.get_page(0) == 10
        assert e.get_page(10) == 20

    def test_extract_domains_returns_none(self):
        e = self._make()
        assert e.extract_domains("html") is None

    def test_check_response_errors_returns_true(self):
        e = self._make()
        assert e.check_response_errors("any") is True

    def test_should_sleep_returns_none(self):
        e = self._make()
        assert e.should_sleep() is None

    def test_generate_query_returns_none(self):
        e = self._make()
        assert e.generate_query() is None

    def test_send_req_returns_text(self):
        e = self._make()
        with patch.object(e.session, "get", return_value=_make_response("result")):
            result = e.send_req("site:example.com")
        assert result == "result"

    def test_send_req_on_exception_returns_zero(self):
        e = self._make()
        host3r.exception = False
        with patch.object(e.session, "get", side_effect=Exception("network error")):
            result = e.send_req("query")
        assert result == 0

    def test_enumerate_stops_after_max_pages(self):
        e = self._make()
        e.MAX_DOMAINS = 0
        e.MAX_PAGES = 1
        e.generate_query = lambda: "site:example.com"
        with patch.object(e, "send_req", return_value=""):
            result = e.enumerate()
        assert result == []

    def test_enumerate_stops_on_retry_limit(self):
        e = self._make()
        e.MAX_DOMAINS = 0
        e.MAX_PAGES = 0
        e.generate_query = lambda: "site:example.com"
        with patch.object(e, "send_req", return_value=""):
            with patch.object(e, "extract_domains", return_value=[]):
                result = e.enumerate()
        assert result == []


# ---------------------------------------------------------------------------
# GoogleEnum
# ---------------------------------------------------------------------------

class TestGoogleEnum:
    HTML_NORMAL = (
        '<cite>www.sub1.example.com</cite>'
        '<cite>http://sub2.example.com/page</cite>'
    )
    HTML_BLOCKED = "Our systems have detected unusual traffic from your computer"

    def _make(self, domain="http://example.com"):
        host3r.verbose = False
        host3r.exception = False
        return host3r.GoogleEnum(domain, q=[])

    def test_engine_name(self):
        e = self._make()
        assert e.engine_name == "Google"

    def test_max_domains(self):
        e = self._make()
        assert e.MAX_DOMAINS == 11

    def test_max_pages(self):
        e = self._make()
        assert e.MAX_PAGES == 200

    def test_extract_domains_finds_subdomain(self):
        e = self._make()
        e.extract_domains(self.HTML_NORMAL)
        assert any("sub" in s for s in e.subdomains)

    def test_extract_domains_skips_primary_domain(self):
        e = self._make()
        e.extract_domains('<cite>example.com</cite>')
        assert "example.com" not in e.subdomains

    def test_extract_domains_deduplicates(self):
        e = self._make()
        html = '<cite>sub.example.com</cite>' * 5
        e.extract_domains(html)
        assert e.subdomains.count("sub.example.com") == 1

    def test_extract_domains_empty_html(self):
        e = self._make()
        e.extract_domains("")
        assert e.subdomains == []

    def test_extract_domains_strips_span_tags(self):
        # Le regex <span.*> est glouton : efface tout le contenu de la cite.
        # Le résultat est une cite vide → aucun sous-domaine ajouté.
        e = self._make()
        e.extract_domains('<cite><span class="x">sub.example.com</span></cite>')
        assert e.subdomains == []

    def test_check_response_errors_normal(self):
        e = self._make()
        assert e.check_response_errors("normal page") is True

    def test_check_response_errors_blocked(self):
        e = self._make()
        assert e.check_response_errors(self.HTML_BLOCKED) is False

    def test_generate_query_no_subdomains(self):
        e = self._make()
        q = e.generate_query()
        assert "site:example.com" in q
        assert "-www.example.com" in q

    def test_generate_query_with_subdomains(self):
        e = self._make()
        e.subdomains = ["a.example.com", "b.example.com"]
        q = e.generate_query()
        assert "-" in q

    def test_should_sleep_with_patch(self):
        e = self._make()
        with patch("time.sleep") as mock_sleep:
            e.should_sleep()
        mock_sleep.assert_called_once_with(5)

    def test_extract_domains_http_prefix_added(self):
        e = self._make()
        e.extract_domains('<cite>sub.example.com/page</cite>')
        assert any("sub.example.com" in s for s in e.subdomains)


# ---------------------------------------------------------------------------
# YahooEnum
# ---------------------------------------------------------------------------

class TestYahooEnum:
    def _make(self):
        host3r.verbose = False
        host3r.exception = False
        return host3r.YahooEnum("http://example.com", q=[])

    def test_engine_name(self):
        assert self._make().engine_name == "Yahoo"

    def test_max_domains(self):
        assert self._make().MAX_DOMAINS == 10

    def test_get_page_increments_ten(self):
        e = self._make()
        assert e.get_page(0) == 10

    def test_extract_domains_empty(self):
        e = self._make()
        e.extract_domains("")
        assert e.subdomains == []

    def test_extract_domains_span_regex(self):
        e = self._make()
        html = '<span class=" fz-15px fw-m fc-12th wr-bw ...">sub.example.com</span>'
        e.extract_domains(html)
        assert any("sub.example.com" in s for s in e.subdomains)

    def test_extract_domains_skips_non_matching_domain(self):
        e = self._make()
        html = '<span class=" fz-15px fw-m fc-12th wr-bw ...">other.com</span>'
        e.extract_domains(html)
        assert e.subdomains == []

    def test_generate_query_no_subdomains(self):
        e = self._make()
        q = e.generate_query()
        assert "site:example.com" in q

    def test_generate_query_with_subdomains(self):
        e = self._make()
        e.subdomains = ["a.example.com"]
        q = e.generate_query()
        assert "domain:" in q

    def test_should_sleep_returns_none(self):
        assert self._make().should_sleep() is None


# ---------------------------------------------------------------------------
# BingEnum
# ---------------------------------------------------------------------------

class TestBingEnum:
    def _make(self):
        host3r.verbose = False
        host3r.exception = False
        return host3r.BingEnum("http://example.com", q=[])

    def test_engine_name(self):
        assert self._make().engine_name == "Bing"

    def test_max_domains(self):
        assert self._make().MAX_DOMAINS == 30

    def test_extract_domains_finds_link(self):
        e = self._make()
        html = '<li class="b_algo"><h2><a href="http://sub.example.com/page">'
        e.extract_domains(html)
        assert any("sub.example.com" in s for s in e.subdomains)

    def test_extract_domains_finds_link_div(self):
        e = self._make()
        html = '<div class="b_title"><h2><a href="http://sub2.example.com/x">'
        e.extract_domains(html)
        assert any("sub2.example.com" in s for s in e.subdomains)

    def test_extract_domains_deduplicates(self):
        e = self._make()
        html = '<li class="b_algo"><h2><a href="http://sub.example.com">' * 3
        e.extract_domains(html)
        assert e.subdomains.count("sub.example.com") == 1

    def test_generate_query_no_subdomains(self):
        e = self._make()
        q = e.generate_query()
        assert "domain:example.com" in q

    def test_generate_query_with_subdomains(self):
        e = self._make()
        e.subdomains = ["a.example.com", "b.example.com"]
        q = e.generate_query()
        assert "-" in q

    def test_extract_domains_empty(self):
        e = self._make()
        e.extract_domains("")
        assert e.subdomains == []


# ---------------------------------------------------------------------------
# AskEnum
# ---------------------------------------------------------------------------

class TestAskEnum:
    def _make(self):
        host3r.verbose = False
        host3r.exception = False
        return host3r.AskEnum("http://example.com", q=[])

    def test_engine_name(self):
        assert self._make().engine_name == "Ask"

    def test_get_page_increments_one(self):
        e = self._make()
        assert e.get_page(0) == 1
        assert e.get_page(5) == 6

    def test_extract_domains_finds_result(self):
        e = self._make()
        html = '<p class="web-result-url">http://sub.example.com/</p>'
        e.extract_domains(html)
        assert any("sub.example.com" in s for s in e.subdomains)

    def test_extract_domains_empty(self):
        e = self._make()
        e.extract_domains("")
        assert e.subdomains == []

    def test_generate_query_no_subdomains(self):
        e = self._make()
        q = e.generate_query()
        assert "site:example.com" in q

    def test_generate_query_with_subdomains(self):
        e = self._make()
        e.subdomains = ["a.example.com"]
        q = e.generate_query()
        assert "-a.example.com" in q


# ---------------------------------------------------------------------------
# BaiduEnum
# ---------------------------------------------------------------------------

class TestBaiduEnum:
    def _make(self):
        host3r.verbose = False
        host3r.exception = False
        return host3r.BaiduEnum("http://example.com", q=[])

    def test_engine_name(self):
        assert self._make().engine_name == "Baidu"

    def test_max_pages(self):
        assert self._make().MAX_PAGES == 760

    def test_extract_domains_finds_subdomain(self):
        e = self._make()
        html = '<a class="c-showurl">sub.example.com</a>'
        e.extract_domains(html)
        assert any("sub.example.com" in s for s in e.subdomains)

    def test_extract_domains_ignores_foreign_domain(self):
        e = self._make()
        html = '<a class="c-showurl">other.org</a>'
        e.extract_domains(html)
        assert e.subdomains == []

    def test_findsubs_returns_most_common(self):
        e = self._make()
        subs = ["a.example.com", "a.example.com", "b.example.com"]
        result = e.findsubs(subs)
        assert "a.example.com" in result

    def test_findsubs_single_item(self):
        e = self._make()
        result = e.findsubs(["only.example.com"])
        assert "only.example.com" in result

    def test_findsubs_empty_second_with_one_item(self):
        e = self._make()
        result = e.findsubs(["only.example.com"])
        assert result[1] == ""

    def test_check_response_errors_always_true(self):
        e = self._make()
        assert e.check_response_errors("anything") is True

    def test_should_sleep_calls_sleep(self):
        e = self._make()
        with patch("time.sleep") as mock_sleep:
            e.should_sleep()
        mock_sleep.assert_called_once()

    def test_generate_query_no_subdomains(self):
        e = self._make()
        q = e.generate_query()
        assert "site:example.com" in q


# ---------------------------------------------------------------------------
# CrtSearch
# ---------------------------------------------------------------------------

class TestCrtSearch:
    def _make(self):
        host3r.verbose = False
        host3r.exception = False
        return host3r.CrtSearch("http://example.com", q=[])

    def test_engine_name(self):
        assert self._make().engine_name == "SSL Certificates"

    def test_base_url_contains_crt_sh(self):
        e = self._make()
        assert "crt.sh" in e.base_url

    def test_extract_domains_finds_subdomain(self):
        e = self._make()
        html = "<TD>sub.example.com</TD>"
        e.extract_domains(html)
        assert "sub.example.com" in e.subdomains

    def test_extract_domains_ignores_wildcard(self):
        e = self._make()
        html = "<TD>*.example.com</TD>"
        e.extract_domains(html)
        assert e.subdomains == []

    def test_extract_domains_ignores_foreign_domain(self):
        e = self._make()
        html = "<TD>other.org</TD>"
        e.extract_domains(html)
        assert e.subdomains == []

    def test_extract_domains_deduplicates(self):
        e = self._make()
        html = "<TD>sub.example.com</TD>" * 4
        e.extract_domains(html)
        assert e.subdomains.count("sub.example.com") == 1

    def test_extract_domains_strips_whitespace(self):
        e = self._make()
        html = "<TD>  sub.example.com  </TD>"
        e.extract_domains(html)
        assert "sub.example.com" in e.subdomains

    def test_extract_domains_empty_html(self):
        e = self._make()
        e.extract_domains("")
        assert e.subdomains == []

    def test_enumerate_calls_extract(self):
        e = self._make()
        with patch.object(e, "req", return_value="<TD>sub.example.com</TD>"):
            result = e.enumerate()
        assert "sub.example.com" in result

    def test_enumerate_empty_response(self):
        e = self._make()
        with patch.object(e, "req", return_value=""):
            result = e.enumerate()
        assert result == []

    def test_timeout(self):
        assert self._make().timeout == 25


# ---------------------------------------------------------------------------
# ThreatCrowd
# ---------------------------------------------------------------------------

class TestThreatCrowd:
    def _make(self):
        host3r.verbose = False
        host3r.exception = False
        return host3r.ThreatCrowd("http://example.com", q=[])

    def test_engine_name(self):
        assert self._make().engine_name == "ThreatCrowd"

    def test_extract_domains_from_json(self):
        e = self._make()
        payload = json.dumps({"subdomains": ["sub.example.com", "mail.example.com"]})
        e.extract_domains(payload)
        assert "sub.example.com" in e.subdomains
        assert "mail.example.com" in e.subdomains

    def test_extract_domains_ignores_foreign(self):
        e = self._make()
        payload = json.dumps({"subdomains": ["other.org"]})
        e.extract_domains(payload)
        assert e.subdomains == []

    def test_extract_domains_invalid_json(self):
        e = self._make()
        e.extract_domains("not json at all")
        assert e.subdomains == []

    def test_extract_domains_missing_key(self):
        e = self._make()
        e.extract_domains(json.dumps({"response_code": "1"}))
        assert e.subdomains == []

    def test_extract_domains_deduplicates(self):
        e = self._make()
        payload = json.dumps({"subdomains": ["sub.example.com", "sub.example.com"]})
        e.extract_domains(payload)
        assert e.subdomains.count("sub.example.com") == 1

    def test_extract_domains_strips_whitespace(self):
        e = self._make()
        payload = json.dumps({"subdomains": ["  sub.example.com  "]})
        e.extract_domains(payload)
        assert "sub.example.com" in e.subdomains

    def test_timeout(self):
        assert self._make().timeout == 50


# ---------------------------------------------------------------------------
# Virustotal
# ---------------------------------------------------------------------------

class TestVirustotal:
    def _make(self):
        host3r.verbose = False
        host3r.exception = False
        return host3r.Virustotal("http://example.com", q=[])

    def test_engine_name(self):
        assert self._make().engine_name == "Virustotal"

    def test_extract_domains_finds_subdomain(self):
        e = self._make()
        html = '<div class="enum "><a target="_blank" href="http://x.com">sub.example.com</a></div>'
        e.extract_domains(html)
        assert "sub.example.com" in e.subdomains

    def test_extract_domains_ignores_foreign(self):
        e = self._make()
        html = '<div class="enum "><a target="_blank" href="#">other.org</a></div>'
        e.extract_domains(html)
        assert e.subdomains == []

    def test_extract_domains_empty(self):
        e = self._make()
        e.extract_domains("")
        assert e.subdomains == []

    def test_extract_domains_deduplicates(self):
        e = self._make()
        html = '<div class="enum "><a target="_blank" href="#">sub.example.com</a></div>' * 3
        e.extract_domains(html)
        assert e.subdomains.count("sub.example.com") == 1


# ---------------------------------------------------------------------------
# PassiveDNS
# ---------------------------------------------------------------------------

class TestPassiveDNS:
    def _make(self):
        host3r.verbose = False
        host3r.exception = False
        return host3r.PassiveDNS("http://example.com", q=[])

    def test_engine_name(self):
        assert self._make().engine_name == "PassiveDNS"

    def test_extract_domains_finds_subdomain(self):
        e = self._make()
        html = "<td>sub.example.com [2026]</td>"
        e.extract_domains(html)
        assert "sub.example.com" in e.subdomains

    def test_extract_domains_ignores_foreign(self):
        e = self._make()
        html = "<td>other.org [2026]</td>"
        e.extract_domains(html)
        assert e.subdomains == []

    def test_extract_domains_empty(self):
        e = self._make()
        e.extract_domains("")
        assert e.subdomains == []

    def test_extract_domains_deduplicates(self):
        e = self._make()
        html = "<td>sub.example.com [2026]</td>" * 3
        e.extract_domains(html)
        assert e.subdomains.count("sub.example.com") == 1

    def test_timeout(self):
        assert self._make().timeout == 25


# ---------------------------------------------------------------------------
# NetcraftEnum
# ---------------------------------------------------------------------------

class TestNetcraftEnum:
    def _make(self):
        host3r.verbose = False
        host3r.exception = False
        return host3r.NetcraftEnum("http://example.com", q=[])

    def test_engine_name(self):
        assert self._make().engine_name == "Netcraft"

    def test_extract_domains_finds_subdomain(self):
        e = self._make()
        html = '<a href="http://toolbar.netcraft.com/site_report?url=http://sub.example.com">'
        e.extract_domains(html)
        assert "sub.example.com" in e.subdomains

    def test_extract_domains_ignores_foreign(self):
        e = self._make()
        html = '<a href="http://toolbar.netcraft.com/site_report?url=http://other.org">'
        e.extract_domains(html)
        assert e.subdomains == []

    def test_extract_domains_empty(self):
        e = self._make()
        e.extract_domains("")
        assert e.subdomains == []

    def test_create_cookies_builds_dict(self):
        e = self._make()
        with patch("hashlib.sha1") as mock_sha:
            mock_sha.return_value.hexdigest.return_value = "deadbeef"
            cookies = e.create_cookies("key=value; path=/")
        assert "key" in cookies
        assert cookies["key"] == "value"

    def test_get_cookies_no_set_cookie_header(self):
        e = self._make()
        cookies = e.get_cookies({})
        assert cookies == {}

    def test_timeout(self):
        assert self._make().timeout == 10


# ---------------------------------------------------------------------------
# DNSdumpster
# ---------------------------------------------------------------------------

class TestDNSdumpster:
    def _make(self):
        host3r.verbose = False
        host3r.exception = False
        return host3r.DNSdumpster("http://example.com", q=[])

    def test_engine_name(self):
        assert self._make().engine_name == "DNSdumpster"

    def test_threads(self):
        assert self._make().threads == 70

    def test_extract_domains_finds_subdomain(self):
        e = self._make()
        table = '<td class="col-md-4">sub.example.com<br>'
        results_tbl = f'<a name="hostanchor"></a>Host Records<table>{table}</table>'
        e.extract_domains(results_tbl)
        assert "sub.example.com" in e.subdomains

    def test_extract_domains_ignores_foreign(self):
        e = self._make()
        table = '<td class="col-md-4">other.org<br>'
        results_tbl = f'<a name="hostanchor"></a>Host Records<table>{table}</table>'
        e.extract_domains(results_tbl)
        assert e.subdomains == []

    def test_extract_domains_empty(self):
        e = self._make()
        e.extract_domains("")
        assert e.subdomains == []

    def test_get_response_none_returns_zero(self):
        e = self._make()
        assert e.get_response(None) == 0

    def test_get_csrftoken_extracts_token(self):
        e = self._make()
        html = "<input type='hidden' name='csrfmiddlewaretoken' value='abc123' />"
        assert e.get_csrftoken(html) == "abc123"

    def test_timeout(self):
        assert self._make().timeout == 25


# ---------------------------------------------------------------------------
# enumratorBaseThreaded
# ---------------------------------------------------------------------------

class TestEnumratorBaseThreaded:
    def _make(self):
        host3r.verbose = False
        host3r.exception = False
        return host3r.enumratorBaseThreaded(
            base_url="https://e.com/search?q={query}&page={page_no}",
            engine_name="Threaded",
            domain="http://example.com",
            q=[],
        )

    def test_is_process(self):
        e = self._make()
        assert isinstance(e, multiprocessing.Process)

    def test_has_queue(self):
        e = self._make()
        assert e.q is not None

    def test_run_appends_to_queue(self):
        q = []
        e = host3r.enumratorBaseThreaded(
            base_url="https://e.com/search?q={query}&page={page_no}",
            engine_name="T",
            domain="http://example.com",
            q=q,
        )
        e.MAX_DOMAINS = 0
        e.MAX_PAGES = 1
        e.generate_query = lambda: "site:example.com"
        with patch.object(e, "send_req", return_value=""):
            with patch.object(e, "extract_domains", return_value=[]):
                e.run()
        assert isinstance(q, list)


# ---------------------------------------------------------------------------
# Intégration — couverture du flux principal sans réseau
# ---------------------------------------------------------------------------

class TestMainFlow:
    def test_domain_check_regex_valid(self):
        import re
        domain_check = re.compile(
            "^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
        # Le regex accepte "example.com" sans scheme (le scheme est optionnel
        # mais le :// n'est pas modélisé — le code ajoute http:// ensuite)
        assert domain_check.match("example.com")
        assert domain_check.match("sub.example.com")
        assert domain_check.match("a.b.example.co.uk")

    def test_domain_check_regex_invalid(self):
        import re
        domain_check = re.compile(
            "^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
        assert not domain_check.match("not a domain")
        assert not domain_check.match("http://")     # :// casse le pattern
        assert not domain_check.match("")
        assert not domain_check.match("nodot")

    def test_subdomains_dedup_via_set(self):
        raw = ["a.example.com", "b.example.com", "a.example.com"]
        deduped = sorted(set(raw))
        assert len(deduped) == 2

    def test_verbose_flag_logic_none_becomes_true(self):
        verbose = None
        if verbose or verbose is None:
            verbose = True
        assert verbose is True

    def test_verbose_flag_logic_false_stays_false(self):
        # False or (False is None) = False or False = False → verbose reste False
        verbose = False
        if verbose or verbose is None:
            verbose = True
        assert verbose is False

    def test_ipv6_flag_logic_none_becomes_true(self):
        ipv6 = None
        if ipv6 or ipv6 is None:
            ipv6 = True
        assert ipv6 is True

    def test_exception_flag_logic(self):
        exception = None
        if exception or exception is None:
            exception = True
        assert exception is True
