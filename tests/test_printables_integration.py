"""Provider-contract tests for the Printables integration.

Covers URL parsing edge cases (TEST-001), GraphQL normalization across payload
variants (TEST-002), the feasibility gate classification (TASK-004), and the
client's error taxonomy using a mocked transport (TASK-003) — no live network.
"""
import json

import httpx
import pytest

from app.integrations import printables_parser as parser
from app.integrations import printables_client as client


# ─────────────────────────── URL parsing (TEST-001) ───────────────────────────

class TestParsePrintablesUrl:
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://www.printables.com/model/258431-rugged-box-parametric", "258431"),
            ("https://www.printables.com/model/258431-rugged-box-parametric/files", "258431"),
            ("https://printables.com/model/258431", "258431"),
            ("https://www.printables.com/en/model/258431-rugged-box", "258431"),
            ("http://printables.com/model/99-x?utm=1#frag", "99"),
        ],
    )
    def test_valid_urls(self, url, expected):
        assert parser.parse_printables_url(url) == expected

    @pytest.mark.parametrize(
        "url",
        [
            "",
            "ftp://printables.com/model/1-x",
            "https://www.thingiverse.com/thing:258431",
            "https://printables.example.com/model/1-x",  # not in allowlist
            "https://www.printables.com/collections/123",  # no /model/
            "https://www.printables.com/model/",  # missing id
            "https://www.printables.com/model/rugged-box",  # no numeric id
        ],
    )
    def test_invalid_urls_raise(self, url):
        with pytest.raises(ValueError):
            parser.parse_printables_url(url)


# ──────────────────── Normalization variants (TEST-002) ────────────────────

def _model(**overrides):
    base = {
        "id": "258431",
        "name": "Rugged Box",
        "summary": "A box",
        "description": "<p>desc</p>",
        "filesCount": 0,
        "premium": False,
        "price": None,
        "excludeCommercialUsage": False,
        "license": {"name": "CC-BY", "abbreviation": "CC-BY"},
        "user": {"publicUsername": "Whity"},
        "stls": [],
        "gcodes": [],
        "slas": [],
        "otherFiles": [],
        "downloadPacks": [],
    }
    base.update(overrides)
    return base


class TestNormalizeFileCandidates:
    def test_stls_are_direct(self):
        model = _model(stls=[{"id": "1", "name": "a.stl", "fileSize": 100, "folder": "F"}])
        out = parser.normalize_file_candidates(model)
        assert len(out) == 1
        c = out[0]
        assert c["file_type"] == "stl"
        assert c["attachment_mode"] == parser.ATTACH_DIRECT
        assert c["source_id"] == "258431"
        assert c["file_id"] == "1"
        assert c["size_bytes"] == 100
        assert c["folder"] == "F"
        assert parser.supports_direct_asset_download(c) is True

    def test_other_files_present(self):
        model = _model(otherFiles=[{"id": "9", "name": "readme.txt", "fileSize": 5, "fileFormat": "txt"}])
        out = parser.normalize_file_candidates(model)
        assert out[0]["file_type"] == "other"
        assert out[0]["attachment_mode"] == parser.ATTACH_DIRECT
        assert out[0]["folder"] is None

    def test_download_packs_only_are_package(self):
        model = _model(downloadPacks=[{"id": "77", "name": "", "fileSize": 999, "fileType": "MODEL_FILES"}])
        out = parser.normalize_file_candidates(model)
        assert len(out) == 1
        c = out[0]
        assert c["file_type"] == "pack"
        assert c["attachment_mode"] == parser.ATTACH_PACKAGE
        assert "pack" in c["name"].lower()  # synthesized name for empty pack name
        assert parser.supports_direct_asset_download(c) is False

    def test_empty_file_results(self):
        assert parser.normalize_file_candidates(_model()) == []

    def test_premium_model_is_reference_only(self):
        model = _model(premium=True, stls=[{"id": "1", "name": "a.stl", "fileSize": 1}])
        out = parser.normalize_file_candidates(model)
        assert out[0]["attachment_mode"] == parser.ATTACH_REFERENCE
        assert parser.supports_direct_asset_download(out[0]) is False

    def test_priced_model_is_reference_only(self):
        model = _model(price="4.99", stls=[{"id": "1", "name": "a.stl", "fileSize": 1}])
        out = parser.normalize_file_candidates(model)
        assert out[0]["attachment_mode"] == parser.ATTACH_REFERENCE

    def test_deterministic_group_ordering(self):
        model = _model(
            stls=[{"id": "1", "name": "a.stl", "fileSize": 1}],
            downloadPacks=[{"id": "2", "name": "p", "fileSize": 1, "fileType": "MODEL_FILES"}],
            otherFiles=[{"id": "3", "name": "o", "fileSize": 1}],
        )
        out = parser.normalize_file_candidates(model)
        assert [c["file_type"] for c in out] == ["stl", "other", "pack"]

    def test_model_summary(self):
        s = parser.model_summary(_model(filesCount=3))
        assert s["title"] == "Rugged Box"
        assert s["files_count"] == 3
        assert s["author"] == "Whity"
        assert s["reference_only"] is False


# ──────────────────── Client w/ mocked transport (TASK-003) ────────────────────

def _mock_transport(handler):
    return httpx.MockTransport(handler)


def _graphql_response(data=None, errors=None, status=200):
    body = {}
    if data is not None:
        body["data"] = data
    if errors is not None:
        body["errors"] = errors
    return httpx.Response(status, json=body)


class TestPrintablesClient:
    def test_fetch_model_success(self):
        def handler(request):
            payload = json.loads(request.content)
            assert payload["variables"]["id"] == "258431"
            return _graphql_response({"print": _model(name="Rugged Box")})

        model = client.fetch_printables_model("258431", transport=_mock_transport(handler))
        assert model["name"] == "Rugged Box"

    def test_fetch_model_not_found(self):
        def handler(request):
            return _graphql_response({"print": None})

        with pytest.raises(client.PrintablesNotFound):
            client.fetch_printables_model("999999", transport=_mock_transport(handler))

    def test_fetch_model_invalid_id(self):
        with pytest.raises(client.PrintablesNotFound):
            client.fetch_printables_model("not-a-number")

    def test_graphql_errors_raise_response_error(self):
        def handler(request):
            return _graphql_response(errors=[{"message": "boom"}])

        with pytest.raises(client.PrintablesResponseError):
            client.fetch_printables_model("1", transport=_mock_transport(handler))

    def test_server_error_is_unavailable(self):
        def handler(request):
            return httpx.Response(503, text="down")

        with pytest.raises(client.PrintablesUnavailable):
            client.fetch_printables_model("1", transport=_mock_transport(handler))

    def test_timeout_is_unavailable(self):
        def handler(request):
            raise httpx.ConnectTimeout("slow", request=request)

        with pytest.raises(client.PrintablesUnavailable):
            client.fetch_printables_model("1", transport=_mock_transport(handler))

    def test_get_download_links_success(self):
        def handler(request):
            return _graphql_response({
                "getDownloadLink": {
                    "ok": True,
                    "errors": None,
                    "output": {
                        "link": "https://files.printables.com/x.stl",
                        "ttl": 86400,
                        "count": 1,
                        "files": [{"id": "1207177", "link": "https://files.printables.com/x.stl", "ttl": 86400, "fileType": "stl"}],
                    },
                }
            })

        files = client.get_download_links(
            "258431", [{"fileType": "stl", "ids": ["1207177"]}], transport=_mock_transport(handler)
        )
        assert files[0]["link"].endswith("x.stl")

    def test_get_download_links_failure(self):
        def handler(request):
            return _graphql_response({"getDownloadLink": {"ok": False, "errors": [{"field": "x", "messages": ["no"]}], "output": None}})

        with pytest.raises(client.PrintablesResponseError):
            client.get_download_links(
                "258431", [{"fileType": "stl", "ids": ["1"]}], transport=_mock_transport(handler)
            )

    def test_download_file_size_cap(self):
        def handler(request):
            return httpx.Response(200, content=b"x" * 50)

        with pytest.raises(client.PrintablesResponseError):
            client.download_file("https://files.printables.com/x.stl", max_bytes=10, transport=_mock_transport(handler))

    def test_download_file_success(self):
        def handler(request):
            return httpx.Response(200, content=b"STL-DATA")

        data = client.download_file("https://files.printables.com/x.stl", max_bytes=1024, transport=_mock_transport(handler))
        assert data == b"STL-DATA"
