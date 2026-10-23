"""Offline tests: guards, the TLP filter, output shaping, every tool against a fake OpenCTI, error
mapping, injection attempts, caps, secret handling and the MCP bearer auth."""

from __future__ import annotations

import json
import logging

import httpx
import pytest
from fakes import MCP_TOKEN, TOKEN, FakeOpenCTI, conn, indicator, observable, report, settings
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import ValidationError

from opencti_mcp_server import queries
from opencti_mcp_server import server as srv
from opencti_mcp_server.config import Settings
from opencti_mcp_server.guards import TlpGuard, check_id, detect_kind, indicator_filters, observable_lookup
from opencti_mcp_server.output import clean, fit

ZWSP, RLO, BEL = chr(0x200B), chr(0x202E), chr(0x07)


async def call(mcp, name, args):
    """Call a tool in-process. Tool errors come back as their message (on the wire, is_error results)."""
    try:
        result = await mcp.call_tool(name, args)
    except ToolError as e:
        return str(e)
    return json.loads(result.content[0].text)


@pytest.fixture
def octi():
    """Install a fake OpenCTI; tests fill `fake.responses` by operation name."""
    fake = FakeOpenCTI()
    srv.set_client(fake.client())
    yield fake
    srv.set_client(None)


@pytest.fixture
def mcp():
    return srv.build_server(settings())


# --- settings -----------------------------------------------------------------------------------


def test_settings_defaults_and_tlp_normalised():
    s = settings(opencti_max_tlp="amber+strict")
    assert s.opencti_max_tlp == "TLP:AMBER+STRICT"
    assert s.opencti_max_first == 50 and s.mcp_max_output_chars == 20_000 and s.opencti_verify_tls is True
    assert s.graphql_url == "https://opencti.example.test/graphql"
    assert (
        settings(opencti_url="https://x.example.test/graphql/").graphql_url
        == "https://x.example.test/graphql"
    )
    assert Settings(_env_file=None).opencti_max_tlp == "TLP:AMBER+STRICT"


@pytest.mark.parametrize("bad", ["TLP:PURPLE", "PAP:RED", "red-ish"])
def test_settings_reject_unknown_tlp(bad):
    with pytest.raises(ValidationError):
        settings(opencti_max_tlp=bad)


def test_settings_never_show_the_token():
    s = settings()
    assert TOKEN not in repr(s) and TOKEN not in str(s) and TOKEN not in s.model_dump_json()


# --- guards -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,kind",
    [
        ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
        ("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "sha256"),
        ("a" * 128, "sha512"),
        ("203.0.113.7", "ipv4"),
        ("2001:db8::1", "ipv6"),
        ("https://malicious.example.com/payload?id=1", "url"),
        ("phish@example.com", "email"),
        ("malicious.example.com", "domain"),
        ("Sub-Domain.Example.co.uk.", "domain"),
    ],
)
def test_detect_kind(value, kind):
    assert detect_kind(value) == kind


@pytest.mark.parametrize("value", ["not a value", "abc", "1234", "deadbeef", "' OR 1=1 --", "a.b/c d"])
def test_detect_kind_refuses_the_unrecognisable(value):
    with pytest.raises(ToolError, match="^bad request: could not detect"):
        detect_kind(value)


def test_observable_lookup_filters():
    kind, value, types, filters = observable_lookup("MALICIOUS.Example.COM.", None)
    assert (kind, value, types) == ("domain", "malicious.example.com", ["Domain-Name", "Hostname"])
    assert filters == {
        "mode": "and",
        "filters": [{"key": ["value"], "values": ["malicious.example.com"], "operator": "eq", "mode": "or"}],
        "filterGroups": [],
    }
    kind, value, types, filters = observable_lookup(
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", None
    )
    assert types == ["StixFile"] and filters["filters"][0]["key"] == ["hashes.SHA-256"]
    assert filters["filters"][0]["values"] == [value.lower()] and value == value.lower()
    assert observable_lookup("files.example.com", "hostname")[2] == ["Hostname"]


@pytest.mark.parametrize(
    "value,kind",
    [
        ("203.0.113.7", "ipv6"),
        ("d41d8cd98f00b204e9800998ecf8427e", "sha256"),
        ("example.com", "url"),
        ("x", "md5"),
        ("example.com", "bogus"),
    ],
)
def test_observable_lookup_refuses_mismatched_type(value, kind):
    with pytest.raises(ToolError, match="^bad request:"):
        observable_lookup(value, kind)


@pytest.mark.parametrize(
    "value", ["", "   ", "example.com" + BEL, "exa" + ZWSP + "mple.com", "x" * 2049, "evil.com\nmutation"]
)
def test_observable_lookup_refuses_bad_text(value):
    with pytest.raises(ToolError, match="^bad request:"):
        observable_lookup(value, None)


@pytest.mark.parametrize(
    "value",
    [
        "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b",
        "indicator--6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b",
        "IPv4-Addr--6C5E1F0A-2B3D-4E5F-8A9B-0C1D2E3F4A5B",
        "x-opencti-hostname--6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b",
    ],
)
def test_check_id_accepts(value):
    assert check_id(value) == value.lower()


@pytest.mark.parametrize(
    "value",
    [
        "",
        "123",
        "indicator--not-a-uuid",
        '6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b") { id } mutation { x',
        "../6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b",
        "--6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b",
        "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b ",
    ],
)
def test_check_id_refuses(value):
    if value.endswith(" "):
        # Surrounding whitespace is trimmed, not refused.
        assert check_id(value)
        return
    with pytest.raises(ToolError, match="^bad request: id must be"):
        check_id(value)


def test_indicator_filters_value_is_exact_and_escaped():
    f = indicator_filters(
        value="it's\\x", min_score=50, observable_type="StixFile", pattern_type="stix", include_revoked=False
    )
    value_group = f["filterGroups"][0]
    assert value_group["mode"] == "or"
    assert value_group["filters"][0] == {
        "key": ["name"],
        "values": ["it's\\x"],
        "operator": "eq",
        "mode": "or",
    }
    assert (
        value_group["filters"][1]["key"] == ["pattern"]
        and value_group["filters"][1]["operator"] == "contains"
    )
    assert value_group["filters"][1]["values"] == ["'it\\'s\\\\x'"]
    keys = [(x["key"], x["values"], x["operator"]) for x in f["filters"]]
    assert keys == [
        (["x_opencti_score"], ["50"], "gte"),
        (["x_opencti_main_observable_type"], ["StixFile"], "eq"),
        (["pattern_type"], ["stix"], "eq"),
        (["revoked"], ["false"], "eq"),
    ]
    assert all(len(x["key"]) == 1 for x in f["filters"] + value_group["filters"])
    assert (
        indicator_filters(
            value=None, min_score=None, observable_type=None, pattern_type=None, include_revoked=True
        )
        is None
    )


@pytest.mark.parametrize(
    "kw",
    [{"min_score": 101}, {"min_score": -1}, {"observable_type": "Malware"}, {"pattern_type": "lucene"}],
)
def test_indicator_filters_refuse(kw):
    args = {
        "value": None,
        "min_score": None,
        "observable_type": None,
        "pattern_type": None,
        "include_revoked": False,
    }
    with pytest.raises(ToolError, match="^bad request:"):
        indicator_filters(**(args | kw))


# --- TLP guard ----------------------------------------------------------------------------------


def node(*markings):
    from fakes import MARKINGS

    return {"objectMarking": [MARKINGS[m] if isinstance(m, str) else m for m in markings]}


@pytest.mark.parametrize(
    "markings,allowed",
    [
        ((), True),
        (("TLP:CLEAR",), True),
        (("TLP:GREEN",), True),
        (("TLP:AMBER",), True),
        (("TLP:AMBER+STRICT",), True),
        (("TLP:RED",), False),
        (("TLP:BLACK",), False),  # unknown TLP, ordered above the ceiling
        (("PAP:RED",), True),  # PAP is not TLP, whatever its order
        (("PAP:RED", "TLP:CLEAR"), True),
        (("statement",), True),
        (("TLP:CLEAR", "TLP:RED"), False),
        (({"definition_type": "TLP", "definition": "TLP:RED", "x_opencti_order": 2},), False),  # by name
        (({"definition_type": "TLP", "definition": "TLP:CUSTOM", "x_opencti_order": 9},), False),  # by order
        (({"definition_type": "TLP", "definition": "TLP:CUSTOM", "x_opencti_order": 3},), True),
        (({"definition_type": "TLP", "definition": "TLP:CUSTOM"},), False),  # unknown, no order: fail closed
        (({"definition_type": "tlp", "definition": "tlp:red", "x_opencti_order": 5},), False),
        (({"definition_type": "PAP", "definition": "TLP:RED", "x_opencti_order": 5},), True),  # type decides
    ],
)
def test_tlp_guard(markings, allowed):
    assert TlpGuard("TLP:AMBER+STRICT").allows(node(*markings)) is allowed


def test_tlp_guard_lower_ceiling():
    guard = TlpGuard("TLP:GREEN")
    assert guard.allows(node("TLP:GREEN")) and not guard.allows(node("TLP:AMBER"))
    assert guard.allows(node("PAP:RED"))  # PAP:RED has order 4 but is not TLP


# --- output -------------------------------------------------------------------------------------


def test_clean_strips_control_and_zero_width():
    assert clean("evil" + ZWSP + ".exa" + RLO + "mple" + BEL + ".com") == "evil.example.com"
    assert clean("line1\nline2\ttab") == "line1\nline2\ttab"
    assert clean("x" * 600, 500) == "x" * 499 + chr(0x2026)


def test_fit_marks_truncation_on_nested_lists():
    result = {"indicator": {"id": "x", "observables": [{"v": "y" * 100}] * 50}, "withheld": 0}
    out = json.loads(fit(result, ("indicator", "observables"), 1_000))
    assert out["truncated"]["list"] == "indicator.observables"
    assert out["truncated"]["original_items"] == 50
    assert out["truncated"]["returned_items"] == len(out["indicator"]["observables"]) < 50


# --- tools --------------------------------------------------------------------------------------


async def test_tools_are_read_only(mcp):
    tools = await mcp.list_tools()
    assert {t.name for t in tools} == {
        "lookup_observable",
        "search_indicators",
        "get_indicator",
        "get_observable",
        "observable_indicators",
    }
    for t in tools:
        assert t.annotations.read_only_hint is True
        assert t.annotations.destructive_hint is False
        assert t.annotations.idempotent_hint is True


def test_documents_are_fixed_queries_without_inline_values():
    for name, doc in queries.ALL.items():
        stripped = doc.strip()
        assert stripped.startswith("query "), name
        assert "mutation" not in doc and "subscription" not in doc, name
        assert '"' not in doc, f"{name} has an inline string literal"


async def test_lookup_observable(octi, mcp):
    obs = observable(
        "malicious.example.com",
        indicators=conn([indicator(), indicator(markings=("TLP:RED",))], total=7),
        reports=conn([report(), report(markings=("TLP:RED",))], total=3),
    )
    octi.responses["LookupObservable"] = {"data": {"stixCyberObservables": conn([obs])}}
    out = await call(mcp, "lookup_observable", {"value": "Malicious.Example.com"})
    req = octi.requests[0]
    assert req["url"] == "https://opencti.example.test/graphql"
    assert req["headers"]["authorization"] == f"Bearer {TOKEN}"
    assert req["body"]["query"] == queries.LOOKUP_OBSERVABLE
    v = req["body"]["variables"]
    assert v["types"] == ["Domain-Name", "Hostname"] and v["first"] == 10 and v["nInd"] == 5
    assert v["filters"]["filters"][0]["values"] == ["malicious.example.com"]
    assert out["query"] == {
        "value": "malicious.example.com",
        "type": "domain",
        "observable_types": ["Domain-Name", "Hostname"],
    }
    assert out["total"] == 1 and out["returned"] == 1 and out["has_more"] is False
    assert out["withheld"] == 2 and out["withheld_reason"] == "marked above TLP:AMBER+STRICT"
    o = out["observables"][0]
    assert o["value"] == "malicious.example.com" and o["type"] == "Domain-Name" and o["score"] == 70
    assert (
        o["markings"] == ["TLP:CLEAR"] and o["labels"] == ["phishing"] and o["created_by"] == "Example Feed"
    )
    assert o["indicators_total"] == 7 and len(o["indicators"]) == 1
    assert o["reports_total"] == 3 and len(o["reports"]) == 1
    assert set(o["reports"][0]) == {"id", "name", "published", "markings"}
    ind = o["indicators"][0]
    assert ind["pattern"] == "[domain-name:value = 'malicious.example.com']" and ind["score"] == 80
    assert "description" not in ind and "kill_chain_phases" not in ind  # compact


async def test_lookup_observable_hash_and_empty(octi, mcp):
    octi.responses["LookupObservable"] = {"data": {"stixCyberObservables": conn([])}}
    out = await call(mcp, "lookup_observable", {"value": "D41D8CD98F00B204E9800998ECF8427E"})
    v = octi.variables
    assert v["types"] == ["StixFile"]
    assert v["filters"]["filters"][0] == {
        "key": ["hashes.MD5"],
        "values": ["d41d8cd98f00b204e9800998ecf8427e"],
        "operator": "eq",
        "mode": "or",
    }
    assert out["total"] == 0 and out["observables"] == [] and out["withheld"] == 0


async def test_lookup_observable_file_hashes_shaped(octi, mcp):
    f = observable("d41d8cd98f00b204e9800998ecf8427e", "StixFile")
    octi.responses["LookupObservable"] = {"data": {"stixCyberObservables": conn([f])}}
    out = await call(mcp, "lookup_observable", {"value": "d41d8cd98f00b204e9800998ecf8427e", "type": "md5"})
    o = out["observables"][0]
    assert o["hashes"] == {"MD5": "d41d8cd98f00b204e9800998ecf8427e"} and o["name"] == "dropper.exe"


async def test_lookup_observable_tlp_withholds_top_level_and_nested(octi, mcp):
    visible = observable(
        "203.0.113.7",
        "IPv4-Addr",
        indicators=conn(
            [indicator(markings=("TLP:BLACK",)), indicator(markings=("TLP:AMBER+STRICT", "PAP:RED"))]
        ),
        reports=conn([report(markings=("TLP:RED",))]),
    )
    hidden = observable(
        "203.0.113.7",
        "IPv4-Addr",
        markings=("TLP:RED",),
        indicators=conn([indicator()]),
        reports=conn([report()]),
    )
    unmarked = observable("203.0.113.7", "IPv4-Addr", markings=(), indicators=conn([]), reports=conn([]))
    octi.responses["LookupObservable"] = {"data": {"stixCyberObservables": conn([visible, hidden, unmarked])}}
    out = await call(mcp, "lookup_observable", {"value": "203.0.113.7"})
    assert out["total"] == 3 and out["returned"] == 2
    # 1 RED observable (its children are not counted separately), 1 TLP:BLACK indicator, 1 RED report.
    assert out["withheld"] == 3
    assert [len(o["indicators"]) for o in out["observables"]] == [1, 0]
    assert out["observables"][0]["indicators"][0]["markings"] == ["TLP:AMBER+STRICT", "PAP:RED"]
    assert out["observables"][0]["reports"] == []
    assert TOKEN not in json.dumps(out)


async def test_lookup_observable_refuses_before_any_request(octi, mcp):
    for args in [
        {"value": "nothing recognisable"},
        {"value": "203.0.113.7", "type": "domain"},
        {"value": "203.0.113.7", "type": "IPv4-Addr"},
        {"value": 'evil.example.com"){id}} mutation { x'},
    ]:
        text = await call(mcp, "lookup_observable", args)
        assert "bad request:" in text, args
    assert octi.requests == []


async def test_search_indicators(octi, mcp):
    octi.responses["SearchIndicators"] = {
        "data": {
            "indicators": conn(
                [indicator(), indicator(markings=("TLP:RED",))], total=40, next_cursor="YWJjZA=="
            )
        }
    }
    out = await call(
        mcp, "search_indicators", {"value": "malicious.example.com", "min_score": 50, "first": 2}
    )
    v = octi.variables
    assert octi.requests[0]["body"]["query"] == queries.SEARCH_INDICATORS
    assert v["first"] == 2 and v["after"] is None and v["search"] is None and v["orderBy"] == "updated_at"
    assert v["filters"]["filters"][-1] == {
        "key": ["revoked"],
        "values": ["false"],
        "operator": "eq",
        "mode": "or",
    }
    assert out["total"] == 40 and out["returned"] == 1 and out["withheld"] == 1
    assert out["has_more"] is True and out["next_cursor"] == "YWJjZA=="
    ind = out["indicators"][0]
    assert ind["kill_chain_phases"] == ["mitre-attack:initial-access"] and ind["description"]
    assert ind["indicator_types"] == ["malicious-activity"] and ind["confidence"] == 75


async def test_search_indicators_search_paging_and_revoked(octi, mcp):
    octi.responses["SearchIndicators"] = {"data": {"indicators": conn([])}}
    out = await call(
        mcp, "search_indicators", {"search": "emotet loader", "include_revoked": True, "after": "YWJjZA=="}
    )
    v = octi.variables
    assert v["search"] == "emotet loader" and v["filters"] is None and v["orderBy"] == "_score"
    assert v["after"] == "YWJjZA==" and v["first"] == 10
    assert out["returned"] == 0 and "next_cursor" not in out


async def test_search_indicators_refusals(octi, mcp):
    for args, needle in [
        ({}, "give at least one of"),
        ({"search": "x", "first": 51}, "first must be between 1 and 50"),
        ({"search": "x", "first": 0}, "first must be between"),
        ({"search": "x", "after": "not a cursor!"}, "after must be"),
        ({"search": "x" * 201}, "search is longer"),
        ({"search": "x" + RLO}, "control or zero-width"),
        ({"min_score": 500}, "min_score"),
        ({"observable_type": "Malware"}, "observable_type must be one of"),
        ({"pattern_type": "graphql"}, "pattern_type must be one of"),
    ]:
        text = await call(mcp, "search_indicators", args)
        assert "bad request:" in text and needle in text, (args, text)
    assert octi.requests == []


async def test_search_indicators_first_capped_by_setting(octi):
    mcp = srv.build_server(settings(opencti_max_first=5))
    octi.responses["SearchIndicators"] = {"data": {"indicators": conn([])}}
    assert "first must be between 1 and 5" in await call(
        mcp, "search_indicators", {"search": "x", "first": 6}
    )
    await call(mcp, "search_indicators", {"search": "x", "first": 5})
    assert octi.variables["first"] == 5


async def test_injection_shaped_values_stay_variables(octi, mcp):
    payloads = [
        '") { id } } mutation { userAdd(input: {}) { id } } #',
        "'] OR [x:y = '",
        "{__schema{types{name}}}",
        "$filters",
    ]
    octi.responses["SearchIndicators"] = {"data": {"indicators": conn([])}}
    for p in payloads:
        await call(mcp, "search_indicators", {"value": p, "search": p[:200]})
    for req, p in zip(octi.requests, payloads, strict=True):
        assert req["body"]["query"] == queries.SEARCH_INDICATORS
        assert req["body"]["variables"]["search"] == p
        group = req["body"]["variables"]["filters"]["filterGroups"][0]
        assert group["filters"][0]["values"] == [p]


async def test_get_indicator(octi, mcp):
    ind = indicator(
        x_opencti_observable_values=[
            {"type": "Domain-Name", "value": "malicious.example.com", "hashes": None}
        ],
        externalReferences={
            "edges": [
                {"node": {"source_name": "Example", "url": "https://ref.example.org/1", "external_id": None}}
            ]
        },
        observables=conn(
            [
                {
                    "id": "o1",
                    "entity_type": "Domain-Name",
                    "observable_value": "malicious.example.com",
                    "objectMarking": [],
                }
            ]
        ),
        reports=conn([report(), report(markings=("TLP:RED",))], total=2),
    )
    octi.responses["GetIndicator"] = {"data": {"indicator": ind}}
    out = await call(mcp, "get_indicator", {"id": "Indicator--6C5E1F0A-2B3D-4E5F-8A9B-0C1D2E3F4A5B"})
    assert octi.variables == {"id": "indicator--6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b", "nObs": 10}
    i = out["indicator"]
    assert i["name"] == "malicious.example.com" and i["revoked"] is False and i["detection"] is True
    assert i["observable_values"] == [{"type": "Domain-Name", "value": "malicious.example.com"}]
    assert i["external_references"] == [{"source_name": "Example", "url": "https://ref.example.org/1"}]
    assert i["observables"] == [
        {"id": "o1", "type": "Domain-Name", "value": "malicious.example.com", "markings": []}
    ]
    assert i["reports_total"] == 2 and len(i["reports"]) == 1 and out["withheld"] == 1


async def test_get_indicator_withheld_and_not_found(octi, mcp):
    octi.responses["GetIndicator"] = {"data": {"indicator": indicator(markings=("TLP:RED",))}}
    out = await call(mcp, "get_indicator", {"id": "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b"})
    assert out == {"indicator": None, "withheld": 1, "withheld_reason": "marked above TLP:AMBER+STRICT"}
    octi.responses["GetIndicator"] = {"data": {"indicator": None}}
    text = await call(mcp, "get_indicator", {"id": "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b"})
    assert "not found: no indicator with id 6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b" in text
    assert "bad request: id must be" in await call(mcp, "get_indicator", {"id": "indicator--x"})
    assert len(octi.requests) == 2


async def test_get_observable_with_relations(octi, mcp):
    def end(name, *markings):
        from fakes import MARKINGS

        return {
            "id": name,
            "entity_type": "Malware",
            "representative": {"main": name},
            "objectMarking": [MARKINGS[m] for m in markings],
        }

    rels = [
        {
            "id": "r1",
            "relationship_type": "related-to",
            "confidence": 50,
            "start_time": None,
            "stop_time": None,
            "objectMarking": [],
            "from": end("self"),
            "to": end("Example Malware", "TLP:GREEN"),
        },
        {
            "id": "r2",
            "relationship_type": "related-to",
            "confidence": 50,
            "start_time": None,
            "stop_time": None,
            "objectMarking": [],
            "from": end("self"),
            "to": end("Secret Malware", "TLP:RED"),
        },
        {
            "id": "r3",
            "relationship_type": "indicates",
            "confidence": 50,
            "start_time": None,
            "stop_time": None,
            "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED", "x_opencti_order": 5}],
            "from": end("self"),
            "to": end("Other"),
        },
    ]
    obs = observable(
        "203.0.113.7",
        "IPv4-Addr",
        externalReferences={"edges": []},
        indicators=conn([indicator()]),
        reports=conn([]),
    )
    octi.responses["GetObservable"] = {"data": {"stixCyberObservable": obs}}
    octi.responses["ObservableRelations"] = {
        "data": {"stixCyberObservable": {"id": obs["id"], "stixCoreRelationships": conn(rels)}}
    }
    out = await call(mcp, "get_observable", {"id": "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b"})
    assert "relations" not in out["observable"] and len(octi.requests) == 1
    out = await call(mcp, "get_observable", {"id": "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b", "relations": True})
    assert octi.requests[-1]["body"]["query"] == queries.OBSERVABLE_RELATIONS
    assert octi.requests[-1]["body"]["variables"]["first"] == 20
    o = out["observable"]
    assert [r["id"] for r in o["relations"]] == ["r1"] and o["relations_total"] == 3
    assert o["relations"][0]["to"] == {"id": "Example Malware", "type": "Malware", "name": "Example Malware"}
    assert out["withheld"] == 2 and len(o["indicators"]) == 1


async def test_get_observable_not_found_skips_relations(octi, mcp):
    octi.responses["GetObservable"] = {"data": {"stixCyberObservable": None}}
    text = await call(
        mcp, "get_observable", {"id": "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b", "relations": True}
    )
    assert "not found: no observable with id" in text and len(octi.requests) == 1


async def test_observable_indicators(octi, mcp):
    obs = {
        "id": "o1",
        "observable_value": "203.0.113.7",
        "objectMarking": [],
        "indicators": conn([indicator(), indicator(markings=("TLP:RED",))], total=12),
    }
    octi.responses["ObservableIndicators"] = {"data": {"stixCyberObservable": obs}}
    out = await call(
        mcp, "observable_indicators", {"id": "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b", "first": 25}
    )
    assert octi.variables == {"id": "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b", "first": 25}
    assert out["observable"] == {"id": "o1", "value": "203.0.113.7"}
    assert out["total"] == 12 and out["returned"] == 1 and out["withheld"] == 1
    assert "first must be between 1 and 50" in await call(
        mcp, "observable_indicators", {"id": "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b", "first": 51}
    )
    octi.responses["ObservableIndicators"] = {"data": {"stixCyberObservable": None}}
    assert "not found:" in await call(
        mcp, "observable_indicators", {"id": "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b"}
    )


# --- caps ---------------------------------------------------------------------------------------


async def test_field_caps_and_text_cleaning(octi, mcp):
    ind = indicator(
        name="evil" + ZWSP + ".example" + RLO + ".com" + BEL,
        description="d" * 600,
        pattern="[domain-name:value = '" + "p" * 1500 + "']",
        objectLabel=[{"value": f"label-{i}"} for i in range(30)],
    )
    octi.responses["SearchIndicators"] = {"data": {"indicators": conn([ind])}}
    out = await call(mcp, "search_indicators", {"search": "evil"})
    i = out["indicators"][0]
    assert i["name"] == "evil.example.com"
    assert len(i["description"]) == 500 and i["description"].endswith(chr(0x2026))
    assert len(i["pattern"]) == 1000
    assert len(i["labels"]) == 20 and i["labels_total"] == 30


async def test_output_capped_with_truncation_marker(octi):
    mcp = srv.build_server(settings(mcp_max_output_chars=3_000))
    many = [indicator(description="d" * 400) for _ in range(20)]
    octi.responses["SearchIndicators"] = {"data": {"indicators": conn(many, total=20)}}
    text = (await mcp.call_tool("search_indicators", {"search": "x", "first": 20})).content[0].text
    out = json.loads(text)
    assert len(text) <= 3_000
    assert out["truncated"]["original_items"] == 20 and out["truncated"]["returned_items"] == len(
        out["indicators"]
    )
    assert out["total"] == 20


# --- OpenCTI errors (HTTP 200 with `errors`) ----------------------------------------------------


def gql_error(code, message="boom", data=None):
    body = {"errors": [{"message": message, "extensions": {"code": code}, "name": code}]}
    if data is not None:
        body["data"] = data
    return body


@pytest.mark.parametrize(
    "response,prefix",
    [
        (
            gql_error("AUTH_REQUIRED", "You must be logged in to do this.", {"indicator": None}),
            "opencti refused the request:",
        ),
        (gql_error("FORBIDDEN_ACCESS", "You are not allowed to do this."), "opencti refused the request:"),
        (gql_error("GRAPHQL_VALIDATION_FAILED", 'Cannot query field "x" on type "Query".'), "bad request:"),
        (gql_error("NOT_FOUND", "Element not found"), "not found:"),
        (gql_error("DATABASE_ERROR", "engine down"), "opencti error:"),
        ({"errors": [{"message": "no code"}]}, "opencti error:"),
    ],
)
async def test_graphql_errors_are_tool_errors(octi, mcp, response, prefix):
    octi.responses["GetIndicator"] = response
    text = await call(mcp, "get_indicator", {"id": "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b"})
    assert f"Error executing tool get_indicator: {prefix}" in text
    code = response["errors"][0].get("extensions", {}).get("code")
    if code:
        assert f"({code})" in text


async def test_partial_data_with_errors_fails_closed(octi, mcp):
    partial = {
        "data": {"stixCyberObservables": conn([observable(indicators=conn([]), reports=conn([]))])},
        "errors": [
            {"message": "Partial failure", "extensions": {"code": "FORBIDDEN_ACCESS"}, "path": ["x"]},
            {"message": "Second", "extensions": {"code": "UNKNOWN"}},
        ],
    }
    octi.responses["LookupObservable"] = partial
    text = await call(mcp, "lookup_observable", {"value": "malicious.example.com"})
    assert "opencti refused the request: Partial failure (FORBIDDEN_ACCESS, +1 more)" in text
    assert "observables" not in text


@pytest.mark.parametrize(
    "response,needle",
    [
        (httpx.ReadTimeout("slow"), "opencti unavailable or timed out"),
        (httpx.ConnectError("refused"), "opencti unavailable or timed out"),
        (httpx.Response(502, text="Bad Gateway"), "opencti unavailable or timed out (HTTP 502)"),
        (httpx.Response(200, text="<html>login</html>"), "opencti error: non-JSON response (HTTP 200)"),
        (httpx.Response(500, json={"message": "x"}), "opencti error: HTTP 500"),
        (httpx.Response(200, json={"data": None}), "opencti error: response has no data"),
        (httpx.Response(200, json=[1, 2]), "opencti error: unexpected response"),
    ],
)
async def test_transport_failures(octi, mcp, response, needle):
    octi.responses["GetIndicator"] = response
    text = await call(mcp, "get_indicator", {"id": "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b"})
    assert needle in text


# --- secrets ------------------------------------------------------------------------------------


async def test_token_never_in_output_or_logs(octi, mcp, caplog):
    caplog.set_level(logging.DEBUG)
    octi.responses["LookupObservable"] = {
        "data": {"stixCyberObservables": conn([observable(indicators=conn([]), reports=conn([]))])}
    }
    octi.responses["SearchIndicators"] = gql_error("AUTH_REQUIRED", f"bad token {TOKEN} supplied")
    octi.responses["GetIndicator"] = httpx.ConnectError(f"cannot connect with {TOKEN}")
    octi.responses["GetObservable"] = httpx.Response(200, text=f"<html>{TOKEN}</html>")
    octi.responses["ObservableIndicators"] = gql_error("DATABASE_ERROR", f"echo {TOKEN}")
    outputs = [
        await call(mcp, "lookup_observable", {"value": "malicious.example.com"}),
        await call(mcp, "search_indicators", {"search": "x"}),
        await call(mcp, "get_indicator", {"id": "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b"}),
        await call(mcp, "get_observable", {"id": "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b"}),
        await call(mcp, "observable_indicators", {"id": "6c5e1f0a-2b3d-4e5f-8a9b-0c1d2e3f4a5b"}),
    ]
    assert "[redacted]" in outputs[1] and "[redacted]" in outputs[4]
    assert all(TOKEN not in json.dumps(o) for o in outputs)
    assert caplog.records and TOKEN not in caplog.text
    assert all(TOKEN not in str(r.args) for r in caplog.records)


# --- deep health and HTTP auth ------------------------------------------------------------------


async def test_deep_health_reports_version_only(octi):
    octi.responses["Health"] = {"data": {"about": {"version": "7.260907.0"}, "me": {"name": "svc-talon"}}}
    assert await srv.deep_health(settings()) == {"opencti_version": "7.260907.0", "authenticated": True}
    assert octi.requests[0]["body"]["query"] == queries.HEALTH


async def test_http_requires_bearer(octi):
    octi.responses["Health"] = {"data": {"about": {"version": "6.9.29"}, "me": {"name": "svc-talon"}}}
    app = srv.build_http_app(settings())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/healthz")).json() == {"status": "ok", "version": "0.1.0"}
        assert (await c.post("/mcp", json={})).status_code == 401
        assert (await c.post("/mcp", json={}, headers={"Authorization": "Bearer wrong"})).status_code == 401
        assert (
            await c.post("/mcp", json={}, headers={"Authorization": f"Basic {MCP_TOKEN}"})
        ).status_code == 401
        assert (
            await c.post("/mcp", json={}, headers={"Authorization": f"Bearer {TOKEN}"})
        ).status_code == 401
        assert (await c.get("/readyz")).status_code == 401
        ready = await c.get("/readyz", headers={"Authorization": f"Bearer {MCP_TOKEN}"})
        assert ready.status_code == 200
        assert ready.json() == {
            "status": "ok",
            "version": "0.1.0",
            "opencti_version": "6.9.29",
            "authenticated": True,
        }
        assert "svc-talon" not in ready.text


async def test_readyz_reports_auth_failure(octi):
    octi.responses["Health"] = gql_error(
        "AUTH_REQUIRED", "You must be logged in to do this.", {"about": None}
    )
    app = srv.build_http_app(settings())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/readyz", headers={"Authorization": f"Bearer {MCP_TOKEN}"})
    assert r.status_code == 503 and r.json()["error"].startswith("opencti refused the request:")


def test_http_refuses_to_start_without_token_or_with_the_opencti_token():
    with pytest.raises(SystemExit):
        srv.build_http_app(settings(mcp_auth_token=""))
    with pytest.raises(SystemExit):
        srv.build_http_app(settings(mcp_auth_token=TOKEN))
