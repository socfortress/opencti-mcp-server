"""Read-only checks against a live OpenCTI. Opt-in: deselected by default (`-m 'not live'`) and
skipped unless OPENCTI_LIVE=1.

    OPENCTI_LIVE=1 OPENCTI_LIVE_ENV_FILE=/path/to/opencti.env uv run pytest -m live -s

The env file (or the environment) supplies OPENCTI_URL and OPENCTI_TOKEN. Set OPENCTI_EXPECT_VERSION
to assert the platform version. Values to look up are picked from listing queries at run time, so
no instance data is hard-coded here, and the tests print counts and versions only.

Every request is checked to be a query before it is sent: these tests never mutate anything.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from opencti_mcp_server import server as srv
from opencti_mcp_server.client import OpenCTIClient
from opencti_mcp_server.config import Settings
from opencti_mcp_server.guards import TlpGuard

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.getenv("OPENCTI_LIVE") != "1", reason="OPENCTI_LIVE=1 not set"),
]

MARKING_FIELDS = "objectMarking { definition_type definition x_opencti_order }"

# Test-only listing queries, used to pick real values at run time. Read-only, like the server's own.
LIST_OBSERVABLES = f"""
query LiveListObservables($types: [String], $first: Int!) {{
  stixCyberObservables(types: $types, first: $first, orderBy: updated_at, orderMode: desc) {{
    edges {{ node {{ id entity_type observable_value {MARKING_FIELDS}
      ... on StixFile {{ hashes {{ algorithm hash }} }} }} }}
  }}
}}
"""
LIST_INDICATORS = f"""
query LiveListIndicators($first: Int!) {{
  indicators(first: $first, orderBy: updated_at, orderMode: desc) {{
    edges {{ node {{ id name {MARKING_FIELDS} }} }}
  }}
}}
"""
LIST_TLP = "query LiveListTlp { markingDefinitions(first: 100) { edges { node { id definition_type definition x_opencti_order } } } }"
COUNT_MARKED = """
query LiveCountMarked($filters: FilterGroup, $first: Int!) {
  indicators(filters: $filters, first: $first) { pageInfo { globalCount } edges { node { id } } }
  stixCyberObservables(filters: $filters, first: $first) { pageInfo { globalCount } edges { node { id } } }
  reports(filters: $filters, first: 1) { pageInfo { globalCount } }
}
"""


def _only_queries(request: httpx.Request) -> None:
    body = json.loads(request.content)
    if not body["query"].lstrip().startswith("query "):
        raise AssertionError("a live test tried to send something other than a query")


@pytest.fixture(scope="module")
def live_settings() -> Settings:
    env_file = os.getenv("OPENCTI_LIVE_ENV_FILE")
    s = Settings(_env_file=env_file) if env_file else Settings(_env_file=None)
    if not s.opencti_token.get_secret_value():
        pytest.skip("no OPENCTI_TOKEN for the live tests")
    return s


@pytest.fixture
async def live(live_settings):
    client = OpenCTIClient(live_settings)
    client._http.event_hooks["request"] = [_async(_only_queries)]
    srv.set_client(client)
    yield srv.build_server(live_settings), client
    await client.aclose()
    srv.set_client(None)


def _async(fn):
    async def hook(request):
        fn(request)

    return hook


async def call(mcp, name: str, args: dict[str, Any]) -> Any:
    try:
        result = await mcp.call_tool(name, args)
    except ToolError as e:
        return str(e)
    return json.loads(result.content[0].text)


def _visible(node: dict[str, Any]) -> bool:
    return TlpGuard("TLP:AMBER+STRICT").allows(node)


async def test_health(live, live_settings):
    health = await srv.deep_health(live_settings)
    print(f"\nlive: OpenCTI {health['opencti_version']}, authenticated={health['authenticated']}")
    assert health["authenticated"] is True
    expected = os.getenv("OPENCTI_EXPECT_VERSION")
    if expected:
        assert health["opencti_version"] == expected


@pytest.mark.parametrize("types,kind", [(["Domain-Name"], None), (["IPv4-Addr"], None), (["Url"], None)])
async def test_lookup_real_value(live, types, kind):
    mcp, client = live
    data = await client.execute(LIST_OBSERVABLES, {"types": types, "first": 10})
    nodes = [e["node"] for e in data["stixCyberObservables"]["edges"] if _visible(e["node"])]
    if not nodes:
        pytest.skip(f"no visible {types[0]} observables")
    target = nodes[0]
    out = await call(mcp, "lookup_observable", {"value": target["observable_value"]})
    assert isinstance(out, dict), out
    ids = [o["id"] for o in out["observables"]]
    print(
        f"\nlive lookup {types[0]}: total={out['total']} returned={out['returned']} withheld={out['withheld']} "
        f"indicators={[o.get('indicators_total') for o in out['observables']]} "
        f"reports={[o.get('reports_total') for o in out['observables']]}"
    )
    assert target["id"] in ids


async def test_lookup_real_hash(live):
    mcp, client = live
    data = await client.execute(LIST_OBSERVABLES, {"types": ["StixFile"], "first": 20})
    picks = [
        (h["algorithm"], h["hash"])
        for e in data["stixCyberObservables"]["edges"]
        if _visible(e["node"])
        for h in e["node"].get("hashes") or []
        if h["algorithm"] in ("MD5", "SHA-1", "SHA-256", "SHA-512")
    ]
    if not picks:
        pytest.skip("no visible file hashes")
    alg, value = picks[0]
    out = await call(mcp, "lookup_observable", {"value": value.upper()})
    print(f"\nlive lookup {alg} (upper-cased): total={out['total']} returned={out['returned']}")
    assert out["returned"] >= 1 and out["query"]["type"] == alg.replace("-", "").lower()


async def test_search_and_get(live):
    mcp, client = live
    data = await client.execute(LIST_INDICATORS, {"first": 10})
    nodes = [e["node"] for e in data["indicators"]["edges"] if _visible(e["node"])]
    if not nodes:
        pytest.skip("no visible indicators")
    name = nodes[0]["name"]

    exact = await call(mcp, "search_indicators", {"value": name, "include_revoked": True})
    print(f"\nlive search_indicators value: total={exact['total']} returned={exact['returned']}")
    assert exact["returned"] >= 1 and nodes[0]["id"] in [i["id"] for i in exact["indicators"]]

    page1 = await call(mcp, "search_indicators", {"min_score": 0, "first": 3})
    print(f"live search_indicators min_score=0 first=3: total={page1['total']} returned={page1['returned']}")
    assert page1["returned"] <= 3
    if page1.get("next_cursor"):
        page2 = await call(
            mcp, "search_indicators", {"min_score": 0, "first": 3, "after": page1["next_cursor"]}
        )
        assert not {i["id"] for i in page1["indicators"]} & {i["id"] for i in page2["indicators"]}
        print(f"live search_indicators page 2: returned={page2['returned']}")

    fuzzy = await call(mcp, "search_indicators", {"search": name[:40], "first": 5})
    print(f"live search_indicators search: total={fuzzy['total']} returned={fuzzy['returned']}")

    ind = await call(mcp, "get_indicator", {"id": nodes[0]["id"]})
    i = ind["indicator"]
    print(
        f"live get_indicator: observables_total={i.get('observables_total')} reports_total={i.get('reports_total')} "
        f"withheld={ind['withheld']}"
    )
    assert i["id"] == nodes[0]["id"]

    obs_ids = [o["id"] for o in i.get("observables", [])]
    if obs_ids:
        obs = await call(mcp, "get_observable", {"id": obs_ids[0], "relations": True})
        o = obs["observable"]
        print(
            f"live get_observable: indicators_total={o.get('indicators_total')} "
            f"relations_total={o.get('relations_total')} returned_relations={len(o.get('relations', []))} "
            f"withheld={obs['withheld']}"
        )
        assert o["id"] == obs_ids[0]
        inds = await call(mcp, "observable_indicators", {"id": obs_ids[0], "first": 5})
        print(f"live observable_indicators: total={inds['total']} returned={inds['returned']}")
        assert nodes[0]["id"] in [x["id"] for x in inds["indicators"]] or inds["total"] > 5

    standard = await call(mcp, "get_indicator", {"id": i["standard_id"]})
    assert standard["indicator"]["id"] == i["id"]

    missing = await call(mcp, "get_indicator", {"id": "indicator--00000000-0000-4000-8000-000000000000"})
    assert "not found:" in missing


async def test_tlp_withholding_on_real_data(live):
    mcp, client = live
    data = await client.execute(LIST_TLP)
    above = [
        e["node"]
        for e in data["markingDefinitions"]["edges"]
        if e["node"]["definition_type"] == "TLP" and not _visible({"objectMarking": [e["node"]]})
    ]
    print(f"\nlive TLP markings above TLP:AMBER+STRICT: {len(above)}")
    if not above:
        pytest.skip("no TLP marking above the ceiling on this instance")
    filters = {
        "mode": "and",
        "filters": [
            {"key": ["objectMarking"], "values": [m["id"] for m in above], "operator": "eq", "mode": "or"}
        ],
        "filterGroups": [],
    }
    counted = await client.execute(COUNT_MARKED, {"filters": filters, "first": 3})
    n_ind = counted["indicators"]["pageInfo"]["globalCount"]
    n_obs = counted["stixCyberObservables"]["pageInfo"]["globalCount"]
    n_rep = counted["reports"]["pageInfo"]["globalCount"]
    print(f"live objects above the ceiling: indicators={n_ind} observables={n_obs} reports={n_rep}")
    if not n_ind and not n_obs:
        pytest.skip("no data marked above the ceiling")
    for e in counted["indicators"]["edges"]:
        out = await call(mcp, "get_indicator", {"id": e["node"]["id"]})
        assert out["indicator"] is None and out["withheld"] == 1
    for e in counted["stixCyberObservables"]["edges"]:
        out = await call(mcp, "get_observable", {"id": e["node"]["id"]})
        assert out["observable"] is None and out["withheld"] == 1
