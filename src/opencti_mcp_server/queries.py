"""The fixed GraphQL documents. They are the only documents the server ever sends.

Every caller-supplied value travels as a GraphQL variable; nothing is ever spliced into a document.
All documents are queries (no mutations or subscriptions), and `tests/test_contract.py` validates
each one against the vendored OpenCTI 6.9 and 7.x schemas.

Every node that can carry a marking asks for `objectMarking`, nested ones included (authors and
relationship ends too), so the TLP guard can withhold it. The guard fails closed on a node that
lacks the key.
"""

from __future__ import annotations

MARKINGS = "objectMarking { definition_type definition x_opencti_order }"

_META = f"""
fragment Meta on StixCoreObject {{
  id standard_id entity_type created_at updated_at
  createdBy {{ name {MARKINGS} }}
  objectLabel {{ value }}
  {MARKINGS}
}}
"""

_IND = """
fragment Ind on Indicator {
  ...Meta
  name description pattern pattern_type indicator_types
  x_opencti_main_observable_type x_opencti_score x_opencti_detection
  confidence valid_from valid_until revoked
  killChainPhases { kill_chain_name phase_name }
}
"""

_OBS = """
fragment Obs on StixCyberObservable {
  ...Meta
  observable_value x_opencti_score x_opencti_description
  ... on StixFile { name }
  ... on HashedObservable { hashes { algorithm hash } }
}
"""

_REPORTS = (
    f"reports(first: 5) {{ pageInfo {{ globalCount }} edges {{ node {{ id name published {MARKINGS} }} }} }}"
)

_EXTERNAL_REFERENCES = "externalReferences(first: 10) { edges { node { source_name url external_id } } }"

LOOKUP_OBSERVABLE = (
    """
query LookupObservable(
  $filters: FilterGroup, $search: String, $types: [String], $first: Int!, $nInd: Int!,
  $orderBy: StixCyberObservablesOrdering
) {
  stixCyberObservables(
    filters: $filters, search: $search, types: $types, first: $first, orderBy: $orderBy, orderMode: desc
  ) {
    pageInfo { globalCount hasNextPage endCursor }
    edges { node {
      ...Obs
      indicators(first: $nInd) { pageInfo { globalCount } edges { node { ...Ind } } }
      """
    + _REPORTS
    + """
    } }
  }
}
"""
    + _META
    + _OBS
    + _IND
)

SEARCH_INDICATORS = (
    """
query SearchIndicators(
  $search: String, $filters: FilterGroup, $first: Int!, $after: ID, $orderBy: IndicatorsOrdering
) {
  indicators(search: $search, filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: desc) {
    pageInfo { globalCount hasNextPage endCursor }
    edges { node { ...Ind } }
  }
}
"""
    + _META
    + _IND
)

GET_INDICATOR = (
    """
query GetIndicator($id: String!, $nObs: Int!) {
  indicator(id: $id) {
    ...Ind
    x_opencti_observable_values { type value hashes { algorithm hash } }
    """
    + _EXTERNAL_REFERENCES
    + f"""
    observables(first: $nObs) {{
      pageInfo {{ globalCount }}
      edges {{ node {{ id entity_type observable_value {MARKINGS} }} }}
    }}
    """
    + _REPORTS
    + """
  }
}
"""
    + _META
    + _IND
)

GET_OBSERVABLE = (
    """
query GetObservable($id: String!, $nInd: Int!) {
  stixCyberObservable(id: $id) {
    ...Obs
    """
    + _EXTERNAL_REFERENCES
    + """
    indicators(first: $nInd) { pageInfo { globalCount } edges { node { ...Ind } } }
    """
    + _REPORTS
    + """
  }
}
"""
    + _META
    + _OBS
    + _IND
)

OBSERVABLE_RELATIONS = f"""
query ObservableRelations($id: String!, $first: Int!) {{
  stixCyberObservable(id: $id) {{
    id
    stixCoreRelationships(first: $first, orderBy: updated_at, orderMode: desc) {{
      pageInfo {{ globalCount }}
      edges {{ node {{
        id relationship_type confidence start_time stop_time
        {MARKINGS}
        from {{
          ... on BasicObject {{ id entity_type }}
          ... on StixObject {{ representative {{ main }} }}
          ... on StixCoreObject {{ {MARKINGS} }}
          ... on StixCoreRelationship {{ {MARKINGS} }}
          ... on StixSightingRelationship {{ {MARKINGS} }}
        }}
        to {{
          ... on BasicObject {{ id entity_type }}
          ... on StixObject {{ representative {{ main }} }}
          ... on StixCoreObject {{ {MARKINGS} }}
          ... on StixCoreRelationship {{ {MARKINGS} }}
          ... on StixSightingRelationship {{ {MARKINGS} }}
        }}
      }} }}
    }}
  }}
}}
"""

OBSERVABLE_INDICATORS = (
    f"""
query ObservableIndicators($id: String!, $first: Int!) {{
  stixCyberObservable(id: $id) {{
    id observable_value {MARKINGS}
    indicators(first: $first) {{ pageInfo {{ globalCount }} edges {{ node {{ ...Ind }} }} }}
  }}
}}
"""
    + _META
    + _IND
)

# Deep health check: the platform version, and proof the token authenticates. `me { name }` is only
# read to confirm the session; neither it nor the user's capabilities are returned.
HEALTH = "query Health { about { version } me { name } }"

ALL: dict[str, str] = {
    "LOOKUP_OBSERVABLE": LOOKUP_OBSERVABLE,
    "SEARCH_INDICATORS": SEARCH_INDICATORS,
    "GET_INDICATOR": GET_INDICATOR,
    "GET_OBSERVABLE": GET_OBSERVABLE,
    "OBSERVABLE_RELATIONS": OBSERVABLE_RELATIONS,
    "OBSERVABLE_INDICATORS": OBSERVABLE_INDICATORS,
    "HEALTH": HEALTH,
}
