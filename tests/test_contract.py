"""Contract tests: every GraphQL document the server sends is valid against the vendored OpenCTI
schemas, for both supported lines (6.9 and 7.x).

`tests/schema/<version>/` holds OpenCTI's own SDL (Apache-2.0, see NOTICE): the main
`opencti.graphql` as `000-main.graphql` and each module's `.graphql`, with the modules'
`type Query` / `type Mutation` rewritten to `extend type ...` so the files merge into one schema.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path

import pytest
from graphql import GraphQLSchema, OperationType, build_ast_schema, parse, validate
from graphql.language import DocumentNode, OperationDefinitionNode

from opencti_mcp_server import queries

SCHEMA_DIR = Path(__file__).parent / "schema"
VERSIONS = sorted(p.name for p in SCHEMA_DIR.iterdir() if p.is_dir())


@cache
def schema(version: str) -> GraphQLSchema:
    definitions = []
    for path in sorted((SCHEMA_DIR / version).glob("*.graphql")):
        definitions.extend(parse(path.read_text(encoding="utf-8")).definitions)
    return build_ast_schema(DocumentNode(definitions=tuple(definitions)), assume_valid_sdl=True)


def test_both_lines_are_vendored():
    assert any(v.startswith("6.9.") for v in VERSIONS) and any(v.startswith("7.") for v in VERSIONS)


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("name", sorted(queries.ALL))
def test_document_is_valid(version, name):
    errors = validate(schema(version), parse(queries.ALL[name]))
    assert not errors, [e.message for e in errors]


@pytest.mark.parametrize("name", sorted(queries.ALL))
def test_document_is_a_single_query(name):
    ops = [d for d in parse(queries.ALL[name]).definitions if isinstance(d, OperationDefinitionNode)]
    assert len(ops) == 1 and ops[0].operation is OperationType.QUERY


def test_schema_rejects_a_bad_document():
    """The harness itself catches a broken document."""
    errors = validate(schema(VERSIONS[0]), parse("query X { indicators(first: 1) { nosuchfield } }"))
    assert errors


@pytest.mark.parametrize("version", VERSIONS)
def test_hash_lookups_cover_files_artifacts_and_certificates(version):
    """Hash lookups filter StixFile, Artifact and X509-Certificate; each has `hashes` in both lines."""
    from graphql import GraphQLObjectType

    from opencti_mcp_server.guards import _KINDS

    gql_names = {"StixFile": "StixFile", "Artifact": "Artifact", "X509-Certificate": "X509Certificate"}
    hashed = schema(version).get_type("HashedObservable")
    for kind in ("md5", "sha1", "sha256", "sha512"):
        types, key = _KINDS[kind]
        assert key.startswith("hashes.") and set(types) == set(gql_names)
    for name in gql_names.values():
        t = schema(version).get_type(name)
        assert isinstance(t, GraphQLObjectType) and hashed in t.interfaces and "hashes" in t.fields
    assert "... on HashedObservable { hashes" in queries.LOOKUP_OBSERVABLE


def test_relation_ends_request_markings_for_every_kind():
    """Relationship ends can be objects, relationships or sightings; each asks for objectMarking."""
    doc = queries.OBSERVABLE_RELATIONS
    for fragment in ("StixCoreObject", "StixCoreRelationship", "StixSightingRelationship"):
        assert doc.count(f"... on {fragment} {{ {queries.MARKINGS} }}") == 2, fragment


def test_authors_request_markings():
    assert f"createdBy {{ name {queries.MARKINGS} }}" in queries.LOOKUP_OBSERVABLE
