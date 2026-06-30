"""Authorization gate + target parsing (Phase 1). No network."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptoprobe import authz
from cryptoprobe.targets import parse_target, load_targets_file, Target


def test_refuses_without_authorization():
    a = authz.resolve(None, None)
    assert a.granted is False
    assert "no authorization" in a.reason


def test_flag_authorizes_any_target():
    a = authz.resolve("OP-1234", None)
    assert a.granted is True
    assert a.source == "flag"
    assert a.identifier == "OP-1234"
    ok, _ = authz.authorize_target(a, "example.com", 443)
    assert ok is True


def test_scope_gates_targets(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "authorization:\n"
        "  operator: jdoe\n"
        "  ticket: OP-9\n"
        "  rate_limit: 2.0\n"
        "targets:\n"
        "  - api.example.com:8443\n"
        "  - '*.lab.example.com'\n"
        "  - 10.0.0.0/24\n",
        encoding="utf-8",
    )
    a = authz.resolve(None, str(scope))
    assert a.granted is True
    assert a.source == "scope"
    assert a.identifier == "jdoe/OP-9"
    assert a.scope.sha256 and len(a.scope.sha256) == 64
    assert a.scope.rate_limit == 2.0

    # exact host:port
    assert authz.authorize_target(a, "api.example.com", 8443)[0] is True
    # wrong port for an exact entry
    assert authz.authorize_target(a, "api.example.com", 443)[0] is False
    # host glob, any port
    assert authz.authorize_target(a, "web1.lab.example.com", 443)[0] is True
    # CIDR membership
    assert authz.authorize_target(a, "10.0.0.5", 443)[0] is True
    assert authz.authorize_target(a, "10.0.1.5", 443)[0] is False
    # out of scope entirely
    assert authz.authorize_target(a, "evil.example.org", 443)[0] is False


def test_scope_requires_identifier_and_targets(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("targets:\n  - x.example.com\n", encoding="utf-8")
    try:
        authz.load_scope(str(bad))
        assert False, "expected AuthorizationError"
    except authz.AuthorizationError as exc:
        assert "operator" in str(exc) or "ticket" in str(exc)


def test_parse_target_forms():
    assert parse_target("example.com") == Target("example.com", 443)
    assert parse_target("example.com:8443") == Target("example.com", 8443)
    assert parse_target("[2001:db8::1]:443") == Target("2001:db8::1", 443)
    try:
        parse_target("example.com:notaport")
        assert False
    except ValueError:
        pass


def test_targets_file_sorted_unique(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text(
        "# a comment\n"
        "b.example.com:443\n"
        "a.example.com\n"
        "b.example.com:443\n"  # duplicate
        "\n",
        encoding="utf-8",
    )
    ts = load_targets_file(str(f))
    assert ts == [Target("a.example.com", 443), Target("b.example.com", 443)]
