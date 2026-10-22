# -*- coding: utf-8 -*-
"""
test_mcp_enterprise.py: Mocked unit tests for the hardened Nexargio MCP client.
===============================================================================
These tests make NO network calls -- the gateway is stubbed.
Run with:  python -m pytest tests/ -v
"""

import sys
import os
import json
import types
import asyncio
import importlib

# Ensure repo root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nexargio_mcp as nx


# --------------------------------------------------------------------------
# Test doubles for httpx
# --------------------------------------------------------------------------

class _FakeResp:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self):
        return self._payload


def _make_fake_client(resp=None, exc=None):
    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            if exc:
                raise exc
            return resp

        async def get(self, *a, **k):
            if exc:
                raise exc
            return resp

    return _FakeClient


def run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------
# SSRF protection
# --------------------------------------------------------------------------

def test_ssrf_blocks_internal_hosts():
    for host in ("localhost", "127.0.0.1", "169.254.169.254", "10.0.0.5",
                 "192.168.1.1", "0.0.0.0", "::1"):
        assert nx._host_is_public(host) is False, f"{host} should be blocked"


def test_ssrf_allows_public_ip():
    assert nx._host_is_public("8.8.8.8") is True


# --------------------------------------------------------------------------
# Fail-closed result builder & cache
# --------------------------------------------------------------------------

def test_incomplete_has_no_threat_verdict():
    r = nx._incomplete("https://x.test", "boom", "SCAN_INCOMPLETE")
    assert r["status"] == "ERROR"
    assert r["decision"]["verdict"] == "SCAN_INCOMPLETE"
    assert r["decision"]["threat_score"] is None
    assert r["decision"]["action_policy"] == "ERROR_REVIEW_REQUIRED"


def test_cache_never_stores_errors():
    nx._CLIENT_SCAN_CACHE.clear()
    nx._set_cached_scan("k1", {"status": "ERROR"})
    nx._set_cached_scan("k2", nx._incomplete("u", "x"))
    nx._set_cached_scan("k3", {"status": "COMPLETED",
                               "decision": {"verdict": "TRANSIENT_NETWORK_DEGRADATION"}})
    assert nx._get_cached_scan("k1") is None
    assert nx._get_cached_scan("k2") is None
    assert nx._get_cached_scan("k3") is None
    nx._set_cached_scan("ok", {"status": "COMPLETED", "decision": {"verdict": "ALLOW"}})
    assert nx._get_cached_scan("ok") is not None


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------

def test_empty_target_is_invalid_input():
    out = json.loads(run(nx.nexargio_scan("   ")))
    assert out["error_code"] == "INVALID_INPUT"
    assert out["decision"]["verdict"] == "SCAN_INCOMPLETE"


def test_overlong_target_is_invalid_input():
    out = json.loads(run(nx.nexargio_scan("https://x/" + "a" * 9000)))
    assert out["error_code"] == "INVALID_INPUT"


# --------------------------------------------------------------------------
# Gateway auth / quota are surfaced, not downgraded
# --------------------------------------------------------------------------

def test_auth_failure_is_surfaced(monkeypatch):
    nx._CLIENT_SCAN_CACHE.clear()
    monkeypatch.setattr(nx, "API_KEY", "nx_test_key")
    monkeypatch.setattr(nx, "_GATEWAY_RETRIES", 0)
    monkeypatch.setattr(nx.httpx, "AsyncClient", _make_fake_client(_FakeResp(401)))
    out = json.loads(run(nx.nexargio_scan("https://example.com")))
    assert out["error_code"] == "AUTH_FAILED"
    assert out["gateway_http_status"] == 401


def test_quota_exceeded_is_surfaced(monkeypatch):
    nx._CLIENT_SCAN_CACHE.clear()
    monkeypatch.setattr(nx, "API_KEY", "nx_test_key")
    monkeypatch.setattr(nx, "_GATEWAY_RETRIES", 0)
    monkeypatch.setattr(nx.httpx, "AsyncClient", _make_fake_client(_FakeResp(429)))
    out = json.loads(run(nx.nexargio_scan("https://example.com")))
    assert out["error_code"] == "QUOTA_EXCEEDED"


# --------------------------------------------------------------------------
# Fail-closed when the service cannot produce a verdict
# --------------------------------------------------------------------------

def test_service_unavailable_is_fail_closed(monkeypatch):
    nx._CLIENT_SCAN_CACHE.clear()
    monkeypatch.setattr(nx, "API_KEY", "nx_test_key")
    monkeypatch.setattr(nx, "_GATEWAY_RETRIES", 0)
    monkeypatch.setattr(nx.httpx, "AsyncClient", _make_fake_client(_FakeResp(500)))
    raw = run(nx.nexargio_scan("https://example.com"))
    out = json.loads(raw)
    assert out["status"] == "ERROR"
    assert out["error_code"] == "SERVICE_UNAVAILABLE"
    assert out["decision"]["verdict"] == "SCAN_INCOMPLETE"
    assert out["decision"]["threat_score"] is None
    assert out["decision"]["action_policy"] == "ERROR_REVIEW_REQUIRED"


def test_network_exception_does_not_leak_detail(monkeypatch):
    nx._CLIENT_SCAN_CACHE.clear()
    monkeypatch.setattr(nx, "API_KEY", "nx_test_key")
    monkeypatch.setattr(nx, "_GATEWAY_RETRIES", 0)
    boom = nx.httpx.ConnectError("secret-internal-host.example refused")
    monkeypatch.setattr(nx.httpx, "AsyncClient", _make_fake_client(exc=boom))
    raw = run(nx.nexargio_scan("https://example.com"))
    out = json.loads(raw)
    assert out["error_code"] == "SERVICE_UNAVAILABLE"
    assert "secret-internal-host" not in raw


def test_missing_api_key_is_auth_required(monkeypatch):
    nx._CLIENT_SCAN_CACHE.clear()
    monkeypatch.setattr(nx, "API_KEY", "")
    monkeypatch.setattr(nx, "_AUTO_TRIAL_ENABLED", False)
    monkeypatch.setattr(nx, "_load_cached_trial_key", lambda: None)
    out = json.loads(run(nx.nexargio_scan("https://example.com")))
    assert out["error_code"] == "AUTH_REQUIRED"
    assert out["decision"]["verdict"] == "SCAN_INCOMPLETE"


def test_published_client_names_no_internals():
    """The client ships publicly; it must not reference internal modules/models."""
    src = open(nx.__file__, encoding="utf-8").read().lower()
    for term in ("orchestrator_dag", "api_v1", "qwen", "jev", "groq", "gemini",
                 "sensory dag", "dom primitive"):
        assert term not in src, f"internal term {term!r} found in published client"


# --------------------------------------------------------------------------
# Successful gateway verdict
# --------------------------------------------------------------------------

def test_gateway_success_returns_verdict(monkeypatch):
    nx._CLIENT_SCAN_CACHE.clear()
    monkeypatch.setattr(nx, "API_KEY", "nx_test_key")
    payload = {"status": "COMPLETED",
               "decision": {"verdict": "WEAPONIZED_ATTACK", "threat_score": 95,
                            "action_policy": "HARD_BLOCK"}}
    monkeypatch.setattr(nx.httpx, "AsyncClient", _make_fake_client(_FakeResp(200, payload)))
    out = json.loads(run(nx.nexargio_scan("https://phish.example")))
    assert out["decision"]["verdict"] == "WEAPONIZED_ATTACK"
    assert out["decision"]["threat_score"] == 95


# --------------------------------------------------------------------------
# Multi-Tool Sovereign Suite Tests (v2.0.0)
# --------------------------------------------------------------------------

def test_disarm_carrier_neutralizes_stego_and_comments():
    plane14_char = chr(0xE0001)
    zw_char = "\u200B"
    payload = f"Hello World{plane14_char}{zw_char}<!-- hidden instruction -->"
    raw = run(nx.nexargio_disarm_carrier(payload))
    out = json.loads(raw)
    assert out["status"] == "COMPLETED"
    assert out["is_weaponized"] is True
    assert out["purified"] is True
    assert "PLANE14_TAG_STEGANOGRAPHY" in str(out["threats_neutralized"])
    assert "ZERO_WIDTH_STEGANOGRAPHY" in str(out["threats_neutralized"])
    assert "HIDDEN_COMMENT_INJECTION" in str(out["threats_neutralized"])
    assert "hidden instruction" not in out["sanitized_content"]
    assert out["sanitized_content"] == "Hello World"


def test_audit_action_blocks_trojan_credential_exfil():
    raw = run(nx.nexargio_audit_action(
        tool_name="update_secret",
        target_resource="/app/.env",
        proposed_value="AWS_KEY=fake",
        origin_taint="UNTRUSTED_INFLOW"
    ))
    out = json.loads(raw)
    assert out["allowed"] is False
    assert out["action_directive"] == "HARD_BLOCK"
    assert out["threat_score"] >= 90
    assert out["violation_code"] == "CRITICAL_CREDENTIAL_MUTATION"


def test_audit_action_blocks_destructive_shell():
    raw = run(nx.nexargio_audit_action(
        tool_name="execute_bash",
        target_resource="/tmp",
        proposed_value="rm -rf /var/log/*",
        origin_taint="UNTRUSTED_INFLOW"
    ))
    out = json.loads(raw)
    assert out["allowed"] is False
    assert out["action_directive"] == "HARD_BLOCK"
    assert out["threat_score"] >= 95
    assert out["violation_code"] == "DESTRUCTIVE_EXECUTION_ATTEMPT"


def test_audit_action_allows_benign_action():
    raw = run(nx.nexargio_audit_action(
        tool_name="read_file",
        target_resource="/app/README.md",
        proposed_value="",
        origin_taint="VERIFIED_OPERATOR"
    ))
    out = json.loads(raw)
    assert out["allowed"] is True
    assert out["action_directive"] == "ALLOW"
    assert out["threat_score"] == 0


def test_anonymous_session_id():
    id1 = nx._get_anonymous_session_id()
    id2 = nx._get_anonymous_session_id()
    assert id1 == id2
    assert len(id1) == 32
    # Verify it is valid hex UUID
    int(id1, 16)


def test_cached_trial_key_resolution(monkeypatch, tmp_path=None):
    nx._CLIENT_SCAN_CACHE.clear()
    monkeypatch.setattr(nx, "API_KEY", "")
    monkeypatch.setattr(nx, "_load_cached_trial_key", lambda: "nx_trial_test12345678")
    key, is_trial = run(nx._resolve_api_key())
    assert key == "nx_trial_test12345678"
    assert is_trial is True
