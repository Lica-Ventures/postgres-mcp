from types import SimpleNamespace

import pytest

from postgres_mcp.auth.auth0 import Auth0Config
from postgres_mcp.auth.auth0 import Auth0TokenVerifier
from postgres_mcp.auth.auth0 import build_auth0_mcp_kwargs
from postgres_mcp.auth.auth0 import load_auth0_config_from_env


def test_load_auth0_config_from_env_returns_none_when_unset(monkeypatch):
    monkeypatch.delenv("AUTH0_ISSUER_URL", raising=False)
    monkeypatch.delenv("AUTH0_AUDIENCE", raising=False)
    monkeypatch.delenv("MCP_RESOURCE_SERVER_URL", raising=False)
    monkeypatch.delenv("MCP_REQUIRED_SCOPES", raising=False)

    assert load_auth0_config_from_env() is None
    assert build_auth0_mcp_kwargs() == {}


def test_load_auth0_config_from_env_parses_values(monkeypatch):
    monkeypatch.setenv("AUTH0_ISSUER_URL", "https://example.us.auth0.com/")
    monkeypatch.setenv("AUTH0_AUDIENCE", "https://postgres-mcp")
    monkeypatch.setenv("MCP_RESOURCE_SERVER_URL", "https://mcp.example.com")
    monkeypatch.setenv("MCP_REQUIRED_SCOPES", "mcp:use,db:read")

    config = load_auth0_config_from_env()

    assert config == Auth0Config(
        issuer_url="https://example.us.auth0.com/",
        audience="https://postgres-mcp",
        resource_server_url="https://mcp.example.com",
        required_scopes=["mcp:use", "db:read"],
    )


@pytest.mark.asyncio
async def test_auth0_token_verifier_accepts_valid_token(monkeypatch):
    config = Auth0Config(
        issuer_url="https://example.us.auth0.com/",
        audience="https://postgres-mcp",
        resource_server_url="https://mcp.example.com",
        required_scopes=["mcp:use"],
    )
    verifier = Auth0TokenVerifier(config)

    class FakeJWKClient:
        def get_signing_key_from_jwt(self, token):
            assert token == "valid-token"
            return SimpleNamespace(key="public-key")

    monkeypatch.setattr("postgres_mcp.auth.auth0.jwt.PyJWKClient", lambda url: FakeJWKClient())

    def fake_decode(token, key, algorithms, audience, issuer, options):
        assert token == "valid-token"
        assert key == "public-key"
        assert algorithms == ["RS256"]
        assert audience == "https://postgres-mcp"
        assert issuer == "https://example.us.auth0.com/"
        assert options["require"] == ["exp", "iat", "sub"]
        return {
            "sub": "auth0|123",
            "azp": "claude-desktop",
            "exp": 2_000_000_000,
            "iat": 1_900_000_000,
            "scope": "mcp:use db:read",
        }

    monkeypatch.setattr("postgres_mcp.auth.auth0.jwt.decode", fake_decode)
    verifier._jwks_client = FakeJWKClient()

    token = await verifier.verify_token("valid-token")

    assert token is not None
    assert token.token == "valid-token"
    assert token.client_id == "claude-desktop"
    assert token.scopes == ["mcp:use", "db:read"]
    assert token.expires_at == 2_000_000_000
    assert token.resource == "https://postgres-mcp"


@pytest.mark.asyncio
async def test_auth0_token_verifier_rejects_missing_scope(monkeypatch):
    config = Auth0Config(
        issuer_url="https://example.us.auth0.com/",
        audience="https://postgres-mcp",
        resource_server_url="https://mcp.example.com",
        required_scopes=["mcp:use"],
    )
    verifier = Auth0TokenVerifier(config)

    class FakeJWKClient:
        def get_signing_key_from_jwt(self, token):
            return SimpleNamespace(key="public-key")

    monkeypatch.setattr("postgres_mcp.auth.auth0.jwt.PyJWKClient", lambda url: FakeJWKClient())
    monkeypatch.setattr(
        "postgres_mcp.auth.auth0.jwt.decode",
        lambda *args, **kwargs: {
            "sub": "auth0|123",
            "exp": 2_000_000_000,
            "iat": 1_900_000_000,
            "scope": "db:read",
        },
    )
    verifier._jwks_client = FakeJWKClient()

    assert await verifier.verify_token("valid-token") is None
