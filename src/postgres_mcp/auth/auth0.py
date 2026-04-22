from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING
from typing import Any

import jwt

from mcp.server.auth.provider import AccessToken
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings

if TYPE_CHECKING:
    from .auth0_proxy import Auth0ProxyProvider

logger = logging.getLogger(__name__)

# Set in build_auth0_mcp_kwargs() when proxy mode is active.
_proxy_provider: Auth0ProxyProvider | None = None


@dataclass(frozen=True)
class Auth0Config:
    """Runtime configuration for Auth0-backed MCP auth."""

    issuer_url: str
    audience: str
    resource_server_url: str
    required_scopes: list[str]


def _split_scopes(raw_scopes: str | None) -> list[str]:
    if not raw_scopes:
        return []

    scopes = [scope.strip() for scope in raw_scopes.split(",")]
    return [scope for scope in scopes if scope]


def load_auth0_config_from_env() -> Auth0Config | None:
    """Load Auth0 settings from environment variables.

    When the Auth0 env vars are absent, authentication stays disabled so local
    development and legacy deployments continue to work.
    """

    issuer_url = os.environ.get("AUTH0_ISSUER_URL")
    audience = os.environ.get("AUTH0_AUDIENCE")
    resource_server_url = os.environ.get("MCP_RESOURCE_SERVER_URL")

    enabled_vars = [issuer_url, audience, resource_server_url]
    if not any(enabled_vars):
        return None

    if not all(enabled_vars):
        missing = [
            name
            for name, value in (
                ("AUTH0_ISSUER_URL", issuer_url),
                ("AUTH0_AUDIENCE", audience),
                ("MCP_RESOURCE_SERVER_URL", resource_server_url),
            )
            if not value
        ]
        raise ValueError(f"Auth0 is partially configured. Missing env vars: {', '.join(missing)}")

    required_scopes = _split_scopes(os.environ.get("MCP_REQUIRED_SCOPES")) or ["mcp:use"]

    return Auth0Config(
        issuer_url=issuer_url.rstrip("/") + "/",
        audience=audience,
        resource_server_url=resource_server_url.rstrip("/"),
        required_scopes=required_scopes,
    )


def _parse_scope_claim(scope_claim: Any) -> list[str]:
    if scope_claim is None:
        return []

    if isinstance(scope_claim, str):
        return [scope for scope in scope_claim.split() if scope]

    if isinstance(scope_claim, (list, tuple, set)):
        return [str(scope).strip() for scope in scope_claim if str(scope).strip()]

    return [str(scope_claim).strip()] if str(scope_claim).strip() else []


class Auth0TokenVerifier(TokenVerifier):
    """Validate Auth0-issued JWT access tokens."""

    def __init__(self, config: Auth0Config):
        self.config = config
        self._jwks_client = jwt.PyJWKClient(f"{config.issuer_url.rstrip('/')}/.well-known/jwks.json")

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            return await asyncio.to_thread(self._verify_token_sync, token)
        except Exception as exc:  # pragma: no cover - safety net
            logger.info("Auth0 token verification failed: %s", exc)
            return None

    def _verify_token_sync(self, token: str) -> AccessToken | None:
        signing_key = self._jwks_client.get_signing_key_from_jwt(token).key
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=self.config.audience,
            issuer=self.config.issuer_url,
            options={
                "require": ["exp", "iat", "sub"],
            },
        )

        token_scopes = _parse_scope_claim(payload.get("scope"))
        if self.config.required_scopes and not set(self.config.required_scopes).issubset(token_scopes):
            raise jwt.InvalidTokenError("Missing required MCP scopes")

        client_id = str(payload.get("azp") or payload.get("client_id") or payload["sub"])
        expires_at = int(payload["exp"]) if payload.get("exp") is not None else None

        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=token_scopes,
            expires_at=expires_at,
            resource=self.config.resource_server_url,
        )


def _get_proxy_provider() -> "Auth0ProxyProvider | None":
    """Return the active proxy provider if proxy mode is configured, else None."""
    return _proxy_provider


def build_auth0_mcp_kwargs() -> dict[str, Any]:
    """Build FastMCP auth keyword arguments when Auth0 is configured.

    Proxy mode (recommended for Claude Desktop):
        Set AUTH0_CLIENT_ID + AUTH0_CLIENT_SECRET in addition to the base vars.
        The MCP server becomes its own OAuth AS and proxies auth to Auth0.
        This avoids the DCR client-grant problem where every new Claude Desktop
        session registers a new unauthorized client.

    Token-verifier mode (legacy / service tokens):
        Omit AUTH0_CLIENT_ID / AUTH0_CLIENT_SECRET.  The server validates Bearer
        JWTs directly; the caller must obtain a token from Auth0 externally.
    """
    global _proxy_provider

    config = load_auth0_config_from_env()
    if config is None:
        return {}

    client_id = os.environ.get("AUTH0_CLIENT_ID")
    client_secret = os.environ.get("AUTH0_CLIENT_SECRET")

    if client_id and client_secret:
        from urllib.parse import urlparse

        from mcp.server.auth.settings import ClientRegistrationOptions

        from .auth0_proxy import Auth0ProxyProvider

        # Derive the MCP server base URL from MCP_RESOURCE_SERVER_URL.
        # e.g. https://pgsql-mcp.mechanigo.ph/mcp  →  https://pgsql-mcp.mechanigo.ph
        parsed = urlparse(config.resource_server_url)
        server_base_url = f"{parsed.scheme}://{parsed.netloc}"
        callback_url = f"{server_base_url}/oauth/callback"

        logger.info(
            "Auth0 proxy mode enabled — MCP server is OAuth AS, proxying to %s",
            config.issuer_url,
        )

        provider = Auth0ProxyProvider(
            issuer_url=config.issuer_url,
            audience=config.audience,
            client_id=client_id,
            client_secret=client_secret,
            callback_url=callback_url,
            required_scopes=config.required_scopes,
        )
        _proxy_provider = provider

        auth_settings = AuthSettings(
            issuer_url=server_base_url,
            resource_server_url=config.resource_server_url,
            required_scopes=config.required_scopes,
            client_registration_options=ClientRegistrationOptions(enabled=True),
        )
        return {
            "auth_server_provider": provider,
            "auth": auth_settings,
        }

    # Legacy token-verifier mode
    logger.info("Auth0 token-verifier mode enabled for issuer %s", config.issuer_url)
    verifier = Auth0TokenVerifier(config)
    auth_settings = AuthSettings(
        issuer_url=config.issuer_url,
        resource_server_url=config.resource_server_url,
        required_scopes=config.required_scopes,
    )
    return {
        "token_verifier": verifier,
        "auth": auth_settings,
    }
