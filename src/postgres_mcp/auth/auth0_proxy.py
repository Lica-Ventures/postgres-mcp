from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass
from dataclasses import field
from urllib.parse import urlencode

import httpx
import jwt

from mcp.server.auth.provider import AccessToken
from mcp.server.auth.provider import AuthorizationCode
from mcp.server.auth.provider import AuthorizationParams
from mcp.server.auth.provider import RefreshToken
from mcp.server.auth.provider import TokenError
from mcp.shared.auth import OAuthClientInformationFull
from mcp.shared.auth import OAuthToken

logger = logging.getLogger(__name__)


@dataclass
class PendingAuth:
    """In-flight OAuth state while the user is at Auth0's login page."""

    client_id: str
    redirect_uri: str
    original_state: str | None
    code_challenge: str
    redirect_uri_provided_explicitly: bool
    scopes: list[str]
    resource: str | None
    created_at: float = field(default_factory=time.time)


class Auth0ProxyProvider:
    """
    OAuth Authorization Server that proxies to Auth0.

    Claude Desktop registers a client here (DCR), then this server redirects
    the user to Auth0 for authentication.  After Auth0 completes the flow it
    redirects back to /oauth/callback, where we exchange the Auth0 code for
    tokens and hand an opaque code back to Claude Desktop.  When Claude Desktop
    exchanges that code we return the real Auth0 JWT, which our load_access_token
    method validates on every subsequent request.
    """

    def __init__(
        self,
        issuer_url: str,
        audience: str,
        client_id: str,
        client_secret: str,
        callback_url: str,
        required_scopes: list[str],
    ) -> None:
        self.issuer_url = issuer_url.rstrip("/")
        self.audience = audience
        self.client_id = client_id
        self.client_secret = client_secret
        self.callback_url = callback_url
        self.required_scopes = required_scopes

        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._pending: dict[str, PendingAuth] = {}
        self._codes: dict[str, dict] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}

        self._jwks_client = jwt.PyJWKClient(
            f"{self.issuer_url}/.well-known/jwks.json",
            cache_keys=True,
        )

    # ------------------------------------------------------------------
    # OAuthAuthorizationServerProvider protocol
    # ------------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.client_id:
            client_info = client_info.model_copy(update={"client_id": secrets.token_urlsafe(24)})
        self._clients[client_info.client_id] = client_info
        logger.info("Registered OAuth client: %s", client_info.client_id)

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        state = secrets.token_urlsafe(32)
        scopes = params.scopes or self.required_scopes

        self._pending[state] = PendingAuth(
            client_id=client.client_id,
            redirect_uri=str(params.redirect_uri),
            original_state=params.state,
            code_challenge=params.code_challenge,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            scopes=scopes,
            resource=params.resource,
        )

        scope_str = " ".join({"openid"} | set(scopes))
        auth_params = {
            "client_id": self.client_id,
            "redirect_uri": self.callback_url,
            "response_type": "code",
            "scope": scope_str,
            "audience": self.audience,
            "state": state,
        }
        url = f"{self.issuer_url}/authorize?{urlencode(auth_params)}"
        logger.debug("Redirecting to Auth0: %s", url)
        return url

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        data = self._codes.get(authorization_code)
        if not data or data["expires_at"] < time.time():
            self._codes.pop(authorization_code, None)
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=data["scopes"],
            expires_at=data["expires_at"],
            client_id=data["client_id"],
            code_challenge=data["code_challenge"],
            redirect_uri=data["redirect_uri"],
            redirect_uri_provided_explicitly=data["redirect_uri_provided_explicitly"],
            resource=data.get("resource"),
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        data = self._codes.pop(authorization_code.code, None)
        if not data:
            raise TokenError("invalid_grant", "Authorization code not found or expired")

        access_token = data["access_token"]
        refresh_token_str = data.get("refresh_token")
        scopes = data["scopes"]

        try:
            info = await asyncio.to_thread(self._decode_jwt, access_token)
            self._access_tokens[access_token] = info
        except Exception as exc:
            logger.warning("Could not pre-cache access token: %s", exc)

        if refresh_token_str:
            self._refresh_tokens[refresh_token_str] = RefreshToken(
                token=refresh_token_str,
                client_id=client.client_id,
                scopes=scopes,
            )

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=3600,
            refresh_token=refresh_token_str,
            scope=" ".join(scopes),
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        return self._refresh_tokens.get(refresh_token)

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        effective_scopes = scopes or refresh_token.scopes
        async with httpx.AsyncClient() as http:
            resp = await http.post(
                f"{self.issuer_url}/oauth/token",
                json={
                    "grant_type": "refresh_token",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "refresh_token": refresh_token.token,
                    "scope": " ".join(effective_scopes),
                },
            )
            resp.raise_for_status()
            tokens = resp.json()

        new_access = tokens["access_token"]
        new_refresh = tokens.get("refresh_token", refresh_token.token)

        self._refresh_tokens.pop(refresh_token.token, None)
        self._refresh_tokens[new_refresh] = RefreshToken(
            token=new_refresh,
            client_id=client.client_id,
            scopes=effective_scopes,
        )
        try:
            info = await asyncio.to_thread(self._decode_jwt, new_access)
            self._access_tokens[new_access] = info
        except Exception:
            pass

        return OAuthToken(
            access_token=new_access,
            token_type="Bearer",
            expires_in=3600,
            refresh_token=new_refresh,
            scope=" ".join(effective_scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        cached = self._access_tokens.get(token)
        if cached:
            if cached.expires_at and cached.expires_at < time.time():
                del self._access_tokens[token]
                return None
            return cached
        try:
            info = await asyncio.to_thread(self._decode_jwt, token)
            if self.required_scopes and not set(self.required_scopes).issubset(set(info.scopes)):
                logger.info("Token missing required scopes %s", self.required_scopes)
                return None
            self._access_tokens[token] = info
            return info
        except Exception as exc:
            logger.info("Access token validation failed: %s", exc)
            return None

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, AccessToken):
            self._access_tokens.pop(token.token, None)
        else:
            self._refresh_tokens.pop(token.token, None)

    # ------------------------------------------------------------------
    # Auth0 callback handling (called by the /oauth/callback route)
    # ------------------------------------------------------------------

    async def handle_callback(self, code: str, state: str) -> str:
        """
        Process the Auth0 redirect after login.

        Exchanges the Auth0 code for tokens, stores them under a new opaque
        code, and returns the URL Claude Desktop should be redirected to.
        """
        pending = self._pending.pop(state, None)
        if not pending:
            raise ValueError(f"Unknown or expired OAuth state: {state!r}")

        async with httpx.AsyncClient() as http:
            resp = await http.post(
                f"{self.issuer_url}/oauth/token",
                json={
                    "grant_type": "authorization_code",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "redirect_uri": self.callback_url,
                },
            )
            if not resp.is_success:
                logger.error("Auth0 token exchange failed: %s %s", resp.status_code, resp.text)
                resp.raise_for_status()
            tokens = resp.json()

        our_code = secrets.token_urlsafe(32)
        self._codes[our_code] = {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token"),
            "scopes": pending.scopes,
            "client_id": pending.client_id,
            "code_challenge": pending.code_challenge,
            "redirect_uri": pending.redirect_uri,
            "redirect_uri_provided_explicitly": pending.redirect_uri_provided_explicitly,
            "resource": pending.resource,
            "expires_at": time.time() + 600,
        }

        redirect_params: dict[str, str] = {"code": our_code}
        if pending.original_state:
            redirect_params["state"] = pending.original_state
        return f"{pending.redirect_uri}?{urlencode(redirect_params)}"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _decode_jwt(self, token: str) -> AccessToken:
        signing_key = self._jwks_client.get_signing_key_from_jwt(token).key
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=self.audience,
            issuer=self.issuer_url + "/",
            options={"require": ["exp", "iat", "sub"]},
        )
        scope_claim = payload.get("scope", "")
        scopes = scope_claim.split() if isinstance(scope_claim, str) else []
        client_id = str(payload.get("azp") or payload.get("client_id") or payload["sub"])
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=int(payload["exp"]),
            resource=self.audience,
        )
