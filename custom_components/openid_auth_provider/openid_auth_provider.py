"""OpenID based authentication provider."""

import logging
from secrets import token_hex
from typing import Any, Optional, cast
from collections.abc import Mapping
import secrets

import aiohttp
from aiohttp import web
from aiohttp.client import ClientResponse
from jose import jwt
import voluptuous as vol
from yarl import URL
from jwt.exceptions import DecodeError

from homeassistant.components import http
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.config_entry_oauth2_flow import (
    LocalOAuth2Implementation,
)
from homeassistant.auth.models import AuthFlowContext, AuthFlowResult
from homeassistant.auth import auth_provider_from_config


from homeassistant.auth.providers import (
    AUTH_PROVIDER_SCHEMA,
    AUTH_PROVIDERS,
    AuthProvider,
    LoginFlow,
)
from homeassistant.auth.models import Credentials, UserMeta

from .const import (
    CONF_CLIENT_ID,
    CONF_CLIENT_SECRET,
    CONF_CONFIGURATION,
    CONF_EMAILS,
    CONF_SUBJECTS,
    AUTH_CALLBACK_PATH,
)

_LOGGER = logging.getLogger(__name__)


DATA_JWT_SECRET = "openid_jwt_secret"
HEADER_FRONTEND_BASE = "HA-Frontend-Base"
AUTH_PROVIDER_TYPE = "openid"

WANTED_SCOPES = {"openid", "email", "profile"}


CONFIG_SCHEMA = AUTH_PROVIDER_SCHEMA.extend(
    {
        vol.Required(CONF_CONFIGURATION): str,
        vol.Required(CONF_CLIENT_ID): str,
        vol.Required(CONF_CLIENT_SECRET): str,
        vol.Optional(CONF_EMAILS): [str],
        vol.Optional(CONF_SUBJECTS): [str],
    },
    extra=vol.PREVENT_EXTRA,
)

OPENID_CONFIGURATION_SCHEMA = vol.Schema(
    {
        vol.Required("issuer"): str,
        vol.Required("jwks_uri"): str,
        vol.Required("id_token_signing_alg_values_supported"): list,
        vol.Optional("scopes_supported"): vol.Contains("openid"),
        vol.Required("token_endpoint"): str,
        vol.Required("authorization_endpoint"): str,
        vol.Required("response_types_supported"): vol.Contains("code"),
        vol.Optional(
            "token_endpoint_auth_methods_supported", default=["client_secret_basic"]
        ): vol.Contains("client_secret_post"),
        vol.Optional(
            "grant_types_supported", default=["authorization_code", "implicit"]
        ): vol.Contains("authorization_code"),
    },
    extra=vol.ALLOW_EXTRA,
)


class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""


async def register(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Register the OpenID Auth Provider."""
    _LOGGER.info("Registering OpenID Auth Provider")

    hass.http.register_view(AuthorizeCallbackView())

    provider = await auth_provider_from_config(
        hass,
        hass.auth._store,
        {
            "type": AUTH_PROVIDER_TYPE,
            **entry.options,
        },
    )
    hass.auth._providers[(AUTH_PROVIDER_TYPE, None)] = provider


async def raise_for_status(response: ClientResponse) -> None:
    """Raise exception on data failure with logging."""
    if response.status >= 400:
        standard = aiohttp.ClientResponseError(
            response.request_info,
            response.history,
            code=response.status,
            headers=response.headers,
        )
        data = await response.text()
        _LOGGER.error("Request failed: %s", data)
        raise InvalidAuthError(data) from standard


async def async_get_configuration(
    session: aiohttp.ClientSession, configuration_url: str
) -> dict[str, Any]:
    """Get discovery document for OpenID."""
    async with session.get(configuration_url) as response:
        await raise_for_status(response)
        data = await response.json()
    return cast(dict[str, Any], OPENID_CONFIGURATION_SCHEMA(data))


class OpenIdLocalOAuth2Implementation(LocalOAuth2Implementation):
    """Local OAuth2 implementation for Toon."""

    _nonce: Optional[str] = None
    _scope: str

    def __init__(
        self,
        hass: HomeAssistant,
        client_id: str,
        client_secret: str,
        configuration: dict[str, Any],
    ):
        """Initialize local auth implementation."""
        super().__init__(
            hass,
            "auth",
            client_id,
            client_secret,
            configuration["authorization_endpoint"],
            configuration["token_endpoint"],
        )

        self._scope = " ".join(
            sorted(WANTED_SCOPES.intersection(configuration["scopes_supported"]))
        )

    @property
    def extra_authorize_data(self) -> dict:
        """Extra data that needs to be appended to the authorize url."""
        return {"scope": self._scope, "nonce": self._nonce}

    async def async_generate_authorize_url_with_nonce(
        self, flow_id: str, nonce: str
    ) -> str:
        """Generate an authorize url with a given nonce."""
        self._nonce = nonce
        url = await self.async_generate_authorize_url(flow_id)
        self._nonce = None
        return url

    async def async_generate_authorize_url(self, flow_id: str) -> str:
        """Generate a url for the user to authorize."""
        redirect_uri = self.redirect_uri
        return str(
            URL(self.authorize_url)
            .with_query(
                {
                    "response_type": "code",
                    "client_id": self.client_id,
                    "redirect_uri": redirect_uri,
                    "state": encode_jwt(
                        self.hass,
                        {
                            "flow_id": flow_id,
                            "redirect_uri": redirect_uri,
                        },
                    ),
                }
            )
            .update_query(self.extra_authorize_data)
        )

    @property
    def redirect_uri(self) -> str:
        """Return the redirect uri.

        This is similar to the oauth config flow, but doers not use "my" since
        the callback paths are different.
        """
        if (req := http.current_request.get()) is None:
            raise RuntimeError("No current request in context")

        if (ha_host := req.headers.get(HEADER_FRONTEND_BASE)) is None:
            raise RuntimeError("No header in request")

        return f"{ha_host}{AUTH_CALLBACK_PATH}"


@AUTH_PROVIDERS.register("openid")
class OpenIdAuthProvider(AuthProvider):
    """Auth provider using openid connect as the authentication source."""

    DEFAULT_TITLE = "OpenID Connect"

    _configuration: dict[str, Any]
    _jwks: dict[str, Any]
    _oauth2: OpenIdLocalOAuth2Implementation

    async def async_get_configuration(self) -> dict[str, Any]:
        """Get discovery document for OpenID."""
        session = async_get_clientsession(self.hass)
        return await async_get_configuration(session, self.config[CONF_CONFIGURATION])

    async def async_get_jwks(self) -> dict[str, Any]:
        """Get the keys for id verification."""
        session = async_get_clientsession(self.hass)
        async with session.get(self._configuration["jwks_uri"]) as response:
            await raise_for_status(response)
            data = await response.json()
        return cast(dict[str, Any], data)

    async def async_login_flow(self, context: AuthFlowContext | None) -> LoginFlow:
        """Return a flow to login."""

        if not hasattr(self, "_configuration"):
            self._configuration = await self.async_get_configuration()

        if not hasattr(self, "_jwks"):
            self._jwks = await self.async_get_jwks()

        self._oauth2 = OpenIdLocalOAuth2Implementation(
            self.hass,
            self.config[CONF_CLIENT_ID],
            self.config[CONF_CLIENT_SECRET],
            self._configuration,
        )
        return OpenIdLoginFlow(self)

    def _decode_id_token(self, token: dict[str, Any], nonce: str) -> dict[str, Any]:
        """Decode openid id_token."""

        algorithms = self._configuration["id_token_signing_alg_values_supported"]
        issuer = self._configuration["issuer"]

        id_token = jwt.decode(
            token["id_token"],
            algorithms=algorithms,
            issuer=issuer,
            key=self._jwks,
            audience=self.config[CONF_CLIENT_ID],
            access_token=token["access_token"],
        )
        if id_token.get("nonce") != nonce:
            raise InvalidAuthError("Nonce mismatch in id_token")

        return id_token

    def _authorize_id_token(self, id_token: dict[str, Any]) -> dict[str, Any]:
        """Authorize an id_token according to our internal database."""

        if id_token["sub"] in self.config.get(CONF_SUBJECTS, []):
            return id_token

        if "email" in id_token and "email_verified" in id_token:
            if (
                id_token["email"] in self.config.get(CONF_EMAILS, [])
                and id_token["email_verified"]
            ):
                return id_token

        raise InvalidAuthError(f"Subject {id_token['sub']} is not allowed")

    async def async_generate_authorize_url_with_nonce(
        self, flow_id: str, nonce: str
    ) -> str:
        """Generate an authorize url with a given nonce."""
        return await self._oauth2.async_generate_authorize_url_with_nonce(
            flow_id, nonce
        )

    async def async_authorize_external_data(
        self, external_data: dict[str, Any], nonce: str
    ) -> dict[str, Any]:
        """Authorize external data."""
        token = await self._oauth2.async_resolve_external_data(external_data)
        id_token = self._decode_id_token(token, nonce)
        return self._authorize_id_token(id_token)

    @property
    def support_mfa(self) -> bool:
        """Return whether multi-factor auth supported by the auth provider."""
        return False

    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        subject = flow_result["sub"]

        for credential in await self.async_credentials():
            if credential.data["sub"] == subject:
                _LOGGER.info("Accepting credential for %s", subject)
                return credential

        _LOGGER.info("Creating credential for %s", subject)
        return self.async_create_credentials({**flow_result})

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials.
        Will be used to populate info when creating a new user.
        """
        if "preferred_username" in credentials.data:
            name = credentials.data["preferred_username"]
        elif "given_name" in credentials.data:
            name = credentials.data["given_name"]
        elif "name" in credentials.data:
            name = credentials.data["name"]
        elif "email" in credentials.data:
            name = cast(str, credentials.data["email"]).split("@", 1)[0]
        else:
            name = credentials.data["sub"]

        return UserMeta(name=name, is_active=True)


class OpenIdLoginFlow(LoginFlow):
    """Handler for the login flow."""

    external_data: dict[str, str]
    _nonce: str

    async def async_step_init(
        self, user_input: Optional[dict[str, str]] = None
    ) -> AuthFlowResult:
        """Handle the step of the form."""
        return await self.async_step_authenticate()

    async def async_step_authenticate(
        self, user_input: Optional[dict[str, str]] = None
    ) -> AuthFlowResult:
        """Authenticate user using external step."""
        provider = cast(OpenIdAuthProvider, self._auth_provider)

        if user_input:
            self.external_data = user_input
            return self.async_external_step_done(next_step_id="authorize")

        self._nonce = token_hex()
        url = await provider.async_generate_authorize_url_with_nonce(
            self.flow_id, self._nonce
        )
        return self.async_external_step(step_id="authenticate", url=url)

    async def async_step_authorize(
        self, user_input: Optional[dict[str, str]] = None
    ) -> AuthFlowResult:
        """Authorize user received from external step."""
        provider = cast(OpenIdAuthProvider, self._auth_provider)
        try:
            result = await provider.async_authorize_external_data(
                self.external_data, self._nonce
            )
        except InvalidAuthError as error:
            _LOGGER.error("Login failed: %s", str(error))
            return self.async_abort(reason="invalid_auth")
        return await self.async_finish(result)


@callback
def encode_jwt(hass: HomeAssistant, data: dict) -> str:
    """JWT encode data."""
    if (secret := hass.data.get(DATA_JWT_SECRET)) is None:
        secret = hass.data[DATA_JWT_SECRET] = secrets.token_hex()

    return jwt.encode(data, secret, algorithm="HS256")


@callback
def decode_jwt(hass: HomeAssistant, encoded: str) -> dict[str, Any] | None:
    """JWT encode data."""
    secret: str | None = hass.data.get(DATA_JWT_SECRET)

    if secret is None:
        return None

    try:
        return jwt.decode(encoded, secret, algorithms=["HS256"])
    except DecodeError:
        return None


class AuthorizeCallbackView(http.HomeAssistantView):
    """OpenID Authorization Callback View."""

    requires_auth = False
    url = AUTH_CALLBACK_PATH
    name = "auth:external:callback"

    async def get(self, request: web.Request) -> web.Response:
        if "state" not in request.query:
            return web.Response(text="Missing state parameter")

        hass = request.app[http.KEY_HASS]

        state = decode_jwt(hass, request.query["state"])

        if state is None:
            _LOGGER.info("OIDC request contained invalid state")
            return web.Response(
                text=(
                    "Invalid state. Is My Home Assistant configured "
                    "to go to the right instance?"
                ),
                status=400,
            )

        user_input: dict[str, Any] = {"state": state}

        if "code" in request.query:
            user_input["code"] = request.query["code"]
        elif "error" in request.query:
            user_input["error"] = request.query["error"]
        else:
            return web.Response(text="Missing code or error parameter")

        flow_mgr = hass.auth.login_flow

        await flow_mgr.async_configure(flow_id=state["flow_id"], user_input=user_input)
        _LOGGER.debug("Resumed OAuth configuration flow")
        return web.Response(
            headers={"content-type": "text/html"},
            text="<script>if (window.opener) { window.opener.postMessage({type: 'externalCallback'}); } window.close();</script>",
        )
