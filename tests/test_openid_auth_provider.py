"""Test openid auth provider."""

from datetime import datetime, timezone
from unittest.mock import patch

import logging
from jose import jwt
import pytest
from aiohttp.test_utils import TestClient

from homeassistant import data_entry_flow
from homeassistant.core import HomeAssistant
from homeassistant.auth import auth_manager_from_config

from homeassistant.core_config import async_process_ha_core_config
from homeassistant.auth import AuthManager
from homeassistant.setup import async_setup_component

from custom_components.openid_auth_provider.openid_auth_provider import (
    encode_jwt,
)
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker
from pytest_homeassistant_custom_component.typing import ClientSessionGenerator
from pytest_homeassistant_custom_component.common import MockConfigEntry


from .conftest import CONST_DESCRIPTION_URI, CONST_CLIENT_ID, CONST_CLIENT_SECRET, CONST_SUBJECT, CONST_EMAIL


_LOGGER = logging.getLogger(__name__)


PROVIDER_MODULE = "homeassistant.auth.providers.openid"

CONST_JWKS_URI = "https://jwks.test/jwks"
CONST_JWKS_KEY = "bla"
CONST_JWKS = {"keys": [CONST_JWKS_KEY]}

CONST_AUTHORIZATION_ENDPOINT = "https://openid.test/authorize"
CONST_TOKEN_ENDPOINT = "https://openid.test/authorize"

CONST_DESCRIPTION = {
    "issuer": "https://openid.test/",
    "jwks_uri": CONST_JWKS_URI,
    "authorization_endpoint": CONST_AUTHORIZATION_ENDPOINT,
    "token_endpoint": CONST_TOKEN_ENDPOINT,
    "token_endpoint_auth_methods_supported": "client_secret_post",
    "id_token_signing_alg_values_supported": ["RS256", "HS256"],
    "scopes_supported": ["openid", "email", "profile"],
    "response_types_supported": "code",
}

CONST_ACCESS_TOKEN = "dummy_access_token"

CONST_NONCE = "dummy_nonce"

CONST_ID_TOKEN = {
    "iss": "https://openid.test/",
    "sub": CONST_SUBJECT,
    "aud": CONST_CLIENT_ID,
    "nonce": CONST_NONCE,
    "exp": datetime(2099, 1, 1, tzinfo=timezone.utc).timestamp(),
    "iat": datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp(),
    "name": "John Doe",
    "email": CONST_EMAIL,
    "email_verified": True,
}


@pytest.fixture(name="openid_server")
async def openid_server_fixture(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Mock openid server."""
    aioclient_mock.get(
        CONST_DESCRIPTION_URI,
        json=CONST_DESCRIPTION,
    )

    aioclient_mock.get(
        CONST_JWKS_URI,
        json=CONST_JWKS,
    )

    aioclient_mock.post(
        CONST_TOKEN_ENDPOINT,
        json={
            "access_token": CONST_ACCESS_TOKEN,
            "type": "bearer",
            "expires_in": 60,
            "id_token": jwt.encode(
                CONST_ID_TOKEN, CONST_JWKS_KEY, access_token=CONST_ACCESS_TOKEN
            ),
        },
    )


@pytest.fixture(name="endpoints")
async def endpoints_fixture(hass: HomeAssistant) -> None:
    """Initialize the needed endpoints and redirects."""
    await async_process_ha_core_config(
        hass,
        {"external_url": "http://example.com"},
    )
    # assert await async_setup_component(hass, "openid_auth_provider", {})


async def _run_external_flow(
    hass: HomeAssistant, manager: AuthManager, client: TestClient
) -> str:
    with patch(f"{PROVIDER_MODULE}.token_hex") as token_hex:
        token_hex.return_value = CONST_NONCE
        result = await manager.login_flow.async_init(("openid", None))  # type: ignore

    state = encode_jwt(
        hass,
        {
            "flow_id": result["flow_id"],
            "redirect_uri": "https://example.com/auth/openid/callback",
        },
    )
    _LOGGER.debug("flow_id=%s", result["flow_id"])

    assert result["type"] == data_entry_flow.RESULT_TYPE_EXTERNAL_STEP
    assert result["url"] == (
        f"{CONST_AUTHORIZATION_ENDPOINT}?response_type=code&client_id={
            CONST_CLIENT_ID}"
        "&redirect_uri=https://example.com/auth/openid/callback"
        f"&state={state}&scope=email+openid+profile&nonce={CONST_NONCE}"
    )

    resp = await client.get(f"/auth/openid/callback?code=abcd&state={state}")
    assert resp.status == 200
    assert resp.headers["content-type"] == "text/html; charset=utf-8"

    return result["flow_id"]


@pytest.mark.usefixtures("current_request_with_host", "openid_server", "endpoints")
async def test_login_flow_validates_email(
    hass: HomeAssistant, hass_client_no_auth: ClientSessionGenerator, config_entry: MockConfigEntry,
) -> None:
    """Test login flow with emails."""
    manager = hass.auth

    client = await hass_client_no_auth()
    flow_id = await _run_external_flow(hass, manager, client)

    result = await manager.login_flow.async_configure(flow_id)

    assert result["type"] == data_entry_flow.RESULT_TYPE_CREATE_ENTRY
    assert result["data"]["email"] == CONST_EMAIL


@pytest.mark.usefixtures("current_request_with_host", "openid_server", "endpoints")
async def test_login_flow_validates_subject(
    hass: HomeAssistant,
    hass_client_no_auth: ClientSessionGenerator, config_entry: MockConfigEntry,
) -> None:
    """Test login flow with subjects."""
    manager = hass.auth

    client = await hass_client_no_auth()
    flow_id = await _run_external_flow(hass, manager, client)

    result = await manager.login_flow.async_configure(flow_id)

    assert result["type"] == data_entry_flow.RESULT_TYPE_CREATE_ENTRY
    assert result["data"]["sub"] == CONST_SUBJECT


@pytest.mark.usefixtures("current_request_with_host", "openid_server", "endpoints")
@pytest.mark.parametrize(("emails", "subjects"), [([], [])])
async def test_login_flow_not_allowlisted(
    hass: HomeAssistant,
    hass_client_no_auth: ClientSessionGenerator, config_entry: MockConfigEntry,
) -> None:
    """Test login flow not in allowlist."""
    manager = hass.auth

    client = await hass_client_no_auth()
    flow_id = await _run_external_flow(hass, manager, client)

    result = await manager.login_flow.async_configure(flow_id)

    assert result["type"] == data_entry_flow.RESULT_TYPE_ABORT
