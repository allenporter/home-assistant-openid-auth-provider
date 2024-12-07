"""Test openid auth provider."""

from datetime import datetime, timezone
from unittest.mock import patch

import logging
from jose import jwt
import pytest
from aiohttp.test_utils import TestClient

from homeassistant import data_entry_flow
from homeassistant.core import HomeAssistant

from homeassistant.core_config import async_process_ha_core_config
from homeassistant.auth import AuthManager

from custom_components.openid_auth_provider.openid_auth_provider import (
    encode_jwt,
)
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker
from pytest_homeassistant_custom_component.typing import ClientSessionGenerator
from pytest_homeassistant_custom_component.common import MockConfigEntry


from .conftest import (
    CONST_DESCRIPTION_URI,
    CONST_DESCRIPTION,
    CONST_CLIENT_ID,
    CONST_SUBJECT,
    CONST_EMAIL,
    CONST_JWKS_URI,
    CONST_JWKS,
    CONST_TOKEN_ENDPOINT,
    CONST_JWKS_KEY,
    CONST_AUTHORIZATION_ENDPOINT,
)


_LOGGER = logging.getLogger(__name__)


PROVIDER_MODULE = "homeassistant.auth.providers.openid"

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
        {"internal_url": "http://example.com", "external_url": "http://external.com"},
    )


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
            "redirect_uri": "https://example.com/auth/oidc/callback",
        },
    )
    _LOGGER.debug("flow_id=%s", result["flow_id"])

    assert result["type"] == data_entry_flow.FlowResultType.EXTERNAL_STEP
    assert result["url"] == (
        f"{CONST_AUTHORIZATION_ENDPOINT}?response_type=code&client_id={
            CONST_CLIENT_ID}"
        "&redirect_uri=https://example.com/auth/oidc/callback"
        f"&state={state}&scope=email+openid+profile&nonce={CONST_NONCE}"
    )

    resp = await client.get(f"/auth/oidc/callback?code=abcd&state={state}")
    assert resp.status == 200
    assert resp.headers["content-type"] == "text/html; charset=utf-8"

    return result["flow_id"]


@pytest.mark.usefixtures("current_request_with_host", "openid_server", "endpoints")
async def test_login_flow_validates_email(
    hass: HomeAssistant,
    hass_client_no_auth: ClientSessionGenerator,
    config_entry: MockConfigEntry,
) -> None:
    """Test login flow with emails."""
    manager = hass.auth

    client = await hass_client_no_auth()
    flow_id = await _run_external_flow(hass, manager, client)

    result = await manager.login_flow.async_configure(flow_id)

    assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
    assert result["data"]["email"] == CONST_EMAIL


@pytest.mark.usefixtures("current_request_with_host", "openid_server", "endpoints")
async def test_login_flow_validates_subject(
    hass: HomeAssistant,
    hass_client_no_auth: ClientSessionGenerator,
    config_entry: MockConfigEntry,
) -> None:
    """Test login flow with subjects."""
    manager = hass.auth

    client = await hass_client_no_auth()
    flow_id = await _run_external_flow(hass, manager, client)

    result = await manager.login_flow.async_configure(flow_id)

    assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
    assert result["data"]["sub"] == CONST_SUBJECT


@pytest.mark.usefixtures("current_request_with_host", "openid_server", "endpoints")
@pytest.mark.parametrize(("emails", "subjects"), [([], [])])
async def test_login_flow_not_allowlisted(
    hass: HomeAssistant,
    hass_client_no_auth: ClientSessionGenerator,
    config_entry: MockConfigEntry,
) -> None:
    """Test login flow not in allowlist."""
    manager = hass.auth

    client = await hass_client_no_auth()
    flow_id = await _run_external_flow(hass, manager, client)

    result = await manager.login_flow.async_configure(flow_id)

    assert result["type"] == data_entry_flow.FlowResultType.ABORT
