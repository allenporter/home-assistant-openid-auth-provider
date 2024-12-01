"""Tests for the config flow."""

from unittest.mock import patch


from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.core import HomeAssistant
from homeassistant.const import (
    CONF_DEVICE_ID,
)


from custom_components.openid_auth_provider.const import DOMAIN


async def test_select_device(
    hass: HomeAssistant,
    zwave_device_id: str,
) -> None:
    """Test selecting a device in the configuration flow."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result.get("type") is FlowResultType.FORM
    assert result.get("errors") is None

    with patch(
        f"custom_components.{DOMAIN}.async_setup_entry", return_value=True
    ) as mock_setup:
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_DEVICE_ID: zwave_device_id,
            },
        )
        await hass.async_block_till_done()

    assert result.get("type") is FlowResultType.CREATE_ENTRY
    assert result.get("title") == "Open ID Auth Provider"
    assert result.get("data") == {}
    assert result.get("options") == {
        CONF_DEVICE_ID: zwave_device_id,
    }
    assert len(mock_setup.mock_calls) == 1
