"""openid_auth_provider custom component."""

from __future__ import annotations
import sys
import logging

from homeassistant.core import HomeAssistant
from homeassistant.const import Platform, CONF_AUTH_PROVIDERS, CONF_AUTH_MFA_MODULES
from homeassistant.auth import auth_manager_from_config
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.typing import ConfigType
from homeassistant.auth import auth_manager_from_config

from .const import DOMAIN
from . import openid_auth_provider

_LOOGER = logging.getLogger(__name__)

__all__ = [
    "DOMAIN",
]

_LOGGER = logging.getLogger(__name__)

PLATFORMS: tuple[Platform] = ()  # type: ignore


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the config."""
    hass.data.setdefault(DOMAIN, {})
    homeassistant_config = config.get("homeassistant", {})
    if CONF_AUTH_MFA_MODULES in homeassistant_config:
        _LOOGER.error("OpenID not supported when MFA modules are configured")
        return False
    hass.data[DOMAIN][CONF_AUTH_PROVIDERS] = homeassistant_config.get(CONF_AUTH_PROVIDERS)

    sys.modules["homeassistant.auth.providers.openid"] = openid_auth_provider
    openid_auth_provider.register(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up a config entry."""

    auth_providers = hass.data[DOMAIN][CONF_AUTH_PROVIDERS]
    if not auth_providers:
        auth_providers = [{"type": "homeassistant"}]
    auth_providers.append(
        {
            "type": "openid",
            **entry.options,
        }
    )
    hass.auth = await auth_manager_from_config(hass, auth_providers, [])



    await hass.config_entries.async_forward_entry_setups(
        entry,
        platforms=PLATFORMS,
    )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(
        entry,
        PLATFORMS,
    )
