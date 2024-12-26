"""openid_auth_provider custom component."""

from __future__ import annotations
import sys
import logging

from homeassistant.core import HomeAssistant
from homeassistant.const import Platform
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.typing import ConfigType

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
    await openid_auth_provider.async_setup(hass)

    # Currently auth providers are not real platforms and they assume
    # they are in a specific package. This is a hack to make it work for now
    # until home assistant is extended with a real with platform.
    sys.modules[f"homeassistant.auth.providers.{DOMAIN}"] = openid_auth_provider

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up a config entry."""
    await openid_auth_provider.async_setup_entry(hass, entry)

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
