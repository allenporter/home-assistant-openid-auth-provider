"""Config flow for openid_auth_provider integration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol

from homeassistant.const import CONF_NAME
from homeassistant.helpers import device_registry as dr, selector
from homeassistant.helpers.schema_config_entry_flow import (
    SchemaConfigFlowHandler,
    SchemaFlowFormStep,
    SchemaFlowError,
    SchemaCommonFlowHandler,
)

from .const import DOMAIN, CONF_CONFIGURATION, CONF_CLIENT_ID, CONF_CLIENT_SECRET, CONF_EMAILS, CONF_SUBJECTS


async def _validate_user_input(handler: SchemaCommonFlowHandler, user_input: dict[str, Any]) -> dict[str, Any]:
    """Validate user input."""
    if emails := user_input.get(CONF_EMAILS):
        user_input[CONF_EMAILS] = [email.strip() for email in emails]
    if subjects := user_input.get(CONF_SUBJECTS):
        user_input[CONF_SUBJECTS] = [subject.strip() for subject in subjects]
    if emails is None and subjects is None:
        raise SchemaFlowError("missing_email_or_subject")
    return user_input


CONFIG_FLOW = {
    "user": SchemaFlowFormStep(
        vol.Schema(
            {
                vol.Required(CONF_NAME): str,
                vol.Required(CONF_CONFIGURATION): selector.TextSelector(
                    selector.TextSelectorConfig(
                        type=selector.TextSelectorType.URL,
                    )
                ),
                vol.Required(CONF_CLIENT_ID): str,
                vol.Required(CONF_CLIENT_SECRET): str,
                vol.Optional(CONF_EMAILS): selector.TextSelector(
                    selector.TextSelectorConfig(
                        type=selector.TextSelectorType.EMAIL,
                        multiple=True,
                    )
                ),
                vol.Optional(CONF_SUBJECTS): selector.TextSelector(
                    selector.TextSelectorConfig(
                        type=selector.TextSelectorType.TEXT,
                        multiple=True,
                    )
                ),

            }
        ),
        validate_user_input=_validate_user_input,
    )
}

OPTIONS_FLOW = {
    "init": CONFIG_FLOW["user"],
}


class OpenIDAuthProviderConfigFlowHandler(SchemaConfigFlowHandler, domain=DOMAIN):
    """Handle a config flow for Switch as X."""

    config_flow = CONFIG_FLOW
    options_flow = OPTIONS_FLOW

    VERSION = 1
    MINOR_VERSION = 1

    def async_config_entry_title(self, options: Mapping[str, Any]) -> str:
        """Return config entry title."""
        return options[CONF_NAME]
