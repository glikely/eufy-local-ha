from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

from .ble import EufyBLEController, EufyBLEError, async_read_device_info
from .const import (
    CONF_ACHROMATIC_RATIO,
    CONF_GAMMA,
    CONF_SATURATION,
    CONF_SERIAL_NUMBER,
    CONF_USER_ID,
    CONF_WHITE_BALANCE_B,
    CONF_WHITE_BALANCE_G,
    DEFAULT_ACHROMATIC_RATIO,
    DEFAULT_DEVICE_NAME,
    DEFAULT_GAMMA,
    DEFAULT_SATURATION,
    DEFAULT_USER_ID,
    DEFAULT_WHITE_BALANCE_B,
    DEFAULT_WHITE_BALANCE_G,
    DOMAIN,
)


def _validate(user_input: dict[str, Any]) -> dict[str, str]:
    errors: dict[str, str] = {}
    serial = user_input.get(CONF_SERIAL_NUMBER, "").strip()
    user_id = user_input.get(CONF_USER_ID, "").strip()
    if serial and len(serial) != 16:
        errors[CONF_SERIAL_NUMBER] = "invalid_serial"
    if user_id and len(user_id) < 16:
        errors[CONF_USER_ID] = "invalid_user_id"
    return errors


class EufyLocalConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):

    VERSION = 1

    def __init__(self) -> None:
        self._discovered_address: str | None = None
        self._discovered_name: str | None = None
        self._serial: str | None = None
        self._probed = False

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> FlowResult:
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        self._discovered_address = discovery_info.address
        self._discovered_name = discovery_info.name
        self.context["title_placeholders"] = {
            "name": discovery_info.name or DEFAULT_DEVICE_NAME
        }
        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        # Connect only once the user confirms: the light takes one Bluetooth
        # connection at a time, and discovery alone shouldn't take it from the
        # eufy app.
        errors: dict[str, str] = {}
        if user_input is not None:
            assert self._discovered_address is not None
            error = await self._async_probe(self._discovered_address)
            if error is None:
                return await self._async_try_create(
                    self._discovered_address, DEFAULT_USER_ID, "bluetooth_confirm"
                )
            errors["base"] = error

        self._set_confirm_only()
        return self.async_show_form(
            step_id="bluetooth_confirm",
            description_placeholders={
                "name": self._discovered_name or DEFAULT_DEVICE_NAME
            },
            errors=errors,
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            errors = _validate(user_input)
            if not errors:
                address = user_input[CONF_ADDRESS].strip()
                await self.async_set_unique_id(address, raise_on_progress=False)
                self._abort_if_unique_id_configured()
                self._discovered_address = address
                serial = user_input.get(CONF_SERIAL_NUMBER, "").strip()
                user_id = user_input.get(CONF_USER_ID, "").strip()
                if serial:
                    self._serial = serial
                else:
                    error = await self._async_probe(address)
                    if error is not None:
                        errors["base"] = error
                if not errors:
                    return await self._async_try_create(
                        address, user_id or DEFAULT_USER_ID, "user"
                    )

        schema = vol.Schema(
            {
                vol.Required(
                    CONF_ADDRESS, default=self._discovered_address or ""
                ): str,
                vol.Optional(CONF_SERIAL_NUMBER, default=""): str,
                vol.Optional(CONF_USER_ID, default=""): str,
            }
        )
        return self.async_show_form(
            step_id="user", data_schema=schema, errors=errors
        )

    async def async_step_user_id(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Ask for a eufy user id when the light refused the all-zero one."""
        errors: dict[str, str] = {}
        if user_input is not None:
            errors = _validate(user_input)
            if not errors:
                return await self._async_try_create(
                    self._discovered_address or "",
                    user_input[CONF_USER_ID].strip(),
                    "user_id",
                )

        return self.async_show_form(
            step_id="user_id",
            data_schema=vol.Schema({vol.Required(CONF_USER_ID): str}),
            errors=errors,
        )

    async def _async_probe(self, address: str) -> str | None:
        """Read the serial number off the light; return an error key or None."""
        try:
            info = await async_read_device_info(self.hass, address)
        except EufyBLEError:
            return "cannot_connect"
        self._serial = info.serial_number
        self._probed = True
        return None

    async def _async_try_create(
        self, address: str, user_id: str, step_id: str
    ) -> FlowResult:
        """Check that a session can be set up, then create the entry."""
        assert self._serial is not None
        controller = EufyBLEController(self.hass, address, self._serial, user_id)
        try:
            await controller.async_ensure_connected()
        except EufyBLEError:
            if user_id == DEFAULT_USER_ID and self._probed:
                # The probe reached the light a moment ago, so a failed
                # handshake most likely means it wants a real account id.
                return await self.async_step_user_id()
            return self.async_show_form(
                step_id=step_id,
                errors={"base": "handshake_failed"},
                description_placeholders={
                    "name": self._discovered_name or DEFAULT_DEVICE_NAME
                },
                data_schema=self._schema_for(step_id),
            )
        finally:
            await controller.async_disconnect()

        data = {
            CONF_ADDRESS: address,
            CONF_SERIAL_NUMBER: self._serial,
            CONF_USER_ID: user_id,
        }
        return self.async_create_entry(
            title=self._discovered_name or DEFAULT_DEVICE_NAME, data=data
        )

    def _schema_for(self, step_id: str) -> vol.Schema | None:
        if step_id == "user_id":
            return vol.Schema({vol.Required(CONF_USER_ID): str})
        if step_id == "user":
            return vol.Schema(
                {
                    vol.Required(
                        CONF_ADDRESS, default=self._discovered_address or ""
                    ): str,
                    vol.Optional(CONF_SERIAL_NUMBER, default=""): str,
                    vol.Optional(CONF_USER_ID, default=""): str,
                }
            )
        return None

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> "EufyLocalOptionsFlow":
        return EufyLocalOptionsFlow(config_entry)


class EufyLocalOptionsFlow(config_entries.OptionsFlow):
    """Color tuning options."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        opts = self._entry.options
        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_GAMMA, default=opts.get(CONF_GAMMA, DEFAULT_GAMMA)
                ): vol.All(vol.Coerce(float), vol.Range(min=0.5, max=3.0)),
                vol.Optional(
                    CONF_SATURATION,
                    default=opts.get(CONF_SATURATION, DEFAULT_SATURATION),
                ): vol.All(vol.Coerce(float), vol.Range(min=0.0, max=1.0)),
                vol.Optional(
                    CONF_ACHROMATIC_RATIO,
                    default=opts.get(
                        CONF_ACHROMATIC_RATIO, DEFAULT_ACHROMATIC_RATIO
                    ),
                ): vol.All(vol.Coerce(float), vol.Range(min=0.0, max=1.0)),
                vol.Optional(
                    CONF_WHITE_BALANCE_G,
                    default=opts.get(
                        CONF_WHITE_BALANCE_G, DEFAULT_WHITE_BALANCE_G
                    ),
                ): vol.All(vol.Coerce(float), vol.Range(min=0.0, max=1.0)),
                vol.Optional(
                    CONF_WHITE_BALANCE_B,
                    default=opts.get(
                        CONF_WHITE_BALANCE_B, DEFAULT_WHITE_BALANCE_B
                    ),
                ): vol.All(vol.Coerce(float), vol.Range(min=0.0, max=1.0)),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
