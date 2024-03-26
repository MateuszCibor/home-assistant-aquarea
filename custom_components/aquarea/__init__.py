"""The Aquarea Smart Cloud integration."""
from __future__ import annotations

from typing import Any

import aioaquarea
import aiohttp
import asyncio
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

PLATFORMS: list[Platform] = [
    Platform.BUTTON,
    Platform.SENSOR,
    Platform.CLIMATE,
    Platform.BINARY_SENSOR,
    Platform.WATER_HEATER,
    Platform.SWITCH,
    Platform.SELECT
]

async def _create_client(hass: HomeAssistant, entry: ConfigEntry) -> aioaquarea.Client:
    username = entry.data.get(CONF_USERNAME)
    password = entry.data.get(CONF_PASSWORD)
    session = async_create_clientsession(hass)
    return aioaquarea.Client(session, username, password)

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Aquarea Smart Cloud from a config entry."""

    client = await _create_client(hass, entry)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        CLIENT: client,
        DEVICES: dict[str, AquareaDataUpdateCoordinator](),
    }

    try:
        async with aiohttp.ClientSession() as session:
            # Nowy sposób autoryzacji
            auth0State = response.headers['set-cookie']?.map(cookie => cookie?.match(/com.auth0.state=(.+?);/i)?.[1]).filter(c => !!c)[0] ?? undefined
            response1 = await session.get(
                f"https://authglb.digital.panasonic.com/authorize?audience=https://digital.panasonic.com/{clientId}/api/v1/&client_id={clientId}&redirect_uri=https://aquarea-smart.panasonic.com/authorizationCallback&response_type=code&scope=openid offline_access&state={auth0State}",
                headers={"Referer": "https://aquarea-smart.panasonic.com/"}
            )

            if response1.status != 200:
                raise Exception(f"Wrong response on location redirect: {response1.status}")

            csrf = response1.headers.get('set-cookie')?.map(cookie => cookie?.match(/_csrf=(.+?);/i)?.[1]).filter(c => !!c)[0] ?? undefined

            response2 = await session.post(
                "https://authglb.digital.panasonic.com/usernamepassword/login",
                headers={
                    "Auth0-Client": "eyJuYW1lIjoiYXV0aDAuanMtdWxwIiwidmVyc2lvbiI6IjkuMjMuMiJ9",
                    "Content-Type": "application/json; charset=UTF-8",
                    "Referer": f"https://authglb.digital.panasonic.com/login?audience=https://digital.panasonic.com/{clientId}/api/v1/&client={clientId}&protocol=oauth2&redirect_uri=https://aquarea-smart.panasonic.com/authorizationCallback&response_type=code&scope=openid offline_access&state={auth0State}",
                    "Cookie": f"_csrf={csrf}",
                },
                json={
                    "client_id": clientId,
                    "redirect_uri": "https://aquarea-smart.panasonic.com/authorizationCallback?lang=en",
                    "tenant": "pdpauthglb-a1",
                    "response_type": "code",
                    "scope": "openid offline_access",
                    "audience": f"https://digital.panasonic.com/{clientId}/api/v1/",
                    "_csrf": csrf,
                    "state": auth0State,
                    "_intstate": "deprecated",
                    "username": entry.data.get(CONF_USERNAME),
                    "password": entry.data.get(CONF_PASSWORD),
                    "lang": "en",
                    "connection": "PanasonicID-Authentication",
                }
            )

            actionUrl = response2.data.match(/action="(.+?)"/i)?.[1]
            inputs = response2.data.match(/<input([^\0]+?)>/ig) ?? []
            formData = {}
            for input in inputs:
                name = input.match(/name="(.+?)"/i)?.[1]
                value = input.match(/value="(.+?)"/i)?.[1]
                if name and value:
                    formData[name] = value

            response3 = await session.post(
                actionUrl,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Referer": f"https://authglb.digital.panasonic.com/login?audience=https://digital.panasonic.com/{clientId}/api/v1/&client={clientId}&protocol=oauth2&redirect_uri=https://aquarea-smart.panasonic.com/authorizationCallback&response_type=code&scope=openid offline_access&state={auth0State}",
                    "Cookie": f"_csrf={csrf}",
                },
                data=formData
            )

            location1 = response3.headers.get('location')

            response4 = await session.get(
                f"https://authglb.digital.panasonic.com{location1}",
                headers={"Cookie": f"_csrf={csrf}"}
            )

            auth0Compat = response4.headers.get('set-cookie')?.map(cookie => cookie?.match(/auth0_compat=(.+?);/i)?.[1]).filter(c => !!c)[0] ?? undefined
            auth0 = response4.headers.get('set-cookie')?.map(cookie => cookie?.match(/auth0=(.+?);/i)?.[1]).filter(c => !!c)[0] ?? undefined

            location2 = response4.headers.get('location')

            response5 = await session.get(
                location2,
                headers={"Cookie": f"_csrf={csrf}; auth0={auth0}; auth0_compat={auth0Compat}"}
            )

            accessToken = response5.headers.get('set-cookie')?.map(cookie => cookie?.match(/accessToken=(.+?);/i)?.[1]).filter(c => !!c)[0] ?? undefined

            # reszta kodu integracji Aquarea

    except aioaquarea.AuthenticationError as err:
        if err.error_code in (
            aioaquarea.AuthenticationErrorCodes.INVALID_USERNAME_OR_PASSWORD,
            aioaquarea.AuthenticationErrorCodes.INVALID_CREDENTIALS,
        ):
            raise ConfigEntryAuthFailed from err

    return True
