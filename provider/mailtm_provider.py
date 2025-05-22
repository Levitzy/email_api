import asyncio
import json
import uuid
from email.utils import parseaddr
from typing import Any, Dict, List, Tuple

import requests

from .utils import (
    LOGGER,
    _rand_string,
    _format_timestamp_iso,
    make_requests_session,
    ProviderNetworkError,
    ProviderAPIError,
)

MAILTM_BASE_URL = "https://api.mail.tm"


async def _setup_internal_mail_tm_gw_like(
    base_url: str, provider_name: str, sess: requests.Session
) -> Tuple[str, str, Dict[str, Any]]:
    try:
        await asyncio.sleep(1)
        domains_res = await asyncio.to_thread(
            sess.get, f"{base_url}/domains?page=1", timeout=15
        )
        domains_res.raise_for_status()
        domains_data = domains_res.json()
        if not domains_data.get("hydra:member") or not domains_data["hydra:member"][
            0
        ].get("domain"):
            raise ProviderAPIError(f"{provider_name}: No domains available.")
        domain = domains_data["hydra:member"][0]["domain"]

        address = f"{_rand_string()}@{domain}"
        password = _rand_string(12)

        account_payload = {"address": address, "password": password}
        await asyncio.sleep(1)
        account_res = await asyncio.to_thread(
            sess.post, f"{base_url}/accounts", json=account_payload, timeout=15
        )
        account_res.raise_for_status()

        token_payload = {"address": address, "password": password}
        await asyncio.sleep(1)
        token_res = await asyncio.to_thread(
            sess.post, f"{base_url}/token", json=token_payload, timeout=15
        )
        token_res.raise_for_status()
        token_data = token_res.json()
        auth_token = token_data.get("token")
        if not auth_token:
            raise ProviderAPIError(f"{provider_name}: Failed to get auth token.")

        provider_data = {
            "base_url": base_url,
            "auth_token": auth_token,
            "address": address,
            "password": password,
        }
        return f"biar-{uuid.uuid4()}", address, provider_data
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            raise ProviderAPIError(f"{provider_name}: Too Many Requests. Details: {e}")
        raise ProviderNetworkError(f"{provider_name}: HTTP error setup: {e}") from e
    except requests.RequestException as e:
        raise ProviderNetworkError(f"{provider_name}: Network error setup: {e}") from e
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        raise ProviderAPIError(f"{provider_name}: API error setup: {e}") from e


async def _fetch_internal_mail_tm_gw_like_messages(
    provider_data: Dict[str, Any],
    provider_name: str,
    sess: requests.Session,
    active_sessions_ref: Dict[str, Any] = None,
    save_sessions_func: callable = None,
) -> List[Dict[str, Any]]:
    base_url = provider_data["base_url"]
    auth_token = provider_data["auth_token"]
    address = provider_data["address"]
    password = provider_data["password"]
    headers = {"Authorization": f"Bearer {auth_token}"}
    all_provider_messages = []

    try:
        await asyncio.sleep(0.5)
        inbox_res = await asyncio.to_thread(
            sess.get, f"{base_url}/messages", headers=headers, timeout=15
        )

        if inbox_res.status_code == 401:
            LOGGER.info(f"{provider_name}: Token expired, re-authenticating.")
            try:
                token_payload = {"address": address, "password": password}
                await asyncio.sleep(1)
                token_res = await asyncio.to_thread(
                    sess.post, f"{base_url}/token", json=token_payload, timeout=15
                )
                token_res.raise_for_status()
                new_auth_token = token_res.json().get("token")
                if not new_auth_token:
                    raise ProviderAPIError(
                        f"{provider_name}: Re-auth failed (no new token)."
                    )

                provider_data["auth_token"] = new_auth_token
                if active_sessions_ref and save_sessions_func:
                    api_session_id_for_update = provider_data.get("api_session_id")
                    if (
                        api_session_id_for_update
                        and api_session_id_for_update in active_sessions_ref
                    ):
                        active_sessions_ref[api_session_id_for_update][
                            "provider_specific_data"
                        ]["auth_token"] = new_auth_token
                        save_sessions_func()

                headers = {"Authorization": f"Bearer {new_auth_token}"}
                await asyncio.sleep(0.5)
                inbox_res = await asyncio.to_thread(
                    sess.get, f"{base_url}/messages", headers=headers, timeout=15
                )
            except requests.exceptions.HTTPError as reauth_e:
                if (
                    reauth_e.response is not None
                    and reauth_e.response.status_code == 429
                ):
                    raise ProviderAPIError(
                        f"{provider_name}: Too Many Requests (re-auth). Details: {reauth_e}"
                    )
                LOGGER.error(f"{provider_name}: Re-auth failed: {reauth_e}")
                raise ProviderAPIError(
                    f"{provider_name}: Re-auth failed."
                ) from reauth_e
            except Exception as reauth_e:
                LOGGER.error(f"{provider_name}: Re-auth failed: {reauth_e}")
                raise ProviderAPIError(
                    f"{provider_name}: Re-auth failed."
                ) from reauth_e

        inbox_res.raise_for_status()
        inbox_data = inbox_res.json()

        for m_summary in inbox_data.get("hydra:member", []):
            msg_id = str(m_summary["id"])
            await asyncio.sleep(0.1)
            full_email_res = await asyncio.to_thread(
                sess.get, f"{base_url}/messages/{msg_id}", headers=headers, timeout=15
            )
            full_email_res.raise_for_status()
            email_content = full_email_res.json()
            sender_email = None
            from_field_data = email_content.get("from")
            from_details_dict = None
            if isinstance(from_field_data, list) and len(from_field_data) > 0:
                from_details_dict = from_field_data[0]
            elif isinstance(from_field_data, dict):
                from_details_dict = from_field_data
            if from_details_dict and isinstance(from_details_dict, dict):
                raw_address_val = from_details_dict.get("address")
                sender_name = from_details_dict.get("name", "")
                if raw_address_val:
                    full_from_string = (
                        f"{sender_name} <{raw_address_val}>".strip()
                        if sender_name
                        else raw_address_val
                    )
                    name, addr = parseaddr(full_from_string)
                    sender_email = addr if addr else raw_address_val
            elif isinstance(from_field_data, str):
                name, addr = parseaddr(from_field_data)
                sender_email = addr if addr else from_field_data

            formatted_message = {
                "id": msg_id,
                "from": sender_email,
                "subject": email_content.get("subject"),
                "date": _format_timestamp_iso(email_content.get("createdAt")),
                "body": email_content.get("text", "").strip(),
                "html": email_content.get("html", []),
                "raw": email_content,
            }
            all_provider_messages.append(formatted_message)
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            raise ProviderAPIError(
                f"{provider_name}: Too Many Requests (fetch). Details: {e}"
            )
        LOGGER.warning(f"{provider_name}: HTTP error polling: {e}")
    except requests.RequestException as e:
        LOGGER.warning(f"{provider_name}: Network error polling: {e}")
    except (json.JSONDecodeError, KeyError) as e:
        LOGGER.warning(f"{provider_name}: API error polling: {e}")
    return all_provider_messages


async def setup_mail_tm(**kwargs) -> Tuple[str, str, Dict[str, Any]]:
    sess = make_requests_session()
    return await _setup_internal_mail_tm_gw_like(MAILTM_BASE_URL, "mail.tm", sess)


async def fetch_mail_tm_messages(
    provider_data: Dict[str, Any],
    active_sessions_ref: Dict[str, Any] = None,
    save_sessions_func: callable = None,
) -> List[Dict[str, Any]]:
    sess = make_requests_session()
    return await _fetch_internal_mail_tm_gw_like_messages(
        provider_data, "mail.tm", sess, active_sessions_ref, save_sessions_func
    )
