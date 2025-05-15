import asyncio
import json
import uuid
from email.utils import parseaddr
from typing import Any, Dict, List, Tuple

import requests

from .utils import (
    LOGGER,
    _format_timestamp_iso,
    make_requests_session,
    ProviderNetworkError,
    ProviderAPIError,
)

TEMPMAIL_LOL_BASE_URL = "https://api.tempmail.lol"


async def setup_tempmail_lol(
    rush: bool = False, **kwargs
) -> Tuple[str, str, Dict[str, Any]]:
    sess = make_requests_session()
    endpoint = (
        f"{TEMPMAIL_LOL_BASE_URL}/generate/rush"
        if rush
        else f"{TEMPMAIL_LOL_BASE_URL}/generate"
    )
    try:
        await asyncio.sleep(0.2)
        res = await asyncio.to_thread(sess.get, endpoint, timeout=15)
        res.raise_for_status()
        data = res.json()
        address = data.get("address")
        token = data.get("token")
        if not address or not token:
            raise ProviderAPIError("tempmail.lol: Failed to get address or token.")
        provider_data = {"token": token, "base_url": TEMPMAIL_LOL_BASE_URL}
        return f"biar-{uuid.uuid4()}", address, provider_data
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            raise ProviderAPIError(f"tempmail.lol: Too Many Requests. Details: {e}")
        raise ProviderNetworkError(f"tempmail.lol: HTTP error setup: {e}") from e
    except requests.RequestException as e:
        raise ProviderNetworkError(f"tempmail.lol: Network error setup: {e}") from e
    except (json.JSONDecodeError, KeyError) as e:
        raise ProviderAPIError(f"tempmail.lol: API error setup: {e}") from e


async def fetch_tempmail_lol_messages(
    provider_data: Dict[str, Any],
    active_sessions_ref: Dict[str, Any],
    save_sessions_func: callable,
) -> List[Dict[str, Any]]:
    sess = make_requests_session()
    token = provider_data["token"]
    base_url = provider_data["base_url"]
    all_provider_messages = []
    try:
        await asyncio.sleep(0.2)
        res = await asyncio.to_thread(sess.get, f"{base_url}/auth/{token}", timeout=15)
        if res.status_code == 404:
            LOGGER.warning(
                f"tempmail.lol: Token {token} invalid (404). Session might be expired."
            )
            api_session_id_for_removal = provider_data.get("api_session_id")
            if (
                api_session_id_for_removal
                and api_session_id_for_removal in active_sessions_ref
            ):
                del active_sessions_ref[api_session_id_for_removal]
                save_sessions_func()
            raise ProviderAPIError(
                f"tempmail.lol: Token {token} is invalid or session expired."
            )
        res.raise_for_status()
        data = res.json()
        for m_content in data.get("email", []):
            date_val = m_content.get("date")
            msg_pseudo_id = f"{m_content.get('from')}_{m_content.get('subject')}_{str(date_val)}_{len(m_content.get('body',''))}"

            sender_email = None
            raw_from_field_val = m_content.get("from")
            if raw_from_field_val:
                name, addr = parseaddr(raw_from_field_val)
                sender_email = addr if addr else raw_from_field_val

            formatted_message = {
                "id": msg_pseudo_id,
                "from": sender_email,
                "subject": m_content.get("subject"),
                "date": _format_timestamp_iso(date_val),
                "body": m_content.get("body", "").strip(),
                "html": m_content.get("html"),
                "raw": m_content,
            }
            all_provider_messages.append(formatted_message)
    except requests.RequestException as e:
        LOGGER.warning(f"tempmail.lol: Network error polling: {e}")
    except (json.JSONDecodeError, KeyError) as e:
        LOGGER.warning(f"tempmail.lol: API error polling: {e}")
    return all_provider_messages
