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

GM_API_URL = "https://api.guerrillamail.com/ajax.php"
GM_USER_AGENT = "Mozilla/5.0 (TempMailAPI/1.0)"


async def setup_guerrillamail(**kwargs) -> Tuple[str, str, Dict[str, Any]]:
    sess = make_requests_session()
    sess.headers.update({"User-Agent": GM_USER_AGENT})
    try:
        params = {"f": "get_email_address", "ip": "127.0.0.1", "agent": GM_USER_AGENT}
        await asyncio.sleep(0.2)
        res = await asyncio.to_thread(sess.get, GM_API_URL, params=params, timeout=15)
        res.raise_for_status()
        init_data = res.json()
        if not init_data.get("sid_token") or not init_data.get("email_addr"):
            raise ProviderAPIError("GuerrillaMail: Failed to initialize session.")
        sid_token = init_data["sid_token"]
        address = init_data["email_addr"]
        provider_data = {
            "sid_token": sid_token,
            "requests_session_headers": dict(sess.headers),
        }
        return f"biar-{uuid.uuid4()}", address, provider_data
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            raise ProviderAPIError(f"GuerrillaMail: Too Many Requests. Details: {e}")
        raise ProviderNetworkError(f"GuerrillaMail: HTTP error: {e}") from e
    except requests.RequestException as e:
        raise ProviderNetworkError(f"GuerrillaMail: Network error: {e}") from e
    except (json.JSONDecodeError, KeyError) as e:
        raise ProviderAPIError(f"GuerrillaMail: API error: {e}") from e


async def fetch_guerrillamail_messages(
    provider_data: Dict[str, Any],
) -> List[Dict[str, Any]]:
    sess = make_requests_session()
    if "requests_session_headers" in provider_data:
        sess.headers.update(provider_data["requests_session_headers"])
    sid_token = provider_data.get("sid_token")
    if not sid_token:
        raise ProviderAPIError("GuerrillaMail: Missing sid_token.")

    all_provider_messages = []
    try:
        params = {"f": "check_email", "sid_token": sid_token, "seq": 0}
        await asyncio.sleep(0.2)
        res = await asyncio.to_thread(sess.get, GM_API_URL, params=params, timeout=15)
        res.raise_for_status()
        box_data = res.json()

        for m_summary in box_data.get("list", []):
            mail_id = str(m_summary["mail_id"])
            fetch_params = {
                "f": "fetch_email",
                "sid_token": sid_token,
                "email_id": mail_id,
            }
            await asyncio.sleep(0.1)
            full_email_res = await asyncio.to_thread(
                sess.get, GM_API_URL, params=fetch_params, timeout=15
            )
            full_email_res.raise_for_status()
            email_content = full_email_res.json()

            sender_email = None
            raw_from_field = email_content.get("mail_from")
            if raw_from_field:
                name, addr = parseaddr(raw_from_field)
                sender_email = addr if addr else raw_from_field

            formatted_message = {
                "id": mail_id,
                "from": sender_email,
                "subject": email_content.get("mail_subject"),
                "date": _format_timestamp_iso(email_content.get("mail_date")),
                "body": email_content.get("mail_body", "").strip(),
                "raw": email_content,
            }
            all_provider_messages.append(formatted_message)
    except requests.RequestException as e:
        LOGGER.warning(f"GuerrillaMail: Network error polling: {e}")
    except (json.JSONDecodeError, KeyError) as e:
        LOGGER.warning(f"GuerrillaMail: API error polling: {e}")
    return all_provider_messages
