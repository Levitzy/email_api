import asyncio
import json
import uuid
from email.utils import parseaddr
from typing import Any, Dict, List, Tuple
from datetime import datetime, timezone # Ensure datetime and timezone are imported

import requests

from .utils import LOGGER, _rand_string, _format_timestamp_iso, make_requests_session, ProviderNetworkError, ProviderAPIError

DROPMAIL_ME_BASE_URL = "https://dropmail.me/api/graphql"

async def setup_dropmail_me(**kwargs) -> Tuple[str, str, Dict[str, Any]]:
    sess = make_requests_session()
    client_session_token = _rand_string(16)
    query = "mutation { introduceSession { id expiresAt addresses { address } } }"
    try:
        await asyncio.sleep(0.2)
        res = await asyncio.to_thread(
            sess.post,
            f"{DROPMAIL_ME_BASE_URL}/{client_session_token}",
            json={"query": query},
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        res.raise_for_status()
        response_data = res.json()
        session_data = response_data.get("data", {}).get("introduceSession")
        if not session_data:
            raise ProviderAPIError(
                f"dropmail.me: 'introduceSession' data not found: {response_data.get('errors')}"
            )

        session_id_val = session_data.get("id")
        addresses = session_data.get("addresses", [])
        if not session_id_val or not addresses or not addresses[0].get("address"):
            raise ProviderAPIError("dropmail.me: Failed to get session ID or address.")
        address = addresses[0]["address"]
        expires_at_str = session_data.get("expiresAt")

        provider_data = {
            "session_id": session_id_val,
            "client_session_token": client_session_token,
            "base_url": DROPMAIL_ME_BASE_URL,
            "expires_at": _format_timestamp_iso(expires_at_str),
        }
        return f"biar-{uuid.uuid4()}", address, provider_data
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            raise ProviderAPIError(f"dropmail.me: Too Many Requests. Details: {e}")
        raise ProviderNetworkError(f"dropmail.me: HTTP error setup: {e}") from e
    except requests.RequestException as e:
        raise ProviderNetworkError(f"dropmail.me: Network error setup: {e}") from e
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
        raise ProviderAPIError(f"dropmail.me: API error setup: {e}") from e

async def fetch_dropmail_me_messages(
    provider_data: Dict[str, Any], active_sessions_ref: Dict[str, Any], save_sessions_func: callable
) -> List[Dict[str, Any]]:
    sess = make_requests_session()
    dropmail_session_id = provider_data["session_id"]
    client_session_token = provider_data["client_session_token"]
    base_url = provider_data["base_url"]
    query = "query($id: ID!){ session(id: $id){ mails{ id fromAddr toAddr headerSubject text html receivedAt downloadUrl } } }"
    variables = {"id": dropmail_session_id}
    all_provider_messages = []

    try:
        expires_at_val = provider_data.get("expires_at")
        if expires_at_val and isinstance(expires_at_val, str):
            expires_dt = datetime.fromisoformat(expires_at_val.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expires_dt:
                LOGGER.warning(
                    f"dropmail.me: Session {dropmail_session_id} has expired."
                )
                api_session_id_for_removal = provider_data.get("api_session_id")
                if api_session_id_for_removal and api_session_id_for_removal in active_sessions_ref:
                    del active_sessions_ref[api_session_id_for_removal]
                    save_sessions_func()
                raise ProviderAPIError(f"dropmail.me: Session has expired at {expires_at_val}.")

        await asyncio.sleep(0.2)
        res = await asyncio.to_thread(
            sess.post,
            f"{base_url}/{client_session_token}",
            json={"query": query, "variables": variables},
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        res.raise_for_status()
        response_data = res.json()
        session_query_data = response_data.get("data", {}).get("session")

        if session_query_data is None:
            LOGGER.warning(
                f"dropmail.me: Session data not found for ID {dropmail_session_id}. Might be expired."
            )
            api_session_id_for_removal = provider_data.get("api_session_id")
            if api_session_id_for_removal and api_session_id_for_removal in active_sessions_ref:
                del active_sessions_ref[api_session_id_for_removal]
                save_sessions_func()
            raise ProviderAPIError(
                f"dropmail.me: Session {dropmail_session_id} not found or expired on server."
            )

        mails = session_query_data.get("mails", [])
        for m_content in mails:
            msg_id = str(m_content["id"])
            sender_email = None
            raw_from_field_val = m_content.get("fromAddr")
            if raw_from_field_val:
                name, addr = parseaddr(raw_from_field_val)
                sender_email = addr if addr else raw_from_field_val

            formatted_message = {
                "id": msg_id, "from": sender_email, "to": m_content.get("toAddr"),
                "subject": m_content.get("headerSubject"),
                "date": _format_timestamp_iso(m_content.get("receivedAt")),
                "body": m_content.get("text", "").strip(), "html": m_content.get("html"),
                "downloadUrl": m_content.get("downloadUrl"), "raw": m_content,
            }
            all_provider_messages.append(formatted_message)
    except requests.RequestException as e:
        LOGGER.warning(f"dropmail.me: Network error polling: {e}")
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        LOGGER.warning(f"dropmail.me: API error polling: {e}")
    return all_provider_messages
