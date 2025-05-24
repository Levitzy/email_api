import asyncio
import json
import uuid
import re
import hashlib
from email.utils import parseaddr
from typing import Any, Dict, List, Tuple, Optional

import requests

from .utils import (
    LOGGER,
    _rand_string,
    _format_timestamp_iso,
    make_requests_session,
    ProviderNetworkError,
    ProviderAPIError,
)

TEMPMAIL_ORG_BASE_URL = "https://api.temp-mail.org"
TEMPMAIL_ORG_WEB_URL = "https://temp-mail.org"


async def setup_tempmail_org(**kwargs) -> Tuple[str, str, Dict[str, Any]]:
    """Setup temp-mail.org session."""
    sess = make_requests_session()
    sess.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": TEMPMAIL_ORG_WEB_URL,
            "Origin": TEMPMAIL_ORG_WEB_URL,
        }
    )

    try:
        await asyncio.sleep(0.3)
        res = await asyncio.to_thread(
            sess.get, f"{TEMPMAIL_ORG_BASE_URL}/v1/request/domains", timeout=15
        )
        res.raise_for_status()
        domains_data = res.json()

        if (
            not domains_data
            or not isinstance(domains_data, list)
            or len(domains_data) == 0
        ):
            raise ProviderAPIError("temp-mail.org: No domains available")

        domain = domains_data[0]
        username = _rand_string(10)
        email_address = f"{username}@{domain}"

        session_token = _rand_string(32)

        provider_data = {
            "email_address": email_address,
            "username": username,
            "domain": domain,
            "session_token": session_token,
            "base_url": TEMPMAIL_ORG_BASE_URL,
        }

        LOGGER.info(f"temp-mail.org: Successfully created email: {email_address}")
        return f"biar-{uuid.uuid4()}", email_address, provider_data

    except requests.RequestException as e:
        error_msg = f"temp-mail.org: Network error during setup: {str(e)}"
        LOGGER.error(error_msg)
        raise ProviderNetworkError(error_msg) from e
    except Exception as e:
        error_msg = f"temp-mail.org: Unexpected error during setup: {str(e)}"
        LOGGER.error(error_msg, exc_info=True)
        raise ProviderAPIError(error_msg) from e


async def fetch_tempmail_org_messages(
    provider_data: Dict[str, Any],
    active_sessions_ref: Dict[str, Any] = None,
    save_sessions_func: callable = None,
) -> List[Dict[str, Any]]:
    """Fetch messages from temp-mail.org."""
    sess = make_requests_session()
    sess.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": TEMPMAIL_ORG_WEB_URL,
            "Origin": TEMPMAIL_ORG_WEB_URL,
        }
    )

    username = provider_data.get("username")
    domain = provider_data.get("domain")

    if not username or not domain:
        raise ProviderAPIError(
            "temp-mail.org: Missing username or domain in session data"
        )

    all_provider_messages = []

    try:
        await asyncio.sleep(0.3)
        res = await asyncio.to_thread(
            sess.get,
            f"{TEMPMAIL_ORG_BASE_URL}/v1/request/mail/id/{username}/domain/{domain}",
            timeout=15,
        )

        if res.status_code == 404:
            LOGGER.info(f"temp-mail.org: No messages found for {username}@{domain}")
            return []

        res.raise_for_status()
        messages_data = res.json()

        if not isinstance(messages_data, list):
            LOGGER.warning(
                f"temp-mail.org: Unexpected response format: {type(messages_data)}"
            )
            return []

        for msg_data in messages_data:
            if not isinstance(msg_data, dict):
                continue

            try:
                processed_message = _process_message_data(msg_data)
                if processed_message:
                    all_provider_messages.append(processed_message)
            except Exception as e:
                LOGGER.error(
                    f"temp-mail.org: Error processing message: {e}", exc_info=True
                )
                continue

        LOGGER.info(
            f"temp-mail.org: Successfully fetched {len(all_provider_messages)} messages"
        )

    except requests.RequestException as e:
        LOGGER.error(f"temp-mail.org: Network error: {e}")
        raise ProviderNetworkError(f"temp-mail.org: Network error: {e}") from e
    except Exception as e:
        LOGGER.error(f"temp-mail.org: Unexpected error: {e}", exc_info=True)
        raise ProviderAPIError(f"temp-mail.org: Unexpected error: {e}") from e

    return all_provider_messages


def _process_message_data(msg_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Process individual message data."""
    try:
        mail_id = msg_data.get("_id") or msg_data.get("id")
        if not mail_id:
            content_hash = hashlib.md5(
                json.dumps(msg_data, sort_keys=True).encode("utf-8")
            ).hexdigest()[:12]
            mail_id = f"msg_{content_hash}"

        mail_from = msg_data.get("from", "")
        mail_to = msg_data.get("to", "")
        mail_subject = msg_data.get("subject", "")
        mail_date = msg_data.get("date") or msg_data.get("timestamp")
        mail_body = msg_data.get("body") or msg_data.get("text", "")
        mail_html = msg_data.get("html")

        sender_email = None
        if mail_from:
            name, addr = parseaddr(mail_from)
            sender_email = addr if addr else mail_from

        formatted_message = {
            "id": str(mail_id),
            "from": sender_email,
            "to": mail_to if mail_to else None,
            "subject": mail_subject if mail_subject else "(No Subject)",
            "date": _format_timestamp_iso(mail_date),
            "body": mail_body.strip() if mail_body else "",
            "html": mail_html,
            "raw": msg_data,
        }

        return formatted_message

    except Exception as e:
        LOGGER.error(
            f"temp-mail.org: Error processing message data: {e}", exc_info=True
        )
        return None
