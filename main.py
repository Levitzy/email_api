from __future__ import annotations

import json
import logging
import os
import random
import string
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union, Coroutine
import time
from email.utils import parseaddr

import requests
import uvicorn
from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, EmailStr, Field
import asyncio

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="[%X]",
)
LOGGER = logging.getLogger("temp-mail-api")

CONFIG_DIR = Path.home() / ".config" / "tempmail-api"  # Still used for history
HISTORY_FILE = CONFIG_DIR / "history.json"

DEFAULT_MAX_HISTORY_ENTRIES = 100
DEFAULT_SAVE_MESSAGES = True


def ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def save_message_to_history(
    provider: str, address: str, message_data: Dict[str, Any]
) -> None:
    if not DEFAULT_SAVE_MESSAGES:  # Use hardcoded default
        return
    ensure_config_dir()
    try:
        history: List[Dict[str, Any]] = []
        if HISTORY_FILE.exists():
            with open(HISTORY_FILE, "r") as f:
                try:
                    history = json.load(f)
                    if not isinstance(history, list):
                        history = []
                except json.JSONDecodeError:
                    history = []

        entry = {
            "provider": provider,
            "address": address,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": message_data,
        }
        history.append(entry)

        max_entries = DEFAULT_MAX_HISTORY_ENTRIES  # Use hardcoded default
        if len(history) > max_entries:
            history = history[-max_entries:]

        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        LOGGER.warning(f"Failed to save message to history: {e}")


def _rand_string(n: int = 10) -> str:
    return "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(n)
    )


def _format_timestamp_iso(
    timestamp_input: Optional[Union[str, int, float]],
) -> Optional[str]:
    if timestamp_input is None:
        return None

    dt_obj = None

    if isinstance(timestamp_input, (int, float)):
        if timestamp_input > 2_000_000_000_000:
            timestamp_input /= 1000
        try:
            dt_obj = datetime.fromtimestamp(timestamp_input, tz=timezone.utc)
        except Exception as e:
            LOGGER.warning(
                f"Could not parse numeric timestamp: {timestamp_input} - {e}"
            )
            return str(timestamp_input)

    elif isinstance(timestamp_input, str):
        formats_to_try = (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        )
        for fmt in formats_to_try:
            try:
                dt_obj = datetime.strptime(timestamp_input, fmt)
                break
            except ValueError:
                continue

        if dt_obj is None:
            try:
                from dateutil import parser

                dt_obj = parser.parse(timestamp_input)
            except ImportError:
                LOGGER.warning(
                    f"dateutil not installed, could not parse timestamp string: {timestamp_input}"
                )
                return timestamp_input
            except Exception as e_du:
                LOGGER.warning(
                    f"Could not parse timestamp string with dateutil: {timestamp_input} - {e_du}"
                )
                return timestamp_input
    else:
        LOGGER.warning(
            f"Unsupported timestamp type: {type(timestamp_input)}, value: {timestamp_input}"
        )
        return str(timestamp_input)

    if dt_obj:
        if dt_obj.tzinfo is None or dt_obj.tzinfo.utcoffset(dt_obj) is None:
            dt_obj = dt_obj.replace(tzinfo=timezone.utc)
        else:
            dt_obj = dt_obj.astimezone(timezone.utc)
        return dt_obj.isoformat()

    return str(timestamp_input)


def make_requests_session(timeout: int = 15) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": "TempMailAPI/1.0 (FastAPI)"})
    return session


class ProviderError(HTTPException):
    def __init__(self, status_code: int, detail: str):
        super().__init__(status_code=status_code, detail=detail)


class NetworkError(ProviderError):
    def __init__(
        self, detail: str = "A network error occurred with the email provider."
    ):
        super().__init__(status_code=503, detail=detail)


class APIError(ProviderError):
    def __init__(
        self,
        detail: str = "The email provider's API returned an error or unexpected response.",
    ):
        super().__init__(status_code=502, detail=detail)


active_api_sessions: Dict[str, Dict[str, Any]] = {}

GM_API_URL = "https://api.guerrillamail.com/ajax.php"
GM_USER_AGENT = "Mozilla/5.0 (TempMailAPI/1.0)"


async def setup_guerrillamail() -> Tuple[str, str, Dict[str, Any]]:
    sess = make_requests_session()
    sess.headers.update({"User-Agent": GM_USER_AGENT})
    try:
        params = {"f": "get_email_address", "ip": "127.0.0.1", "agent": GM_USER_AGENT}
        await asyncio.sleep(0.2)
        res = await asyncio.to_thread(sess.get, GM_API_URL, params=params, timeout=15)
        res.raise_for_status()
        init_data = res.json()
        if not init_data.get("sid_token") or not init_data.get("email_addr"):
            raise APIError(
                "GuerrillaMail: Failed to initialize session (missing sid_token or email_addr)."
            )
        sid_token = init_data["sid_token"]
        address = init_data["email_addr"]
        provider_data = {
            "sid_token": sid_token,
            "requests_session_headers": dict(sess.headers),
        }
        return f"biar-{uuid.uuid4()}", address, provider_data
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            raise APIError(
                f"GuerrillaMail: Too Many Requests. Please try again later. Details: {e}"
            )
        raise NetworkError(f"GuerrillaMail: HTTP error during setup: {e}") from e
    except requests.RequestException as e:
        raise NetworkError(f"GuerrillaMail: Network error during setup: {e}") from e
    except (json.JSONDecodeError, KeyError) as e:
        raise APIError(
            f"GuerrillaMail: API error during setup (invalid response): {e}"
        ) from e


async def fetch_guerrillamail_messages(
    provider_data: Dict[str, Any], seen_ids: Set[str]
) -> List[Dict[str, Any]]:
    sess = make_requests_session()
    if "requests_session_headers" in provider_data:
        sess.headers.update(provider_data["requests_session_headers"])

    sid_token = provider_data.get("sid_token")
    if not sid_token:
        raise APIError("GuerrillaMail: Missing sid_token in session data.")

    new_messages = []
    try:
        params = {"f": "check_email", "sid_token": sid_token, "seq": 0}
        await asyncio.sleep(0.2)
        res = await asyncio.to_thread(sess.get, GM_API_URL, params=params, timeout=15)
        res.raise_for_status()
        box_data = res.json()

        for m_summary in box_data.get("list", []):
            mail_id = str(m_summary["mail_id"])
            if mail_id in seen_ids:
                continue

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
            new_messages.append(formatted_message)

    except requests.RequestException as e:
        LOGGER.warning(f"GuerrillaMail: Network error during polling: {e}")
    except (json.JSONDecodeError, KeyError) as e:
        LOGGER.warning(f"GuerrillaMail: API error during polling: {e}")
    return new_messages


async def _setup_mail_tm_gw_like(
    base_url: str, provider_name: str
) -> Tuple[str, str, Dict[str, Any]]:
    sess = make_requests_session()
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
            raise APIError(f"{provider_name}: No domains available.")
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
            raise APIError(f"{provider_name}: Failed to get authentication token.")

        provider_data = {
            "base_url": base_url,
            "auth_token": auth_token,
            "address": address,
            "password": password,
        }
        return f"biar-{uuid.uuid4()}", address, provider_data
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            raise APIError(
                f"{provider_name}: Too Many Requests from provider API. Please try again later. Details: {e}"
            )
        raise NetworkError(f"{provider_name}: HTTP error during setup: {e}") from e
    except requests.RequestException as e:
        raise NetworkError(f"{provider_name}: Network error during setup: {e}") from e
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        raise APIError(f"{provider_name}: API error during setup: {e}") from e


async def _fetch_mail_tm_gw_like_messages(
    provider_data: Dict[str, Any], seen_ids: Set[str], provider_name: str
) -> List[Dict[str, Any]]:
    sess = make_requests_session()
    base_url = provider_data["base_url"]
    auth_token = provider_data["auth_token"]
    address = provider_data["address"]
    password = provider_data["password"]

    headers = {"Authorization": f"Bearer {auth_token}"}
    new_messages = []

    try:
        await asyncio.sleep(0.5)
        inbox_res = await asyncio.to_thread(
            sess.get, f"{base_url}/messages", headers=headers, timeout=15
        )

        if inbox_res.status_code == 401:
            LOGGER.info(
                f"{provider_name}: Token expired or unauthorized, attempting re-authentication."
            )
            try:
                token_payload = {"address": address, "password": password}
                await asyncio.sleep(1)
                token_res = await asyncio.to_thread(
                    sess.post, f"{base_url}/token", json=token_payload, timeout=15
                )
                token_res.raise_for_status()
                new_auth_token = token_res.json().get("token")
                if not new_auth_token:
                    raise APIError(
                        f"{provider_name}: Re-authentication failed to retrieve new token."
                    )

                provider_data["auth_token"] = new_auth_token
                if (
                    "api_session_id" in provider_data
                    and provider_data["api_session_id"] in active_api_sessions
                ):
                    active_api_sessions[provider_data["api_session_id"]][
                        "provider_specific_data"
                    ]["auth_token"] = new_auth_token
                headers = {"Authorization": f"Bearer {new_auth_token}"}

                await asyncio.sleep(0.5)
                inbox_res = await asyncio.to_thread(
                    sess.get, f"{base_url}/messages", headers=headers, timeout=15
                )
            except requests.exceptions.HTTPError as reauth_e:
                if reauth_e.response.status_code == 429:
                    raise APIError(
                        f"{provider_name}: Too Many Requests during re-authentication. Session may be invalid. Details: {reauth_e}"
                    )
                LOGGER.error(f"{provider_name}: Re-authentication failed: {reauth_e}")
                raise APIError(
                    f"{provider_name}: Re-authentication failed. Session may be invalid."
                ) from reauth_e
            except Exception as reauth_e:
                LOGGER.error(f"{provider_name}: Re-authentication failed: {reauth_e}")
                raise APIError(
                    f"{provider_name}: Re-authentication failed. Session may be invalid."
                ) from reauth_e

        inbox_res.raise_for_status()
        inbox_data = inbox_res.json()

        for m_summary in inbox_data.get("hydra:member", []):
            msg_id = str(m_summary["id"])
            if msg_id in seen_ids:
                continue

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
                raw_address = from_details_dict.get("address")
                sender_name = from_details_dict.get("name", "")
                if raw_address:
                    full_from_string = (
                        f"{sender_name} <{raw_address}>".strip()
                        if sender_name
                        else raw_address
                    )
                    name, addr = parseaddr(full_from_string)
                    sender_email = addr if addr else raw_address
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
            new_messages.append(formatted_message)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            raise APIError(
                f"{provider_name}: Too Many Requests while fetching messages. Please try again later. Details: {e}"
            )
        LOGGER.warning(f"{provider_name}: HTTP error during polling: {e}")
    except requests.RequestException as e:
        LOGGER.warning(f"{provider_name}: Network error during polling: {e}")
    except (json.JSONDecodeError, KeyError) as e:
        LOGGER.warning(f"{provider_name}: API error during polling: {e}")
    return new_messages


async def setup_mail_tm() -> Tuple[str, str, Dict[str, Any]]:
    return await _setup_mail_tm_gw_like("https://api.mail.tm", "mail.tm")


async def fetch_mail_tm_messages(
    provider_data: Dict[str, Any], seen_ids: Set[str]
) -> List[Dict[str, Any]]:
    return await _fetch_mail_tm_gw_like_messages(provider_data, seen_ids, "mail.tm")


async def setup_mail_gw() -> Tuple[str, str, Dict[str, Any]]:
    return await _setup_mail_tm_gw_like("https://api.mail.gw", "mail.gw")


async def fetch_mail_gw_messages(
    provider_data: Dict[str, Any], seen_ids: Set[str]
) -> List[Dict[str, Any]]:
    return await _fetch_mail_tm_gw_like_messages(provider_data, seen_ids, "mail.gw")


TEMPMAIL_LOL_BASE_URL = "https://api.tempmail.lol"


async def setup_tempmail_lol(rush: bool = False) -> Tuple[str, str, Dict[str, Any]]:
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
            raise APIError("tempmail.lol: Failed to get address or token.")
        provider_data = {"token": token, "base_url": TEMPMAIL_LOL_BASE_URL}
        return f"biar-{uuid.uuid4()}", address, provider_data
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            raise APIError(
                f"tempmail.lol: Too Many Requests. Please try again later. Details: {e}"
            )
        raise NetworkError(f"tempmail.lol: HTTP error during setup: {e}") from e
    except requests.RequestException as e:
        raise NetworkError(f"tempmail.lol: Network error during setup: {e}") from e
    except (json.JSONDecodeError, KeyError) as e:
        raise APIError(f"tempmail.lol: API error during setup: {e}") from e


async def fetch_tempmail_lol_messages(
    provider_data: Dict[str, Any], seen_ids: Set[str]
) -> List[Dict[str, Any]]:
    sess = make_requests_session()
    token = provider_data["token"]
    base_url = provider_data["base_url"]
    new_messages = []
    try:
        await asyncio.sleep(0.2)
        res = await asyncio.to_thread(sess.get, f"{base_url}/auth/{token}", timeout=15)
        res.raise_for_status()
        data = res.json()

        for m_content in data.get("email", []):
            date_val = m_content.get("date")
            msg_pseudo_id = f"{m_content.get('from')}_{m_content.get('subject')}_{str(date_val)}_{len(m_content.get('body',''))}"

            if msg_pseudo_id in seen_ids:
                continue

            sender_email = None
            raw_from_field = m_content.get("from")
            if raw_from_field:
                name, addr = parseaddr(raw_from_field)
                sender_email = addr if addr else raw_from_field

            formatted_message = {
                "id": msg_pseudo_id,
                "from": sender_email,
                "subject": m_content.get("subject"),
                "date": _format_timestamp_iso(date_val),
                "body": m_content.get("body", "").strip(),
                "html": m_content.get("html"),
                "raw": m_content,
            }
            new_messages.append(formatted_message)

    except requests.RequestException as e:
        LOGGER.warning(f"tempmail.lol: Network error during polling: {e}")
    except (json.JSONDecodeError, KeyError) as e:
        LOGGER.warning(f"tempmail.lol: API error during polling: {e}")
    return new_messages


DROPMAIL_ME_BASE_URL = "https://dropmail.me/api/graphql"


async def setup_dropmail_me() -> Tuple[str, str, Dict[str, Any]]:
    sess = make_requests_session()
    client_session_token = _rand_string(16)

    query = """
    mutation {
      introduceSession {
        id
        expiresAt
        addresses {
          address
        }
      }
    }
    """
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
            raise APIError(
                f"dropmail.me: 'introduceSession' data not found in response: {response_data.get('errors')}"
            )

        session_id = session_data.get("id")
        addresses = session_data.get("addresses", [])

        if not session_id or not addresses or not addresses[0].get("address"):
            raise APIError("dropmail.me: Failed to get valid session ID or address.")

        address = addresses[0]["address"]
        expires_at_str = session_data.get("expiresAt")

        provider_data = {
            "session_id": session_id,
            "client_session_token": client_session_token,
            "base_url": DROPMAIL_ME_BASE_URL,
            "expires_at": _format_timestamp_iso(expires_at_str),
        }
        return f"biar-{uuid.uuid4()}", address, provider_data
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            raise APIError(
                f"dropmail.me: Too Many Requests. Please try again later. Details: {e}"
            )
        raise NetworkError(f"dropmail.me: HTTP error during setup: {e}") from e
    except requests.RequestException as e:
        raise NetworkError(f"dropmail.me: Network error during setup: {e}") from e
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
        raise APIError(f"dropmail.me: API error during setup: {e}") from e


async def fetch_dropmail_me_messages(
    provider_data: Dict[str, Any], seen_ids: Set[str]
) -> List[Dict[str, Any]]:
    sess = make_requests_session()
    dropmail_session_id = provider_data["session_id"]
    client_session_token = provider_data["client_session_token"]
    base_url = provider_data["base_url"]

    query = """
    query($id: ID!){
      session(id: $id){
        mails{
          id
          fromAddr
          toAddr
          headerSubject
          text
          html
          receivedAt
          downloadUrl
        }
      }
    }
    """
    variables = {"id": dropmail_session_id}
    new_messages = []

    try:
        expires_at_str = provider_data.get("expires_at")
        if expires_at_str:
            expires_dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expires_dt:
                LOGGER.warning(
                    f"dropmail.me: Session {dropmail_session_id} has expired."
                )
                raise APIError(f"dropmail.me: Session has expired at {expires_at_str}.")

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
        if (
            session_query_data is None
        ):  # If session is null, it likely expired on the server
            LOGGER.warning(
                f"dropmail.me: Session data not found for ID {dropmail_session_id}. It might have expired."
            )
            # Raise APIError so get_new_messages can handle session removal
            raise APIError(
                f"dropmail.me: Session {dropmail_session_id} not found or expired on server."
            )

        mails = session_query_data.get("mails", [])
        for m_content in mails:
            msg_id = str(m_content["id"])
            if msg_id in seen_ids:
                continue

            sender_email = None
            raw_from_field = m_content.get("fromAddr")
            if raw_from_field:
                name, addr = parseaddr(raw_from_field)
                sender_email = addr if addr else raw_from_field

            formatted_message = {
                "id": msg_id,
                "from": sender_email,
                "to": m_content.get("toAddr"),
                "subject": m_content.get("headerSubject"),
                "date": _format_timestamp_iso(m_content.get("receivedAt")),
                "body": m_content.get("text", "").strip(),
                "html": m_content.get("html"),
                "downloadUrl": m_content.get("downloadUrl"),
                "raw": m_content,
            }
            new_messages.append(formatted_message)

    except requests.RequestException as e:
        LOGGER.warning(f"dropmail.me: Network error during polling: {e}")
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        LOGGER.warning(f"dropmail.me: API error during polling: {e}")
    return new_messages


PROVIDER_SETUP_FUNCTIONS: Dict[
    str, Callable[..., Coroutine[Any, Any, Tuple[str, str, Dict[str, Any]]]]
] = {
    "guerrillamail": setup_guerrillamail,
    "mail.tm": setup_mail_tm,
    "mail.gw": setup_mail_gw,
    "tempmail.lol": setup_tempmail_lol,
    "dropmail.me": setup_dropmail_me,
}

PROVIDER_FETCH_FUNCTIONS: Dict[
    str, Callable[[Dict[str, Any], Set[str]], Coroutine[Any, Any, List[Dict[str, Any]]]]
] = {
    "guerrillamail": fetch_guerrillamail_messages,
    "mail.tm": fetch_mail_tm_messages,
    "mail.gw": fetch_mail_gw_messages,
    "tempmail.lol": fetch_tempmail_lol_messages,
    "dropmail.me": fetch_dropmail_me_messages,
}

app = FastAPI(
    title="Temp Mail API",
    description="API for generating temporary email addresses and checking their inboxes. Serves custom HTML for root and /docs.",
    version="1.1.0",
    docs_url=None,
    redoc_url=None,
)


class Message(BaseModel):
    id: str
    from_address: Optional[EmailStr] = Field(None, alias="from")
    to_address: Optional[EmailStr] = Field(None, alias="to")
    subject: Optional[str] = None
    date: Optional[str] = None
    body: Optional[str] = None
    html: Optional[Union[str, List[str]]] = None
    raw: Dict[str, Any]

    class Config:
        populate_by_name = True


class EmailSessionResponse(BaseModel):
    api_session_id: str = Field(..., description="Unique ID for this API session.")
    email_address: EmailStr = Field(
        ..., description="The generated temporary email address."
    )
    provider: str = Field(..., description="The email provider used for this session.")
    created_at: str = Field(
        ..., description="Timestamp (ISO format) when the session was created."
    )
    expires_at: Optional[str] = Field(
        None,
        description="Timestamp (ISO format) when the session/email might expire, if known.",
    )


class HistoryEntry(BaseModel):
    provider: str
    address: EmailStr
    timestamp: str
    message: Message


@app.get("/", response_class=HTMLResponse)
async def get_index_page():
    index_path = Path(__file__).parent / "index.html"
    if not index_path.is_file():
        LOGGER.error(f"index.html not found at {index_path}")
        raise HTTPException(
            status_code=500, detail="Index page HTML file not found on server."
        )
    return FileResponse(index_path)


@app.get("/docs", response_class=HTMLResponse)
async def get_docs_page():
    docs_path = Path(__file__).parent / "docs.html"
    if not docs_path.is_file():
        LOGGER.error(f"docs.html not found at {docs_path}")
        raise HTTPException(
            status_code=500, detail="Documentation page HTML file not found on server."
        )
    return FileResponse(docs_path)


@app.get(
    "/providers", summary="List available email providers", response_model=List[str]
)
async def list_providers() -> List[str]:
    return list(PROVIDER_SETUP_FUNCTIONS.keys())


@app.post(
    "/sessions",
    response_model=EmailSessionResponse,
    status_code=201,
    summary="Generate a new temporary email address (create session)",
)
async def create_email_session(
    provider_name: str = Query(
        ...,
        description=f"Name of the email provider. Available: {', '.join(PROVIDER_SETUP_FUNCTIONS.keys())}.",
    ),
    rush_mode: bool = Query(
        False,
        description="For tempmail.lol: Use rush mode for faster address generation.",
    ),
) -> EmailSessionResponse:
    if provider_name not in PROVIDER_SETUP_FUNCTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Provider '{provider_name}' not found or not supported. Available: {list(PROVIDER_SETUP_FUNCTIONS.keys())}",
        )

    setup_func = PROVIDER_SETUP_FUNCTIONS[provider_name]

    try:
        if provider_name == "tempmail.lol":
            api_session_id, email_address, provider_specific_data = await setup_func(
                rush=rush_mode
            )
        else:
            api_session_id, email_address, provider_specific_data = await setup_func()
    except (NetworkError, APIError) as e:
        raise e
    except Exception as e:
        LOGGER.error(
            f"Unexpected error creating session for {provider_name}: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create email session with {provider_name}: {str(e)}",
        )

    created_at_dt = datetime.now(timezone.utc)
    session_data = {
        "api_session_id": api_session_id,
        "provider_name": provider_name,
        "email_address": email_address,
        "provider_specific_data": provider_specific_data,
        "seen_message_ids": set(),
        "created_at": created_at_dt,
        "last_accessed_at": created_at_dt,
    }
    active_api_sessions[api_session_id] = session_data

    expires_at = provider_specific_data.get("expires_at")

    return EmailSessionResponse(
        api_session_id=api_session_id,
        email_address=email_address,
        provider=provider_name,
        created_at=created_at_dt.isoformat(),
        expires_at=expires_at,
    )


@app.api_route(
    "/gen",
    methods=["GET", "POST"],
    response_model=EmailSessionResponse,
    status_code=201,
    summary="Generate a new temporary email (supports random/default provider)",
    description=(
        "Creates a new temporary email session. "
        "Supports selection of a specific provider or a random provider. "
        "Parameters are accepted as query parameters for both GET and POST methods."
    ),
)
async def generate_email_address(
    provider: Optional[str] = Query(
        None,
        description=(
            "Specify the email provider name (e.g., 'mail.tm'), "
            f"'random' for a random selection, or omit for a random provider. "
            f"Available: {', '.join(PROVIDER_SETUP_FUNCTIONS.keys())}."
        ),
    ),
    rush_mode: bool = Query(
        False,
        description="For tempmail.lol provider: Use rush mode for potentially faster address generation.",
    ),
) -> EmailSessionResponse:
    provider_to_use: str
    available_providers = list(PROVIDER_SETUP_FUNCTIONS.keys())

    if not available_providers:
        LOGGER.error(
            "CRITICAL: No email providers configured in PROVIDER_SETUP_FUNCTIONS."
        )
        raise HTTPException(
            status_code=500,
            detail="Internal server error: No email providers available.",
        )

    if provider and provider.lower() == "random":
        provider_to_use = random.choice(available_providers)
        LOGGER.info(f"Random provider selected for /gen: {provider_to_use}")
    elif provider and provider in PROVIDER_SETUP_FUNCTIONS:
        provider_to_use = provider
        LOGGER.info(f"Specific provider selected for /gen: {provider_to_use}")
    elif not provider:  # If no provider is specified, pick a random one
        provider_to_use = random.choice(available_providers)
        LOGGER.info(
            f"No provider specified for /gen. Choosing a random provider: {provider_to_use}"
        )
    else:  # Provider specified but not valid
        raise HTTPException(
            status_code=400,
            detail=(
                f"Provider '{provider}' not supported. "
                f"Available options: {', '.join(available_providers)}, 'random', or omit for random."
            ),
        )

    setup_func = PROVIDER_SETUP_FUNCTIONS[provider_to_use]

    try:
        if provider_to_use == "tempmail.lol":
            api_session_id, email_address, provider_specific_data = await setup_func(
                rush=rush_mode
            )
        else:
            api_session_id, email_address, provider_specific_data = await setup_func()
    except (NetworkError, APIError) as e:
        raise e
    except Exception as e:
        LOGGER.error(
            f"Unexpected error creating session for {provider_to_use} via /gen: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create email session with {provider_to_use}: {str(e)}",
        )

    created_at_dt = datetime.now(timezone.utc)
    session_data = {
        "api_session_id": api_session_id,
        "provider_name": provider_to_use,
        "email_address": email_address,
        "provider_specific_data": provider_specific_data,
        "seen_message_ids": set(),
        "created_at": created_at_dt,
        "last_accessed_at": created_at_dt,
    }
    active_api_sessions[api_session_id] = session_data

    expires_at = provider_specific_data.get("expires_at")

    return EmailSessionResponse(
        api_session_id=api_session_id,
        email_address=email_address,
        provider=provider_to_use,
        created_at=created_at_dt.isoformat(),
        expires_at=expires_at,
    )


@app.get(
    "/sessions/{api_session_id}/messages",
    response_model=List[Message],
    summary="Check inbox and fetch new messages for a session",
)
async def get_new_messages(api_session_id: str) -> List[Message]:
    if api_session_id not in active_api_sessions:
        raise HTTPException(status_code=404, detail="API session not found or expired.")

    session_data = active_api_sessions[api_session_id]
    session_data["last_accessed_at"] = datetime.now(timezone.utc)

    provider_name = session_data["provider_name"]
    fetch_func = PROVIDER_FETCH_FUNCTIONS[provider_name]
    provider_specific_data = session_data["provider_specific_data"]
    provider_specific_data["api_session_id"] = (
        api_session_id  # Pass current API session ID
    )

    seen_ids_for_this_session = session_data["seen_message_ids"]

    try:
        raw_messages = await fetch_func(
            provider_specific_data, seen_ids_for_this_session
        )
    except APIError as e:  # Catch APIErrors specifically for session expiry
        if (
            "Session has expired" in str(e.detail)
            or "Session data not found" in str(e.detail)
            or "not found or expired on server" in str(e.detail)
        ):  # Added for dropmail.me
            LOGGER.warning(
                f"API session {api_session_id} ({provider_name}) is invalid/expired: {e.detail}. Removing."
            )
            if api_session_id in active_api_sessions:
                del active_api_sessions[api_session_id]
            raise HTTPException(
                status_code=404,
                detail=f"API session {api_session_id} no longer valid or expired.",
            ) from e
        raise e
    except NetworkError as e:
        raise e
    except Exception as e:
        LOGGER.error(
            f"Unexpected error fetching messages for session {api_session_id} ({provider_name}): {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch messages: {str(e)}"
        )

    processed_messages: List[Message] = []
    for raw_msg_item in raw_messages:
        if not isinstance(raw_msg_item, dict):
            LOGGER.warning(f"Skipping non-dict message item: {raw_msg_item}")
            continue

        msg_id = str(raw_msg_item.get("id", _rand_string()))

        raw_msg_for_model = raw_msg_item.copy()
        if "id" in raw_msg_for_model:
            del raw_msg_for_model["id"]

        try:
            msg_model = Message(id=msg_id, **raw_msg_for_model)
            processed_messages.append(msg_model)
            seen_ids_for_this_session.add(msg_id)

            if DEFAULT_SAVE_MESSAGES:
                history_message_data = {
                    "id": msg_model.id,
                    "from": msg_model.from_address,
                    "to": msg_model.to_address,
                    "subject": msg_model.subject,
                    "date": msg_model.date,
                    "body": msg_model.body,
                    "html": msg_model.html,
                    "raw": msg_model.raw,
                }
                save_message_to_history(
                    provider_name, session_data["email_address"], history_message_data
                )
        except Exception as model_exc:
            LOGGER.error(
                f"Error creating Message model for ID {msg_id} from provider {provider_name}: {model_exc}. Data: {raw_msg_for_model}",
                exc_info=True,
            )
            continue

    return processed_messages


@app.delete(
    "/sessions/{api_session_id}",
    status_code=204,
    summary="Delete an active email session",
)
async def delete_email_session(api_session_id: str):
    if api_session_id in active_api_sessions:
        del active_api_sessions[api_session_id]
        return
    raise HTTPException(status_code=404, detail="API session not found.")


@app.get(
    "/history",
    response_model=List[HistoryEntry],
    summary="View saved message history (paginated)",
)
async def view_message_history(
    page: int = Query(1, ge=1, description="Page number for pagination."),
    page_size: int = Query(20, ge=1, le=100, description="Number of entries per page."),
) -> List[HistoryEntry]:
    if not HISTORY_FILE.exists():
        return []
    try:
        with open(HISTORY_FILE, "r") as f:
            history_data = json.load(f)
        if not isinstance(history_data, list):
            return []

        history_data.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        start_index = (page - 1) * page_size
        end_index = start_index + page_size
        paginated_history = history_data[start_index:end_index]

        result: List[HistoryEntry] = []
        for entry in paginated_history:
            msg_data_from_history = entry.get("message", {})
            msg_data_for_model = msg_data_from_history.copy()
            current_msg_id = str(msg_data_for_model.pop("id", _rand_string()))

            try:
                adapted_message = Message(id=current_msg_id, **msg_data_for_model)
                hist_entry = HistoryEntry(
                    provider=entry.get("provider", "unknown"),
                    address=entry.get("address", "unknown@example.com"),
                    timestamp=entry.get("timestamp", datetime.min.isoformat()),
                    message=adapted_message,
                )
                result.append(hist_entry)
            except Exception as e_model:
                LOGGER.error(
                    f"Error creating Message model from history item {current_msg_id}: {e_model}. Data: {msg_data_for_model}"
                )
                continue
        return result
    except Exception as e:
        LOGGER.error(f"Error reading history: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error retrieving message history.")


@app.post(
    "/history/export",
    summary="Export message history to a file (server-side)",
    response_model=Dict[str, str],
)
async def export_history_to_file(
    output_filename: str = Query(
        "email_export.json", description="Filename for the export."
    )
) -> Dict[str, str]:
    if not HISTORY_FILE.exists():
        raise HTTPException(status_code=404, detail="No message history to export.")
    try:
        with open(HISTORY_FILE, "r") as f_in:
            history_content = json.load(f_in)

        ensure_config_dir()
        export_path = CONFIG_DIR / output_filename
        with open(export_path, "w") as f_out:
            json.dump(history_content, f_out, indent=2)

        return {"message": f"Successfully exported history to {export_path.resolve()}"}
    except Exception as e:
        LOGGER.error(f"Error exporting history: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Error exporting history: {str(e)}"
        )


@app.delete(
    "/history", summary="Clear all saved message history", response_model=Dict[str, str]
)
async def clear_all_history() -> Dict[str, str]:
    if not HISTORY_FILE.exists():
        return {"message": "No message history to clear."}
    try:
        os.remove(HISTORY_FILE)
        return {"message": "Message history cleared successfully."}
    except Exception as e:
        LOGGER.error(f"Error clearing history: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error clearing history: {str(e)}")


if __name__ == "__main__":
    current_dir = Path(__file__).parent
    if not (current_dir / "index.html").is_file():
        print(
            f"ERROR: index.html not found in {current_dir}. Please create it using the provided content."
        )
        exit(1)
    if not (current_dir / "docs.html").is_file():
        print(
            f"ERROR: docs.html not found in {current_dir}. Please create it using the provided content."
        )
        exit(1)

    uvicorn.run(app, host="0.0.0.0", port=8000)
