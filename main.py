from __future__ import annotations

import json
import logging
import os
import platform  # Not strictly needed for API, but was in original
import random
import string
import sys  # Not strictly needed for API, but was in original
import time  # Not strictly needed for API, but was in original
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import requests
from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
import asyncio  # For asyncio.to_thread

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="[%X]",
)
LOGGER = logging.getLogger("temp-mail-api")


# --- Configuration and History File Paths ---
CONFIG_DIR = Path.home() / ".config" / "tempmail-api"
CONFIG_FILE = CONFIG_DIR / "config.json"
HISTORY_FILE = CONFIG_DIR / "history.json"


# --- Configuration Management ---
def ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> Dict[str, Any]:
    ensure_config_dir()
    default_config = {
        "default_provider": "mail.tm",
        "max_history_entries": 100,
        "save_messages": True,
    }
    if not CONFIG_FILE.exists():
        return default_config
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            for key, value in default_config.items():
                if key not in config:
                    config[key] = value
            return config
    except Exception as e:
        LOGGER.warning(f"Failed to load config: {e}. Using defaults.")
        return default_config


def save_config(config: Dict[str, Any]) -> None:
    ensure_config_dir()
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        LOGGER.error(f"Failed to save config: {e}")


# --- History Management ---
def save_message_to_history(
    provider: str, address: str, message_data: Dict[str, Any]
) -> None:
    config = load_config()
    if not config.get("save_messages", True):
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

        max_entries = config.get("max_history_entries", 100)
        if len(history) > max_entries:
            history = history[-max_entries:]

        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        LOGGER.warning(f"Failed to save message to history: {e}")


# --- Utility Functions ---
def _rand_string(n: int = 10) -> str:
    return "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(n)
    )


def _format_timestamp_iso(timestamp_str: Optional[str]) -> Optional[str]:
    if not timestamp_str:
        return None
    try:
        formats_to_try = (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        )
        dt_obj = None
        for fmt in formats_to_try:
            try:
                dt_obj = datetime.strptime(timestamp_str, fmt)
                break
            except ValueError:
                continue

        if dt_obj is None:
            try:
                from dateutil import parser

                dt_obj = parser.parse(timestamp_str)
            except ImportError:
                LOGGER.warning(
                    f"dateutil not installed, could not parse timestamp: {timestamp_str}"
                )
                return timestamp_str
            except Exception:
                LOGGER.warning(
                    f"Could not parse timestamp: {timestamp_str} with dateutil"
                )
                return timestamp_str

        if dt_obj.tzinfo is None or dt_obj.tzinfo.utcoffset(dt_obj) is None:
            dt_obj = dt_obj.replace(tzinfo=timezone.utc)

        return dt_obj.isoformat()

    except Exception as e:
        LOGGER.warning(f"Error formatting timestamp '{timestamp_str}': {e}")
        return timestamp_str


# --- HTTP Session ---
def make_requests_session(timeout: int = 15) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": "TempMailAPI/1.0 (FastAPI)"})
    return session


# --- Custom Exceptions ---
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


# --- Global State for Active Email Sessions ---
active_api_sessions: Dict[str, Dict[str, Any]] = {}


# --- Provider Specific Logic (Refactored for API) ---

# GuerrillaMail
GM_API_URL = "https://api.guerrillamail.com/ajax.php"
GM_USER_AGENT = "Mozilla/5.0 (TempMailAPI/1.0)"


async def setup_guerrillamail() -> Tuple[str, str, Dict[str, Any]]:
    sess = make_requests_session()
    sess.headers.update({"User-Agent": GM_USER_AGENT})
    try:
        params = {"f": "get_email_address", "ip": "127.0.0.1", "agent": GM_USER_AGENT}
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
        return str(uuid.uuid4()), address, provider_data
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
            full_email_res = await asyncio.to_thread(
                sess.get, GM_API_URL, params=fetch_params, timeout=15
            )
            full_email_res.raise_for_status()
            email_content = full_email_res.json()

            formatted_message = {
                "id": mail_id,
                "from": email_content.get("mail_from"),
                "subject": email_content.get("mail_subject"),
                "date": _format_timestamp_iso(email_content.get("mail_date")),
                "body": email_content.get("mail_body", "").strip(),
                "raw": email_content,
            }
            new_messages.append(formatted_message)
            # seen_ids.add(mail_id) # This will be done in the calling endpoint logic

    except requests.RequestException as e:
        LOGGER.warning(f"GuerrillaMail: Network error during polling: {e}")
    except (json.JSONDecodeError, KeyError) as e:
        LOGGER.warning(f"GuerrillaMail: API error during polling: {e}")
    return new_messages


# Mail.tm and Mail.gw
async def _setup_mail_tm_gw_like(
    base_url: str, provider_name: str
) -> Tuple[str, str, Dict[str, Any]]:
    sess = make_requests_session()
    try:
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
        account_res = await asyncio.to_thread(
            sess.post, f"{base_url}/accounts", json=account_payload, timeout=15
        )
        account_res.raise_for_status()

        token_payload = {"address": address, "password": password}
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
        return str(uuid.uuid4()), address, provider_data

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
        inbox_res = await asyncio.to_thread(
            sess.get, f"{base_url}/messages", headers=headers, timeout=15
        )

        if inbox_res.status_code == 401:
            LOGGER.info(
                f"{provider_name}: Token expired or unauthorized, attempting re-authentication."
            )
            try:
                token_payload = {"address": address, "password": password}
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
                # Update in global state if this function is called directly by endpoint that has access
                if (
                    "api_session_id" in provider_data
                    and provider_data["api_session_id"] in active_api_sessions
                ):
                    active_api_sessions[provider_data["api_session_id"]][
                        "provider_specific_data"
                    ]["auth_token"] = new_auth_token
                headers = {"Authorization": f"Bearer {new_auth_token}"}

                inbox_res = await asyncio.to_thread(
                    sess.get, f"{base_url}/messages", headers=headers, timeout=15
                )
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

            full_email_res = await asyncio.to_thread(
                sess.get, f"{base_url}/messages/{msg_id}", headers=headers, timeout=15
            )
            full_email_res.raise_for_status()
            email_content = full_email_res.json()

            from_details = email_content.get("from", {})
            sender_address = (
                from_details.get("address") if isinstance(from_details, dict) else None
            )

            formatted_message = {
                "id": msg_id,
                "from": sender_address,
                "subject": email_content.get("subject"),
                "date": _format_timestamp_iso(email_content.get("createdAt")),
                "body": email_content.get("text", "").strip(),
                "html": email_content.get("html", []),
                "raw": email_content,
            }
            new_messages.append(formatted_message)

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


# Tempmail.lol
TEMPMAIL_LOL_BASE_URL = "https://api.tempmail.lol"


async def setup_tempmail_lol(rush: bool = False) -> Tuple[str, str, Dict[str, Any]]:
    sess = make_requests_session()
    endpoint = (
        f"{TEMPMAIL_LOL_BASE_URL}/generate/rush"
        if rush
        else f"{TEMPMAIL_LOL_BASE_URL}/generate"
    )
    try:
        res = await asyncio.to_thread(sess.get, endpoint, timeout=15)
        res.raise_for_status()
        data = res.json()
        address = data.get("address")
        token = data.get("token")
        if not address or not token:
            raise APIError("tempmail.lol: Failed to get address or token.")
        provider_data = {"token": token, "base_url": TEMPMAIL_LOL_BASE_URL}
        return str(uuid.uuid4()), address, provider_data
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
        res = await asyncio.to_thread(sess.get, f"{base_url}/auth/{token}", timeout=15)
        res.raise_for_status()
        data = res.json()

        for m_content in data.get("email", []):
            msg_pseudo_id = f"{m_content.get('from')}_{m_content.get('subject')}_{m_content.get('date')}_{len(m_content.get('body',''))}"
            if msg_pseudo_id in seen_ids:
                continue

            formatted_message = {
                "id": msg_pseudo_id,
                "from": m_content.get("from"),
                "subject": m_content.get("subject"),
                "date": _format_timestamp_iso(m_content.get("date")),
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


# Dropmail.me
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
        return str(uuid.uuid4()), address, provider_data

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
            expires_dt = datetime.fromisoformat(
                expires_at_str.replace("Z", "+00:00")
            )  # Ensure timezone aware
            if datetime.now(timezone.utc) > expires_dt:
                LOGGER.warning(
                    f"dropmail.me: Session {dropmail_session_id} has expired."
                )
                raise APIError(f"dropmail.me: Session has expired at {expires_at_str}.")

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
                f"dropmail.me: Session data not found for ID {dropmail_session_id}. It might have expired."
            )
            return []

        mails = session_query_data.get("mails", [])
        for m_content in mails:
            msg_id = str(m_content["id"])
            if msg_id in seen_ids:
                continue

            formatted_message = {
                "id": msg_id,
                "from": m_content.get("fromAddr"),
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


# --- Provider Registry ---
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

# --- FastAPI Application ---
app = FastAPI(
    title="Temp Mail API",
    description="API for generating temporary email addresses and checking their inboxes.",
    version="1.0.1",
)


# --- Pydantic Models for API ---
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


class ConfigResponse(BaseModel):
    default_provider: str
    max_history_entries: int
    save_messages: bool


class UpdateConfigRequest(BaseModel):
    default_provider: Optional[str] = None
    max_history_entries: Optional[int] = None
    save_messages: Optional[bool] = None


# --- API Endpoints ---


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
            # Type ignore because setup_tempmail_lol has 'rush' but others don't, handled by conditional call
            api_session_id, email_address, provider_specific_data = await setup_func(rush=rush_mode)  # type: ignore
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
        email_address=email_address,  # type: ignore # Pydantic will validate
        provider=provider_name,
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
        api_session_id  # For potential re-auth updates
    )

    # Crucially, pass the set of seen message IDs for this session
    seen_ids_for_this_session = session_data["seen_message_ids"]

    try:
        raw_messages = await fetch_func(
            provider_specific_data, seen_ids_for_this_session
        )
    except (NetworkError, APIError) as e:
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
    config = load_config()
    save_enabled = config.get("save_messages", True)

    for raw_msg in raw_messages:
        msg_id = str(raw_msg.get("id", _rand_string()))  # Ensure ID is string

        # Add new message ID to the session's seen set *after* processing it
        # This ensures if saving fails, we don't mark it as seen.
        # The fetch_func itself should ideally only return new messages,
        # but this is an additional safety if it doesn't perfectly filter.
        # However, the current design is that fetch_func uses the passed seen_ids to filter.
        # So, raw_messages should *only* contain new messages. We add their IDs to seen_ids_for_this_session here.

        msg_model = Message(
            id=msg_id,
            from_address=raw_msg.get("from"),
            to_address=raw_msg.get("to"),
            subject=raw_msg.get("subject"),
            date=raw_msg.get("date"),
            body=raw_msg.get("body"),
            html=raw_msg.get("html"),
            raw=raw_msg.get("raw", raw_msg),
        )
        processed_messages.append(msg_model)
        seen_ids_for_this_session.add(msg_id)  # Add to set for this session

        if save_enabled:
            history_message_data = {
                "from": msg_model.from_address,
                "subject": msg_model.subject,
                "date": msg_model.date,
                "body": msg_model.body,
                "html": msg_model.html,
                "id": msg_model.id,
                "raw_data": msg_model.raw,
            }
            save_message_to_history(
                provider_name, session_data["email_address"], history_message_data
            )

    return processed_messages


@app.delete(
    "/sessions/{api_session_id}",
    status_code=204,
    summary="Delete an active email session",
)
async def delete_email_session(api_session_id: str):
    if api_session_id in active_api_sessions:
        del active_api_sessions[api_session_id]
        # No explicit return for 204
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
            msg_data = entry.get("message", {})
            adapted_message = Message(
                id=str(
                    msg_data.get(
                        "id", msg_data.get("raw_data", {}).get("id", _rand_string())
                    )
                ),
                from_address=msg_data.get("from"),
                subject=msg_data.get("subject"),
                date=msg_data.get("date"),
                body=msg_data.get("body"),
                html=msg_data.get("html"),
                raw=msg_data.get("raw_data", {}),
            )
            hist_entry = HistoryEntry(
                provider=entry.get("provider", "unknown"),
                address=entry.get("address", "unknown@example.com"),  # type: ignore
                timestamp=entry.get("timestamp", datetime.min.isoformat()),
                message=adapted_message,
            )
            result.append(hist_entry)
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

        ensure_config_dir()  # Ensure CONFIG_DIR exists
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


@app.get(
    "/config", response_model=ConfigResponse, summary="View current API configuration"
)
async def get_current_config() -> ConfigResponse:
    config = load_config()
    return ConfigResponse(**config)


@app.patch("/config", response_model=ConfigResponse, summary="Update API configuration")
async def update_api_config(new_config_payload: UpdateConfigRequest) -> ConfigResponse:
    current_config = load_config()
    update_data = new_config_payload.model_dump(exclude_unset=True)

    if (
        "default_provider" in update_data
        and update_data["default_provider"] not in PROVIDER_SETUP_FUNCTIONS
    ):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid default_provider: {update_data['default_provider']}. Must be one of {list(PROVIDER_SETUP_FUNCTIONS.keys())}",
        )
    if "max_history_entries" in update_data:
        val = update_data["max_history_entries"]
        if not isinstance(val, int) or val <= 0:
            raise HTTPException(
                status_code=400,
                detail="max_history_entries must be a positive integer.",
            )

    for key, value in update_data.items():
        current_config[key] = value

    save_config(current_config)
    return ConfigResponse(**current_config)
