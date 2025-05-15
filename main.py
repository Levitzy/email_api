from __future__ import annotations

import json
import logging
import os
import random
import string
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, Coroutine
from email.utils import parseaddr
from contextlib import asynccontextmanager
import shutil

import requests
import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, EmailStr, Field
import asyncio

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="[%X]",
)
LOGGER = logging.getLogger("temp-mail-api")

CONFIG_DIR = Path.home() / ".config" / "tempmail-api"
ACTIVE_SESSIONS_FILE = CONFIG_DIR / "active_sessions.json"
ACTIVE_SESSIONS_FILE_TEMP = CONFIG_DIR / "active_sessions.json.tmp"
SESSION_EXPIRY_DAYS = 7

active_api_sessions: Dict[str, Dict[str, Any]] = {}


def ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def save_active_sessions() -> None:
    ensure_config_dir()
    try:
        sessions_to_save = {}
        for session_id, data in active_api_sessions.items():
            session_copy = data.copy()
            # Ensure messages_cache is serializable (already list of dicts)
            session_copy["messages_cache"] = data.get("messages_cache", [])
            for key in ["created_at", "last_accessed_at", "last_saved_at"]:
                if key in session_copy and isinstance(session_copy[key], datetime):
                    session_copy[key] = session_copy[key].isoformat()

            if "provider_specific_data" in session_copy and isinstance(
                session_copy["provider_specific_data"], dict
            ):
                prov_data_copy = session_copy["provider_specific_data"].copy()
                if "expires_at" in prov_data_copy:
                    if isinstance(prov_data_copy["expires_at"], datetime):
                        prov_data_copy["expires_at"] = prov_data_copy[
                            "expires_at"
                        ].isoformat()
                    elif prov_data_copy["expires_at"] is None:
                        pass
                session_copy["provider_specific_data"] = prov_data_copy
            sessions_to_save[session_id] = session_copy

        with open(ACTIVE_SESSIONS_FILE_TEMP, "w") as f:
            json.dump(sessions_to_save, f, indent=2)
        shutil.move(str(ACTIVE_SESSIONS_FILE_TEMP), str(ACTIVE_SESSIONS_FILE))
    except Exception as e:
        LOGGER.error(f"Failed to save active sessions: {e}", exc_info=True)
        if ACTIVE_SESSIONS_FILE_TEMP.exists():
            try:
                os.remove(ACTIVE_SESSIONS_FILE_TEMP)
            except OSError as ose:
                LOGGER.error(
                    f"Could not remove temporary session file {ACTIVE_SESSIONS_FILE_TEMP}: {ose}"
                )


def load_active_sessions() -> None:
    global active_api_sessions
    ensure_config_dir()
    if ACTIVE_SESSIONS_FILE.exists():
        try:
            with open(ACTIVE_SESSIONS_FILE, "r") as f:
                loaded_sessions = json.load(f)

            now = datetime.now(timezone.utc)
            valid_sessions = {}
            for session_id, data in loaded_sessions.items():
                last_accessed_str = data.get("last_accessed_at")
                if last_accessed_str and isinstance(last_accessed_str, str):
                    try:
                        last_accessed_dt = datetime.fromisoformat(last_accessed_str)
                        if now - last_accessed_dt > timedelta(days=SESSION_EXPIRY_DAYS):
                            LOGGER.info(
                                f"Session {session_id} expired due to inactivity, removing."
                            )
                            continue
                    except ValueError:
                        LOGGER.warning(
                            f"Could not parse last_accessed_at for session {session_id}: {last_accessed_str}"
                        )

                data["messages_cache"] = data.get(
                    "messages_cache", []
                )  # Ensure it exists

                for key in ["created_at", "last_accessed_at", "last_saved_at"]:
                    if key in data and isinstance(data[key], str):
                        try:
                            data[key] = datetime.fromisoformat(data[key])
                        except ValueError:
                            LOGGER.warning(
                                f"Could not parse {key} for session {session_id}: {data[key]}"
                            )
                            data[key] = datetime.now(timezone.utc)

                if "provider_specific_data" in data and isinstance(
                    data["provider_specific_data"], dict
                ):
                    if "expires_at" in data["provider_specific_data"] and isinstance(
                        data["provider_specific_data"]["expires_at"], str
                    ):
                        try:
                            data["provider_specific_data"]["expires_at"] = (
                                datetime.fromisoformat(
                                    data["provider_specific_data"]["expires_at"]
                                )
                            )
                        except ValueError:
                            LOGGER.warning(
                                f"Could not parse provider_specific_data.expires_at for session {session_id}"
                            )
                            data["provider_specific_data"]["expires_at"] = None
                valid_sessions[session_id] = data
            active_api_sessions = valid_sessions
            LOGGER.info(f"Loaded {len(active_api_sessions)} active sessions from file.")
            if len(loaded_sessions) != len(valid_sessions):
                save_active_sessions()
        except json.JSONDecodeError as jde:
            LOGGER.error(
                f"Failed to load active sessions due to JSONDecodeError: {jde}. Corrupted file? Starting fresh.",
                exc_info=True,
            )
            if ACTIVE_SESSIONS_FILE.exists():
                corrupted_backup = (
                    CONFIG_DIR
                    / f"active_sessions_corrupted_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
                )
                try:
                    shutil.move(str(ACTIVE_SESSIONS_FILE), str(corrupted_backup))
                    LOGGER.info(
                        f"Backed up corrupted session file to {corrupted_backup}"
                    )
                except Exception as e_backup:
                    LOGGER.error(f"Could not backup corrupted session file: {e_backup}")
            active_api_sessions = {}
        except Exception as e:
            LOGGER.error(f"Failed to load active sessions: {e}", exc_info=True)
            active_api_sessions = {}
    else:
        active_api_sessions = {}
        LOGGER.info("No active sessions file found. Starting with empty sessions.")


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
                    f"dateutil not installed, could not parse: {timestamp_input}"
                )
                return timestamp_input
            except Exception as e_du:
                LOGGER.warning(
                    f"Could not parse with dateutil: {timestamp_input} - {e_du}"
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
            raise APIError("GuerrillaMail: Failed to initialize session.")
        sid_token = init_data["sid_token"]
        address = init_data["email_addr"]
        provider_data = {
            "sid_token": sid_token,
            "requests_session_headers": dict(sess.headers),
        }
        return f"biar-{uuid.uuid4()}", address, provider_data
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            raise APIError(f"GuerrillaMail: Too Many Requests. Details: {e}")
        raise NetworkError(f"GuerrillaMail: HTTP error: {e}") from e
    except requests.RequestException as e:
        raise NetworkError(f"GuerrillaMail: Network error: {e}") from e
    except (json.JSONDecodeError, KeyError) as e:
        raise APIError(f"GuerrillaMail: API error: {e}") from e


async def fetch_guerrillamail_messages(
    provider_data: Dict[str, Any],
) -> List[Dict[str, Any]]:
    sess = make_requests_session()
    if "requests_session_headers" in provider_data:
        sess.headers.update(provider_data["requests_session_headers"])
    sid_token = provider_data.get("sid_token")
    if not sid_token:
        raise APIError("GuerrillaMail: Missing sid_token.")

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
            raise APIError(f"{provider_name}: Failed to get auth token.")

        provider_data = {
            "base_url": base_url,
            "auth_token": auth_token,
            "address": address,
            "password": password,
        }
        return f"biar-{uuid.uuid4()}", address, provider_data
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            raise APIError(f"{provider_name}: Too Many Requests. Details: {e}")
        raise NetworkError(f"{provider_name}: HTTP error setup: {e}") from e
    except requests.RequestException as e:
        raise NetworkError(f"{provider_name}: Network error setup: {e}") from e
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        raise APIError(f"{provider_name}: API error setup: {e}") from e


async def _fetch_mail_tm_gw_like_messages(
    provider_data: Dict[str, Any], provider_name: str
) -> List[Dict[str, Any]]:
    sess = make_requests_session()
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
                    raise APIError(f"{provider_name}: Re-auth failed (no new token).")

                provider_data["auth_token"] = new_auth_token
                api_session_id_for_update = provider_data.get("api_session_id")
                if (
                    api_session_id_for_update
                    and api_session_id_for_update in active_api_sessions
                ):
                    active_api_sessions[api_session_id_for_update][
                        "provider_specific_data"
                    ]["auth_token"] = new_auth_token
                    save_active_sessions()

                headers = {"Authorization": f"Bearer {new_auth_token}"}
                await asyncio.sleep(0.5)
                inbox_res = await asyncio.to_thread(
                    sess.get, f"{base_url}/messages", headers=headers, timeout=15
                )
            except requests.exceptions.HTTPError as reauth_e:
                if reauth_e.response.status_code == 429:
                    raise APIError(
                        f"{provider_name}: Too Many Requests (re-auth). Details: {reauth_e}"
                    )
                LOGGER.error(f"{provider_name}: Re-auth failed: {reauth_e}")
                raise APIError(f"{provider_name}: Re-auth failed.") from reauth_e
            except Exception as reauth_e:
                LOGGER.error(f"{provider_name}: Re-auth failed: {reauth_e}")
                raise APIError(f"{provider_name}: Re-auth failed.") from reauth_e

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
        if e.response.status_code == 429:
            raise APIError(f"{provider_name}: Too Many Requests (fetch). Details: {e}")
        LOGGER.warning(f"{provider_name}: HTTP error polling: {e}")
    except requests.RequestException as e:
        LOGGER.warning(f"{provider_name}: Network error polling: {e}")
    except (json.JSONDecodeError, KeyError) as e:
        LOGGER.warning(f"{provider_name}: API error polling: {e}")
    return all_provider_messages


async def setup_mail_tm() -> Tuple[str, str, Dict[str, Any]]:
    return await _setup_mail_tm_gw_like("https://api.mail.tm", "mail.tm")


async def fetch_mail_tm_messages(provider_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return await _fetch_mail_tm_gw_like_messages(provider_data, "mail.tm")


async def setup_mail_gw() -> Tuple[str, str, Dict[str, Any]]:
    return await _setup_mail_tm_gw_like("https://api.mail.gw", "mail.gw")


async def fetch_mail_gw_messages(provider_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return await _fetch_mail_tm_gw_like_messages(provider_data, "mail.gw")


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
            raise APIError(f"tempmail.lol: Too Many Requests. Details: {e}")
        raise NetworkError(f"tempmail.lol: HTTP error setup: {e}") from e
    except requests.RequestException as e:
        raise NetworkError(f"tempmail.lol: Network error setup: {e}") from e
    except (json.JSONDecodeError, KeyError) as e:
        raise APIError(f"tempmail.lol: API error setup: {e}") from e


async def fetch_tempmail_lol_messages(
    provider_data: Dict[str, Any],
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
                and api_session_id_for_removal in active_api_sessions
            ):
                del active_api_sessions[api_session_id_for_removal]
                save_active_sessions()
            raise APIError(
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


DROPMAIL_ME_BASE_URL = "https://dropmail.me/api/graphql"


async def setup_dropmail_me() -> Tuple[str, str, Dict[str, Any]]:
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
            raise APIError(
                f"dropmail.me: 'introduceSession' data not found: {response_data.get('errors')}"
            )

        session_id_val = session_data.get("id")
        addresses = session_data.get("addresses", [])
        if not session_id_val or not addresses or not addresses[0].get("address"):
            raise APIError("dropmail.me: Failed to get session ID or address.")
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
        if e.response.status_code == 429:
            raise APIError(f"dropmail.me: Too Many Requests. Details: {e}")
        raise NetworkError(f"dropmail.me: HTTP error setup: {e}") from e
    except requests.RequestException as e:
        raise NetworkError(f"dropmail.me: Network error setup: {e}") from e
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
        raise APIError(f"dropmail.me: API error setup: {e}") from e


async def fetch_dropmail_me_messages(
    provider_data: Dict[str, Any],
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
                if (
                    api_session_id_for_removal
                    and api_session_id_for_removal in active_api_sessions
                ):
                    del active_api_sessions[api_session_id_for_removal]
                    save_active_sessions()
                raise APIError(f"dropmail.me: Session has expired at {expires_at_val}.")

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
            if (
                api_session_id_for_removal
                and api_session_id_for_removal in active_api_sessions
            ):
                del active_api_sessions[api_session_id_for_removal]
                save_active_sessions()
            raise APIError(
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
            all_provider_messages.append(formatted_message)
    except requests.RequestException as e:
        LOGGER.warning(f"dropmail.me: Network error polling: {e}")
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        LOGGER.warning(f"dropmail.me: API error polling: {e}")
    return all_provider_messages


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
    str, Callable[[Dict[str, Any]], Coroutine[Any, Any, List[Dict[str, Any]]]]
] = {
    "guerrillamail": fetch_guerrillamail_messages,
    "mail.tm": fetch_mail_tm_messages,
    "mail.gw": fetch_mail_gw_messages,
    "tempmail.lol": fetch_tempmail_lol_messages,
    "dropmail.me": fetch_dropmail_me_messages,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_active_sessions()
    yield


app = FastAPI(
    title="Temp Mail API",
    description="API for temporary emails.",
    version="1.5.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
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
    api_session_id: str
    email_address: EmailStr
    provider: str
    created_at: str
    expires_at: Optional[str] = None


def _ensure_html_file_exists(path: Path, detail_msg: str):
    if not path.is_file():
        LOGGER.error(f"{detail_msg} at {path}")
        raise HTTPException(status_code=500, detail=detail_msg)


@app.get("/", response_class=HTMLResponse)
async def get_index_page():
    index_path = Path(__file__).parent / "index.html"
    _ensure_html_file_exists(index_path, "Index page HTML file not found on server.")
    return FileResponse(index_path)


@app.get("/docs", response_class=HTMLResponse)
async def get_docs_page():
    docs_path = Path(__file__).parent / "docs.html"
    _ensure_html_file_exists(
        docs_path, "Documentation page HTML file not found on server."
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
    summary="Create new temp email session",
)
async def create_email_session(
    provider_name: str = Query(...), rush_mode: bool = Query(False)
) -> EmailSessionResponse:
    if provider_name not in PROVIDER_SETUP_FUNCTIONS:
        raise HTTPException(
            status_code=400, detail=f"Provider '{provider_name}' not supported."
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
        LOGGER.error(f"Error creating session for {provider_name}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Failed to create session: {str(e)}"
        )

    created_at_dt = datetime.now(timezone.utc)
    session_data = {
        "api_session_id": api_session_id,
        "provider_name": provider_name,
        "email_address": email_address,
        "provider_specific_data": provider_specific_data,
        "messages_cache": [],  # Initialize empty message cache
        "created_at": created_at_dt,
        "last_accessed_at": created_at_dt,
        "last_saved_at": created_at_dt,
    }
    active_api_sessions[api_session_id] = session_data
    save_active_sessions()

    expires_at_iso = provider_specific_data.get("expires_at")
    if isinstance(expires_at_iso, datetime):
        expires_at_iso = expires_at_iso.isoformat()

    return EmailSessionResponse(
        api_session_id=api_session_id,
        email_address=email_address,
        provider=provider_name,
        created_at=created_at_dt.isoformat(),
        expires_at=expires_at_iso,
    )


@app.api_route(
    "/gen",
    methods=["GET", "POST"],
    response_model=EmailSessionResponse,
    status_code=201,
    summary="Generate temp email (random/specific provider)",
)
async def generate_email_address(
    provider: Optional[str] = Query(None), rush_mode: bool = Query(False)
) -> EmailSessionResponse:
    provider_to_use: str
    available_providers = list(PROVIDER_SETUP_FUNCTIONS.keys())
    if not available_providers:
        raise HTTPException(status_code=500, detail="No email providers available.")

    if provider and provider.lower() == "random":
        provider_to_use = random.choice(available_providers)
    elif provider and provider in PROVIDER_SETUP_FUNCTIONS:
        provider_to_use = provider
    elif not provider:
        provider_to_use = random.choice(available_providers)
    else:
        raise HTTPException(
            status_code=400, detail=f"Provider '{provider}' not supported."
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
            f"Error creating session for {provider_to_use} (/gen): {e}", exc_info=True
        )
        raise HTTPException(
            status_code=500, detail=f"Failed to create session: {str(e)}"
        )

    created_at_dt = datetime.now(timezone.utc)
    session_data = {
        "api_session_id": api_session_id,
        "provider_name": provider_to_use,
        "email_address": email_address,
        "provider_specific_data": provider_specific_data,
        "messages_cache": [],  # Initialize empty message cache
        "created_at": created_at_dt,
        "last_accessed_at": created_at_dt,
        "last_saved_at": created_at_dt,
    }
    active_api_sessions[api_session_id] = session_data
    save_active_sessions()

    expires_at_iso = provider_specific_data.get("expires_at")
    if isinstance(expires_at_iso, datetime):
        expires_at_iso = expires_at_iso.isoformat()

    return EmailSessionResponse(
        api_session_id=api_session_id,
        email_address=email_address,
        provider=provider_to_use,
        created_at=created_at_dt.isoformat(),
        expires_at=expires_at_iso,
    )


@app.get(
    "/sessions/{api_session_id}/messages",
    response_model=List[Message],
    summary="Fetch messages for a session (returns all messages ever seen for the session)",
)
async def get_messages_for_session(api_session_id: str) -> List[Message]:
    if api_session_id not in active_api_sessions:
        load_active_sessions()
        if api_session_id not in active_api_sessions:
            raise HTTPException(
                status_code=404, detail="API session not found or expired."
            )

    session_data = active_api_sessions[api_session_id]
    session_data["last_accessed_at"] = datetime.now(timezone.utc)

    provider_name = session_data["provider_name"]
    fetch_func = PROVIDER_FETCH_FUNCTIONS[provider_name]
    provider_specific_data = session_data["provider_specific_data"]
    provider_specific_data["api_session_id"] = (
        api_session_id  # For context within fetch functions
    )

    try:
        provider_messages_list = await fetch_func(provider_specific_data)
    except APIError as e:
        if (
            "Session has expired" in str(e.detail)
            or "Session data not found" in str(e.detail)
            or "not found or expired on server" in str(e.detail)
            or "token is invalid" in str(e.detail).lower()
        ):
            LOGGER.warning(
                f"API session {api_session_id} ({provider_name}) invalid/expired by provider: {e.detail}. Removing local session."
            )
            if api_session_id in active_api_sessions:
                del active_api_sessions[api_session_id]
                save_active_sessions()
            raise HTTPException(
                status_code=404,
                detail=f"API session {api_session_id} no longer valid or expired by provider.",
            ) from e
        raise e  # Re-raise other APIErrors
    except NetworkError as e:
        raise e  # Re-raise NetworkErrors
    except Exception as e:
        LOGGER.error(
            f"Error fetching messages from provider for {api_session_id} ({provider_name}): {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch messages from provider: {str(e)}"
        )

    # Merge provider messages with existing cache
    cached_messages_list = session_data.get("messages_cache", [])
    message_map_for_merge = {msg["id"]: msg for msg in cached_messages_list}

    for provider_msg_dict in provider_messages_list:
        if not isinstance(provider_msg_dict, dict):
            continue  # Skip if not a dict
        msg_id = str(provider_msg_dict.get("id", _rand_string()))
        provider_msg_dict["id"] = msg_id  # Ensure ID is set for the map key
        message_map_for_merge[msg_id] = provider_msg_dict  # Add new or update existing

    updated_messages_cache = list(message_map_for_merge.values())
    session_data["messages_cache"] = updated_messages_cache

    # Sort messages by date if possible, most recent first, before returning
    # This is for consistent client display if they don't sort
    try:
        updated_messages_cache.sort(
            key=lambda m: (
                datetime.fromisoformat(m["date"].replace("Z", "+00:00"))
                if m.get("date")
                else datetime.min.replace(tzinfo=timezone.utc)
            ),
            reverse=True,
        )
    except Exception as sort_e:
        LOGGER.warning(
            f"Could not sort messages by date for session {api_session_id}: {sort_e}"
        )

    session_data["last_saved_at"] = datetime.now(timezone.utc)
    save_active_sessions()  # Persist the updated cache and access times

    # Convert list of dicts to list of Pydantic Message models for response
    response_messages: List[Message] = []
    for msg_dict in updated_messages_cache:
        try:
            msg_id_for_model = str(msg_dict.get("id"))
            raw_data_for_model = {k: v for k, v in msg_dict.items() if k != "id"}
            response_messages.append(Message(id=msg_id_for_model, **raw_data_for_model))
        except Exception as model_exc:
            LOGGER.error(
                f"Error creating Message model for response: {model_exc}. Data: {msg_dict}"
            )
            continue

    return response_messages


@app.delete(
    "/sessions/{api_session_id}",
    status_code=204,
    summary="Delete an active email session",
)
async def delete_email_session(api_session_id: str):
    if api_session_id in active_api_sessions:
        del active_api_sessions[api_session_id]
        save_active_sessions()
        return
    load_active_sessions()  # Try loading from disk if not in memory
    if api_session_id in active_api_sessions:
        del active_api_sessions[api_session_id]
        save_active_sessions()
        return
    # If still not found after reload, then it's a 404
    raise HTTPException(status_code=404, detail="API session not found.")


if __name__ == "__main__":
    ensure_config_dir()
    current_dir = Path(__file__).parent
    _ensure_html_file_exists(current_dir / "index.html", "ERROR: index.html not found.")
    _ensure_html_file_exists(current_dir / "docs.html", "ERROR: docs.html not found.")
    uvicorn.run(app, host="0.0.0.0", port=8000)
