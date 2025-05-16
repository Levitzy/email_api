from __future__ import annotations

import json
import logging
import os
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Coroutine, Union
from contextlib import asynccontextmanager
import shutil
import uuid
import re

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Path as FastAPIPath
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, EmailStr, Field
import asyncio

from provider.utils import ProviderNetworkError, ProviderAPIError, BaseProviderError
from provider.guerrillamail_provider import (
    setup_guerrillamail,
    fetch_guerrillamail_messages,
)
from provider.mailtm_provider import setup_mail_tm, fetch_mail_tm_messages
from provider.mailgw_provider import setup_mail_gw, fetch_mail_gw_messages
from provider.tempmaillol_provider import (
    setup_tempmail_lol,
    fetch_tempmail_lol_messages,
)
from provider.dropmailme_provider import setup_dropmail_me, fetch_dropmail_me_messages
from provider.disposableemail_provider import (
    setup_disposablemail,
    fetch_disposablemail_messages,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="[%X]",
)
LOGGER = logging.getLogger("temp-mail-api")

CONFIG_DIR = Path("/tmp") / "tempmail-api-data"
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

                data["messages_cache"] = data.get("messages_cache", [])

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


PROVIDER_SETUP_FUNCTIONS: Dict[
    str, Callable[..., Coroutine[Any, Any, Tuple[str, str, Dict[str, Any]]]]
] = {
    "guerrillamail": setup_guerrillamail,
    "mail.tm": setup_mail_tm,
    "mail.gw": setup_mail_gw,
    "tempmail.lol": setup_tempmail_lol,
    "dropmail.me": setup_dropmail_me,
    "disposablemail": setup_disposablemail,
}

PROVIDER_FETCH_FUNCTIONS: Dict[
    str,
    Callable[
        [Dict[str, Any], Dict[str, Any], Callable],
        Coroutine[Any, Any, List[Dict[str, Any]]],
    ],
] = {
    "guerrillamail": fetch_guerrillamail_messages,
    "mail.tm": fetch_mail_tm_messages,
    "mail.gw": fetch_mail_gw_messages,
    "tempmail.lol": fetch_tempmail_lol_messages,
    "dropmail.me": fetch_dropmail_me_messages,
    "disposablemail": fetch_disposablemail_messages,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_active_sessions()
    yield


app = FastAPI(
    title="Temp Mail API",
    description="API for temporary emails.",
    version="1.6.6",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


class Message(BaseModel):
    id: str
    from_address: Optional[str] = Field(None, alias="from")
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


async def _handle_provider_call(func: Callable, *args, **kwargs):
    try:
        return await func(*args, **kwargs)
    except ProviderNetworkError as e:
        raise HTTPException(status_code=e.status_code or 503, detail=e.message)
    except ProviderAPIError as e:
        raise HTTPException(status_code=e.status_code or 502, detail=e.message)
    except BaseProviderError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=e.message)
    except Exception as e:
        LOGGER.error(
            f"Unexpected error during provider call '{func.__name__}': {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred with the provider: {str(e)}",
        )


@app.post(
    "/sessions",
    response_model=EmailSessionResponse,
    status_code=201,
    summary="Create new temp email session",
)
async def create_email_session(
    provider_name: str = Query(...),
    rush_mode: bool = Query(False),
    custom_name: Optional[str] = Query(None),
) -> EmailSessionResponse:
    if provider_name not in PROVIDER_SETUP_FUNCTIONS:
        raise HTTPException(
            status_code=400, detail=f"Provider '{provider_name}' not supported."
        )
    setup_func = PROVIDER_SETUP_FUNCTIONS[provider_name]

    api_session_id, email_address, provider_specific_data = await _handle_provider_call(
        setup_func, rush=rush_mode, custom_name=custom_name
    )

    created_at_dt = datetime.now(timezone.utc)
    session_data = {
        "api_session_id": api_session_id,
        "provider_name": provider_name,
        "email_address": email_address,
        "provider_specific_data": provider_specific_data,
        "messages_cache": [],
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
    provider: Optional[str] = Query(None),
    rush_mode: bool = Query(False),
    custom_name: Optional[str] = Query(None),
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
    api_session_id, email_address, provider_specific_data = await _handle_provider_call(
        setup_func, rush=rush_mode, custom_name=custom_name
    )

    created_at_dt = datetime.now(timezone.utc)
    session_data = {
        "api_session_id": api_session_id,
        "provider_name": provider_to_use,
        "email_address": email_address,
        "provider_specific_data": provider_specific_data,
        "messages_cache": [],
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
    provider_specific_data["api_session_id"] = api_session_id

    try:
        provider_messages_list = await fetch_func(
            provider_specific_data, active_api_sessions, save_active_sessions
        )
    except ProviderAPIError as e:
        if (
            "session expired" in e.message.lower()
            or "session not found" in e.message.lower()
            or "token is invalid" in e.message.lower()
            or "session context lost" in e.message.lower()
        ):
            LOGGER.warning(
                f"API session {api_session_id} ({provider_name}) invalid/expired by provider: {e.message}. Removing local session."
            )
            if api_session_id in active_api_sessions:
                del active_api_sessions[api_session_id]
                save_active_sessions()
            raise HTTPException(
                status_code=404,
                detail=f"API session {api_session_id} no longer valid or expired by provider.",
            ) from e
        raise HTTPException(status_code=e.status_code or 502, detail=e.message)
    except ProviderNetworkError as e:
        raise HTTPException(status_code=e.status_code or 503, detail=e.message)
    except BaseProviderError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=e.message)
    except Exception as e:
        LOGGER.error(
            f"Error fetching messages from provider for {api_session_id} ({provider_name}): {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch messages from provider: {str(e)}"
        )

    session_message_cache_list = session_data.get("messages_cache", [])
    session_message_cache_map = {
        msg_dict["id"]: msg_dict for msg_dict in session_message_cache_list
    }

    cache_needs_saving = False

    for provider_msg_data_dict in provider_messages_list:
        if not isinstance(provider_msg_data_dict, dict):
            continue

        provider_msg_id = str(provider_msg_data_dict.get("id", uuid.uuid4().hex[:10]))
        provider_msg_data_dict["id"] = provider_msg_id

        if provider_msg_id not in session_message_cache_map:
            session_message_cache_map[provider_msg_id] = provider_msg_data_dict
            cache_needs_saving = True
        else:
            if session_message_cache_map[provider_msg_id] != provider_msg_data_dict:
                session_message_cache_map[provider_msg_id] = provider_msg_data_dict
                cache_needs_saving = True

    if cache_needs_saving:
        updated_cache_list = list(session_message_cache_map.values())
        session_data["messages_cache"] = updated_cache_list
        session_data["last_saved_at"] = datetime.now(timezone.utc)
        save_active_sessions()

    final_messages_to_return_dicts = list(session_message_cache_map.values())

    try:
        final_messages_to_return_dicts.sort(
            key=lambda m: (
                datetime.fromisoformat(m["date"].replace("Z", "+00:00"))
                if m.get("date")
                and isinstance(m["date"], str)
                and not re.match(
                    r"(\d+)\s+(sec|min|hour|day)s?\.\s+ago", m["date"], re.IGNORECASE
                )
                else datetime.min.replace(tzinfo=timezone.utc)
            ),
            reverse=True,
        )
    except Exception as sort_e:
        LOGGER.warning(
            f"Could not sort messages by date for session {api_session_id}: {sort_e}"
        )

    response_messages: List[Message] = []
    for msg_dict in final_messages_to_return_dicts:
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
    "/sessions/{api_session_id}/messages/{message_id}",
    status_code=204,
    summary="Delete a specific message from a session's cache",
)
async def delete_message_from_session_cache(
    api_session_id: str = FastAPIPath(..., description="The ID of the API session"),
    message_id: str = FastAPIPath(..., description="The ID of the message to delete"),
):
    if api_session_id not in active_api_sessions:
        load_active_sessions()
        if api_session_id not in active_api_sessions:
            raise HTTPException(status_code=404, detail="API session not found.")

    session_data = active_api_sessions[api_session_id]

    messages_cache = session_data.get("messages_cache", [])

    initial_cache_length = len(messages_cache)
    messages_cache = [msg for msg in messages_cache if str(msg.get("id")) != message_id]

    if len(messages_cache) < initial_cache_length:
        session_data["messages_cache"] = messages_cache
        session_data["last_saved_at"] = datetime.now(timezone.utc)
        save_active_sessions()
        LOGGER.info(
            f"Message {message_id} deleted from cache for session {api_session_id}."
        )
        return
    else:
        LOGGER.info(
            f"Message {message_id} not found in cache for session {api_session_id}, no action taken."
        )
        return


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
    load_active_sessions()
    if api_session_id in active_api_sessions:
        del active_api_sessions[api_session_id]
        save_active_sessions()
        return
    raise HTTPException(status_code=404, detail="API session not found.")


if __name__ == "__main__":
    ensure_config_dir()
    current_dir = Path(__file__).parent
    _ensure_html_file_exists(current_dir / "index.html", "ERROR: index.html not found.")
    _ensure_html_file_exists(current_dir / "docs.html", "ERROR: docs.html not found.")
    uvicorn.run(app, host="0.0.0.0", port=8000)
