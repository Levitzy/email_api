import asyncio
import json
import uuid
import re
import time
import random
import gzip
from urllib.parse import quote as url_quote, unquote as url_unquote
from email.utils import parseaddr
from email import message_from_string
from email.message import Message as EmailMessageClass
from typing import Any, Dict, List, Tuple, Optional
from pathlib import Path  # For saving to /tmp

import requests
import hashlib

from .utils import (
    LOGGER,
    _rand_string,
    _format_timestamp_iso,
    make_requests_session,
    ProviderNetworkError,
    ProviderAPIError,
)

DISPOSABLEMAIL_BASE_URL = "https://www.disposablemail.com"
UPDATED_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36"


MINIMAL_INITIAL_HEADERS = {
    "User-Agent": UPDATED_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

DEFAULT_XHR_HEADERS = {
    "User-Agent": UPDATED_USER_AGENT,
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "X-Requested-With": "XMLHttpRequest",
    "Origin": DISPOSABLEMAIL_BASE_URL,
    "Referer": f"{DISPOSABLEMAIL_BASE_URL}/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Connection": "keep-alive",
}


async def setup_disposablemail(
    custom_name: Optional[str] = None, **kwargs
) -> Tuple[str, str, Dict[str, Any]]:
    await asyncio.sleep(random.uniform(0.5, 1.5))

    sess = make_requests_session(timeout=30)
    provider_data = {}
    email_address = ""

    if custom_name:
        try:
            sess.headers.update(
                MINIMAL_INITIAL_HEADERS
            )  # Start with minimal headers for first contact

            LOGGER.info(
                f"DisposableMail (Custom): Initial GET to {DISPOSABLEMAIL_BASE_URL} with headers: {sess.headers}"
            )
            LOGGER.debug(
                f"DisposableMail (Custom): Session cookies BEFORE initial GET: {sess.cookies.get_dict()}"
            )
            initial_get_res = await asyncio.to_thread(
                sess.get, DISPOSABLEMAIL_BASE_URL, timeout=30
            )
            LOGGER.info(
                f"DisposableMail (Custom): Initial GET response status: {initial_get_res.status_code}, URL: {initial_get_res.url}"
            )
            LOGGER.debug(
                f"DisposableMail (Custom): Initial GET response headers: {initial_get_res.headers}"
            )
            LOGGER.debug(
                f"DisposableMail (Custom): Initial GET session cookies AFTER initial GET: {sess.cookies.get_dict()}"
            )
            initial_get_res.raise_for_status()

            html_content_initial_bytes = initial_get_res.content
            content_encoding_initial = initial_get_res.headers.get("Content-Encoding")
            LOGGER.info(
                f"DisposableMail (Custom Initial GET): Content-Encoding: {content_encoding_initial}, Apparent Encoding: {initial_get_res.apparent_encoding}, Length: {len(html_content_initial_bytes)}"
            )

            if content_encoding_initial == "gzip":
                LOGGER.info(
                    "DisposableMail (Custom Initial GET): Decompressing gzipped content."
                )
                try:
                    html_content_initial_bytes = gzip.decompress(
                        html_content_initial_bytes
                    )
                    LOGGER.info(
                        "DisposableMail (Custom Initial GET): Gzip decompression successful."
                    )
                except Exception as e_gzip:
                    LOGGER.error(
                        f"DisposableMail (Custom Initial GET): Gzip decompression failed: {e_gzip}. Logging raw bytes snippet."
                    )
                    LOGGER.debug(
                        f"DisposableMail (Custom Initial GET): Raw gzipped bytes snippet: {initial_get_res.content[:500].hex()}"
                    )
                    raise ProviderAPIError(
                        "DisposableMail: Failed to decompress gzipped initial content."
                    )

            html_content_initial = ""
            try:
                html_content_initial = html_content_initial_bytes.decode("utf-8")
                LOGGER.info(
                    "DisposableMail (Custom Initial GET): Decoded content with UTF-8."
                )
            except UnicodeDecodeError:
                LOGGER.warning(
                    "DisposableMail (Custom Initial GET): UTF-8 decoding failed, trying latin-1."
                )
                try:
                    html_content_initial = html_content_initial_bytes.decode("latin-1")
                    LOGGER.info(
                        "DisposableMail (Custom Initial GET): Decoded content with latin-1."
                    )
                except Exception as e_decode_fallback:
                    LOGGER.error(
                        f"DisposableMail (Custom Initial GET): Fallback decoding failed: {e_decode_fallback}. Logging raw bytes as hex."
                    )
                    LOGGER.debug(
                        f"DisposableMail (Custom Initial GET): Raw bytes as hex (first 1000 bytes): {html_content_initial_bytes[:1000].hex()}"
                    )
                    html_content_initial = ""

            for term in [
                "captcha",
                "human verification",
                "rate limit",
                "blocked",
                "are you a robot",
                "verify you are human",
                "robot check",
            ]:
                if (
                    html_content_initial and term in html_content_initial.lower()
                ):  # Check if html_content_initial is not empty
                    LOGGER.error(
                        f"DisposableMail (Custom Initial GET): Detected possible '{term}' page. HTML (first 2000 chars): {html_content_initial[:2000]}"
                    )
                    raise ProviderAPIError(
                        f"DisposableMail: Provider served a '{term}' page on initial GET, cannot proceed."
                    )

            await asyncio.sleep(random.uniform(0.3, 0.8))

            check_headers = DEFAULT_XHR_HEADERS.copy()
            check_payload = {"email": custom_name, "format": "json"}
            LOGGER.info(
                f"DisposableMail: Checking custom name '{custom_name}' with headers: {check_headers} and payload: {check_payload}"
            )
            LOGGER.debug(
                f"DisposableMail: Session cookies BEFORE custom name check: {sess.cookies.get_dict()}"
            )
            check_res = await asyncio.to_thread(
                sess.post,
                f"{DISPOSABLEMAIL_BASE_URL}/index/email-check/",
                data=check_payload,
                headers=check_headers,
                timeout=20,
            )
            LOGGER.info(
                f"DisposableMail: Custom name check response status: {check_res.status_code}, text: {check_res.text[:200]}"
            )
            LOGGER.debug(
                f"DisposableMail: Session cookies AFTER custom name check: {sess.cookies.get_dict()}"
            )
            check_res.raise_for_status()
            if check_res.text != "ok":
                raise ProviderAPIError(
                    f"DisposableMail: Custom email name '{custom_name}' not available or invalid format. Response: {check_res.text}"
                )

            await asyncio.sleep(random.uniform(0.3, 0.8))

            create_headers = check_headers
            create_payload = {"emailInput": custom_name, "format": "json"}
            LOGGER.info(
                f"DisposableMail: Creating custom email '{custom_name}' with headers: {create_headers} and payload: {create_payload}"
            )
            LOGGER.debug(
                f"DisposableMail: Session cookies BEFORE custom email create: {sess.cookies.get_dict()}"
            )
            create_res = await asyncio.to_thread(
                sess.post,
                f"{DISPOSABLEMAIL_BASE_URL}/index/new-email/",
                data=create_payload,
                headers=create_headers,
                timeout=20,
            )
            LOGGER.info(
                f"DisposableMail: Custom email create response status: {create_res.status_code}"
            )
            LOGGER.debug(
                f"DisposableMail: Custom email create response headers: {create_res.headers}"
            )
            LOGGER.debug(
                f"DisposableMail: Session cookies AFTER custom email create: {sess.cookies.get_dict()}"
            )
            create_res.raise_for_status()

            tma_cookie_str = None
            for cookie_obj in sess.cookies:
                if (
                    cookie_obj.name == "TMA"
                    and "disposablemail.com" in cookie_obj.domain
                ):
                    tma_cookie_str = f"TMA={cookie_obj.value}"
                    break

            LOGGER.info(
                f"DisposableMail: TMA cookie string for custom mail from session: {tma_cookie_str}"
            )
            if not tma_cookie_str or not tma_cookie_str.startswith("TMA="):
                raise ProviderAPIError(
                    "DisposableMail: Failed to retrieve TMA cookie for custom email from session."
                )

            email_address_encoded = tma_cookie_str.split("=", 1)[1]
            email_address = url_unquote(email_address_encoded)

            provider_data = {
                "type": "custom",
                "email": email_address,
                "tma_cookie_value": tma_cookie_str,
                "session_cookies": sess.cookies.get_dict(),
            }

        except requests.RequestException as e:
            raise ProviderNetworkError(
                f"DisposableMail (custom): Network error: {e}"
            ) from e
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
            raise ProviderAPIError(
                f"DisposableMail (custom): API response error: {e}"
            ) from e
    else:
        try:
            home_headers = (
                sess.headers.copy()
            )  # sess.headers should have MINIMAL_INITIAL_HEADERS
            home_headers["Referer"] = f"{DISPOSABLEMAIL_BASE_URL}/"

            LOGGER.info(
                f"DisposableMail (Default): Requesting homepage with headers: {home_headers}"
            )
            LOGGER.debug(
                f"DisposableMail (Default): Session cookies BEFORE homepage GET: {sess.cookies.get_dict()}"
            )
            home_res = await asyncio.to_thread(
                sess.get, DISPOSABLEMAIL_BASE_URL, headers=home_headers, timeout=30
            )
            LOGGER.info(
                f"DisposableMail (Default): Homepage response status: {home_res.status_code}, URL: {home_res.url}"
            )
            LOGGER.debug(
                f"DisposableMail (Default): Homepage response headers: {home_res.headers}"
            )
            LOGGER.debug(
                f"DisposableMail (Default): Session cookies AFTER homepage GET: {sess.cookies.get_dict()}"
            )
            home_res.raise_for_status()

            html_content_bytes = home_res.content
            content_encoding = home_res.headers.get("Content-Encoding")
            LOGGER.info(
                f"DisposableMail (Default Homepage): Content-Encoding: {content_encoding}, Apparent Encoding: {home_res.apparent_encoding}, Length: {len(html_content_bytes)}"
            )

            # Save raw response to /tmp for debugging on Vercel
            try:
                tmp_file_path = (
                    Path("/tmp") / f"disposablemail_home_{uuid.uuid4().hex}.html.gz"
                    if content_encoding == "gzip"
                    else Path("/tmp") / f"disposablemail_home_{uuid.uuid4().hex}.html"
                )
                with open(tmp_file_path, "wb") as f_tmp:
                    f_tmp.write(
                        home_res.content
                    )  # Save original content (potentially gzipped)
                LOGGER.info(
                    f"DisposableMail (Default Homepage): Saved raw response to {tmp_file_path}, size: {tmp_file_path.stat().st_size}"
                )
            except Exception as e_save:
                LOGGER.error(
                    f"DisposableMail (Default Homepage): Failed to save raw response to /tmp: {e_save}"
                )

            if content_encoding == "gzip":
                LOGGER.info(
                    "DisposableMail (Default Homepage): Decompressing gzipped content."
                )
                try:
                    html_content_bytes = gzip.decompress(html_content_bytes)
                    LOGGER.info(
                        "DisposableMail (Default Homepage): Gzip decompression successful."
                    )
                except Exception as e_gzip:
                    LOGGER.error(
                        f"DisposableMail (Default Homepage): Gzip decompression failed: {e_gzip}. Logging raw bytes snippet."
                    )
                    LOGGER.debug(
                        f"DisposableMail (Default Homepage): Raw gzipped bytes as hex (first 1000 bytes): {home_res.content[:1000].hex()}"
                    )
                    raise ProviderAPIError(
                        "DisposableMail: Failed to decompress gzipped homepage content."
                    )

            html_content = ""
            try:
                html_content = html_content_bytes.decode("utf-8")
                LOGGER.info(
                    "DisposableMail (Default Homepage): Decoded content with UTF-8."
                )
            except UnicodeDecodeError:
                LOGGER.warning(
                    "DisposableMail (Default Homepage): UTF-8 decoding failed, trying latin-1."
                )
                try:
                    html_content = html_content_bytes.decode("latin-1")
                    LOGGER.info(
                        "DisposableMail (Default Homepage): Decoded content with latin-1."
                    )
                except Exception as e_decode_fallback:
                    LOGGER.error(
                        f"DisposableMail (Default Homepage): Fallback decoding failed: {e_decode_fallback}. Logging raw bytes as hex."
                    )
                    LOGGER.debug(
                        f"DisposableMail (Default Homepage): Raw bytes as hex (first 1000 bytes after potential gzip): {html_content_bytes[:1000].hex()}"
                    )
                    html_content = ""

            for term in [
                "captcha",
                "human verification",
                "rate limit",
                "blocked",
                "are you a robot",
                "verify you are human",
                "robot check",
            ]:
                if html_content and term in html_content.lower():
                    LOGGER.error(
                        f"DisposableMail (Default Homepage): Detected possible '{term}' page. Full HTML (or as much as decoded):\n{html_content}"
                    )
                    raise ProviderAPIError(
                        f"DisposableMail: Provider served a '{term}' page, cannot proceed."
                    )

            phpsessid_cookie_str = None
            for cookie_obj in sess.cookies:
                if (
                    cookie_obj.name == "PHPSESSID"
                    and "disposablemail.com" in cookie_obj.domain
                ):
                    phpsessid_cookie_str = f"PHPSESSID={cookie_obj.value}"
                    break

            LOGGER.info(
                f"DisposableMail (Default): PHPSESSID cookie string from session: {phpsessid_cookie_str}"
            )
            if not phpsessid_cookie_str:
                raise ProviderAPIError(
                    "DisposableMail: Failed to retrieve PHPSESSID cookie from session after homepage GET."
                )

            csrf_regex = r'CSRF\s*=\s*["\']([a-zA-Z0-9_.\-]+)["\']'
            csrf_match = re.search(csrf_regex, html_content)
            if not csrf_match:
                LOGGER.error(
                    f"DisposableMail: CSRF token not found. Full HTML received (after potential decoding):\n{html_content}"
                )
                raise ProviderAPIError(
                    "DisposableMail: Failed to retrieve CSRF token. Page content may have changed or CAPTCHA present."
                )
            csrf_token = csrf_match.group(1)
            LOGGER.info(f"DisposableMail (Default): CSRF token found: {csrf_token}")

            await asyncio.sleep(random.uniform(0.5, 1.2))

            inbox_headers = DEFAULT_XHR_HEADERS.copy()
            inbox_headers["Cookie"] = phpsessid_cookie_str

            LOGGER.info(
                f"DisposableMail (Default): Requesting index/index with CSRF: {csrf_token}, headers: {inbox_headers}"
            )
            LOGGER.debug(
                f"DisposableMail (Default): Session cookies BEFORE index/index GET: {sess.cookies.get_dict()}"
            )
            inbox_res = await asyncio.to_thread(
                sess.get,
                f"{DISPOSABLEMAIL_BASE_URL}/index/index?csrf_token={csrf_token}",
                headers=inbox_headers,
                timeout=20,
            )
            LOGGER.info(
                f"DisposableMail (Default): index/index response status: {inbox_res.status_code}, text: {inbox_res.text[:200]}"
            )
            LOGGER.debug(
                f"DisposableMail (Default): Session cookies AFTER index/index GET: {sess.cookies.get_dict()}"
            )
            inbox_res.raise_for_status()
            inbox_data = inbox_res.json()

            email_address = inbox_data.get("email")

            if not email_address:
                raise ProviderAPIError(
                    "DisposableMail: Failed to generate random email address from index/index."
                )

            tma_cookie_from_session = None
            for cookie_obj in sess.cookies:
                if (
                    cookie_obj.name == "TMA"
                    and "disposablemail.com" in cookie_obj.domain
                ):
                    tma_cookie_from_session = f"TMA={cookie_obj.value}"
                    break

            provider_data = {
                "type": "default",
                "email": email_address,
                "password": inbox_data.get("heslo"),
                "tma_cookie_value": tma_cookie_from_session
                or f"TMA={url_quote(email_address)}",
                "session_cookies": sess.cookies.get_dict(),
            }
        except requests.RequestException as e:
            raise ProviderNetworkError(
                f"DisposableMail (default): Network error: {e}"
            ) from e
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
            raise ProviderAPIError(
                f"DisposableMail (default): API response error: {e}"
            ) from e

    return f"biar-{uuid.uuid4()}", email_address, provider_data


async def fetch_disposablemail_messages(
    provider_data: Dict[str, Any],
    active_sessions_ref: Dict[str, Any],
    save_sessions_func: callable,
) -> List[Dict[str, Any]]:
    sess = make_requests_session(timeout=20)
    all_provider_messages = []

    if "session_cookies" in provider_data:
        sess.cookies.update(provider_data["session_cookies"])
        LOGGER.debug(
            f"DisposableMail (Fetch): Restored session cookies: {sess.cookies.get_dict()}"
        )

    api_session_id = provider_data.get("api_session_id")
    if not api_session_id or api_session_id not in active_sessions_ref:
        LOGGER.error(
            "DisposableMail: API session context (api_session_id) missing in provider_data."
        )
        raise ProviderAPIError(
            "DisposableMail: Cannot fetch messages, API session context lost."
        )

    session_info = active_sessions_ref.get(api_session_id)
    if not session_info:
        LOGGER.error(f"DisposableMail: Active session {api_session_id} not found.")
        raise ProviderAPIError(
            "DisposableMail: Cannot fetch messages, API session context lost."
        )

    current_email_address = session_info.get("email_address")
    if not current_email_address:
        LOGGER.error(
            f"DisposableMail: Email address not found in session {api_session_id}."
        )
        raise ProviderAPIError(
            "DisposableMail: Email address not found in session for fetching messages."
        )

    tma_cookie_for_request = provider_data.get("tma_cookie_value")
    if not tma_cookie_for_request:
        tma_cookie_for_request = f"TMA={url_quote(current_email_address)}"
        LOGGER.warning(
            f"DisposableMail: tma_cookie_value not in provider_data for fetch, constructing from email: {tma_cookie_for_request}"
        )

    try:
        summary_fetch_headers = DEFAULT_XHR_HEADERS.copy()
        summary_fetch_headers["Cookie"] = tma_cookie_for_request

        LOGGER.info(
            f"DisposableMail: Fetching message summaries for {current_email_address} with headers: {summary_fetch_headers}"
        )
        LOGGER.debug(
            f"DisposableMail: Session cookies BEFORE summaries fetch: {sess.cookies.get_dict()}"
        )
        summary_res = await asyncio.to_thread(
            sess.get,
            f"{DISPOSABLEMAIL_BASE_URL}/index/refresh",
            headers=summary_fetch_headers,
            timeout=20,
        )
        LOGGER.info(
            f"DisposableMail: Summaries response status: {summary_res.status_code}, text: {summary_res.text[:200]}"
        )
        LOGGER.debug(
            f"DisposableMail: Session cookies AFTER summaries fetch: {sess.cookies.get_dict()}"
        )
        summary_res.raise_for_status()
        message_summaries = summary_res.json()
        LOGGER.debug(
            f"DisposableMail: Received summaries from provider: {message_summaries}"
        )

        if isinstance(message_summaries, list):
            for m_summary_content in message_summaries:
                if not isinstance(m_summary_content, dict):
                    LOGGER.warning(
                        f"DisposableMail: Encountered non-dict item in message summaries: {m_summary_content}"
                    )
                    continue

                provider_internal_id = m_summary_content.get("id")
                mail_from_raw = m_summary_content.get("od")
                mail_subject_raw = m_summary_content.get("predmet")
                mail_date_raw = m_summary_content.get("kdy")

                message_id_to_use: str
                if provider_internal_id is not None:
                    message_id_to_use = str(provider_internal_id)
                else:
                    LOGGER.warning(
                        f"DisposableMail: Provider's 'id' field is missing for a message summary. "
                        f"From: '{mail_from_raw}', Subject: '{mail_subject_raw}', Date: '{mail_date_raw}'. "
                        f"Generating fallback hashed ID."
                    )
                    content_to_hash = (
                        f"{mail_from_raw if mail_from_raw is not None else ''}|"
                        f"{mail_subject_raw if mail_subject_raw is not None else ''}|"
                        f"{mail_date_raw if mail_date_raw is not None else ''}|"
                        f"{m_summary_content.get('predmetZkraceny', '')[:50]}"
                    )
                    message_id_to_use = hashlib.md5(
                        content_to_hash.encode("utf-8")
                    ).hexdigest()

                if not mail_from_raw:
                    LOGGER.info(
                        f"DisposableMail msg (ID {message_id_to_use}): 'od' (from) is missing or empty."
                    )
                if not mail_subject_raw:
                    LOGGER.info(
                        f"DisposableMail msg (ID {message_id_to_use}): 'predmet' (subject) is missing or empty."
                    )
                if not mail_date_raw:
                    LOGGER.info(
                        f"DisposableMail msg (ID {message_id_to_use}): 'kdy' (date) is missing or empty."
                    )

                email_body_text = ""
                email_html_text = None

                if message_id_to_use:
                    LOGGER.info(
                        f"DisposableMail: Attempting to download full EML content for message ID {message_id_to_use}"
                    )
                    try:
                        download_url = f"{DISPOSABLEMAIL_BASE_URL}/download-email/{message_id_to_use}"
                        download_headers = (
                            summary_fetch_headers.copy()
                        )  # Re-use relevant headers

                        LOGGER.debug(
                            f"DisposableMail: Session cookies BEFORE EML download for ID {message_id_to_use}: {sess.cookies.get_dict()}"
                        )
                        eml_content_res = await asyncio.to_thread(
                            sess.get, download_url, headers=download_headers, timeout=25
                        )
                        LOGGER.info(
                            f"DisposableMail: Download EML response status for ID {message_id_to_use}: {eml_content_res.status_code}"
                        )
                        LOGGER.debug(
                            f"DisposableMail: Session cookies AFTER EML download for ID {message_id_to_use}: {sess.cookies.get_dict()}"
                        )
                        eml_content_res.raise_for_status()

                        raw_eml_text = (
                            eml_content_res.text
                        )  # Assume it's text-based EML
                        parsed_eml: EmailMessageClass = message_from_string(
                            raw_eml_text
                        )

                        if parsed_eml.is_multipart():
                            for part in parsed_eml.walk():
                                content_type = part.get_content_type()
                                content_disposition = str(
                                    part.get("Content-Disposition")
                                )
                                charset = part.get_content_charset() or "utf-8"

                                if "attachment" not in content_disposition:
                                    if (
                                        content_type == "text/plain"
                                        and not email_body_text
                                    ):
                                        try:
                                            email_body_text = part.get_payload(
                                                decode=True
                                            ).decode(charset, "replace")
                                        except Exception as e_decode:
                                            LOGGER.warning(
                                                f"DisposableMail: Error decoding text part for msg {message_id_to_use}: {e_decode}"
                                            )
                                            email_body_text = part.get_payload(
                                                decode=False
                                            )
                                    elif (
                                        content_type == "text/html"
                                        and not email_html_text
                                    ):
                                        try:
                                            email_html_text = part.get_payload(
                                                decode=True
                                            ).decode(charset, "replace")
                                        except Exception as e_decode:
                                            LOGGER.warning(
                                                f"DisposableMail: Error decoding HTML part for msg {message_id_to_use}: {e_decode}"
                                            )
                                            email_html_text = part.get_payload(
                                                decode=False
                                            )
                        else:
                            content_type = parsed_eml.get_content_type()
                            charset = parsed_eml.get_content_charset() or "utf-8"
                            payload_bytes = parsed_eml.get_payload(
                                decode=True
                            )  # Get bytes first
                            try:
                                decoded_payload = payload_bytes.decode(
                                    charset, "replace"
                                )
                            except Exception as e_decode:
                                LOGGER.warning(
                                    f"DisposableMail: Error decoding non-multipart payload for msg {message_id_to_use} with charset {charset}: {e_decode}"
                                )
                                try:  # Try with latin-1 as fallback
                                    decoded_payload = payload_bytes.decode(
                                        "latin-1", "replace"
                                    )
                                    LOGGER.info(
                                        f"DisposableMail: Successfully decoded non-multipart payload with latin-1 for msg {message_id_to_use}"
                                    )
                                except:
                                    decoded_payload = parsed_eml.get_payload(
                                        decode=False
                                    )  # Last resort

                            if content_type == "text/html":
                                email_html_text = decoded_payload
                                if not email_body_text:
                                    clean_text = re.sub(r"<[^>]+>", "", decoded_payload)
                                    email_body_text = re.sub(
                                        r"\s+", " ", clean_text
                                    ).strip()

                            elif content_type == "text/plain":
                                email_body_text = decoded_payload
                            else:
                                email_body_text = decoded_payload

                        LOGGER.info(
                            f"DisposableMail: Processed EML for message ID {message_id_to_use}. Body found: {bool(email_body_text)}, HTML found: {bool(email_html_text)}"
                        )

                    except requests.RequestException as download_e:
                        LOGGER.warning(
                            f"DisposableMail: Failed to download EML content for message ID {message_id_to_use}: {download_e}"
                        )
                    except Exception as generic_download_e:
                        LOGGER.error(
                            f"DisposableMail: Unexpected error downloading/parsing EML for message ID {message_id_to_use}: {generic_download_e}",
                            exc_info=True,
                        )

                formatted_message = {
                    "id": message_id_to_use,
                    "from": mail_from_raw,
                    "subject": mail_subject_raw,
                    "date": _format_timestamp_iso(mail_date_raw),
                    "body": email_body_text.strip() if email_body_text else "",
                    "html": email_html_text,
                    "raw": m_summary_content,
                }
                all_provider_messages.append(formatted_message)

        elif isinstance(message_summaries, dict) and message_summaries.get("error"):
            LOGGER.warning(
                f"DisposableMail: Provider API error fetching message summaries: {message_summaries.get('error')}"
            )
        else:
            LOGGER.warning(
                f"DisposableMail: Unexpected data format received for message summaries: {type(message_summaries)}"
            )

    except requests.RequestException as e:
        LOGGER.error(
            f"DisposableMail: Network error during message processing: {e}",
            exc_info=True,
        )
        raise ProviderNetworkError(
            f"DisposableMail: Network error during message processing: {e}"
        ) from e
    except json.JSONDecodeError as e:
        LOGGER.error(
            f"DisposableMail: JSON decoding error during message processing: {e}. Response text: {summary_res.text if 'summary_res' in locals() else 'N/A'}",
            exc_info=True,
        )
        raise ProviderAPIError(
            f"DisposableMail: API response JSON error during message processing: {e}"
        ) from e
    except Exception as e:
        LOGGER.error(
            f"DisposableMail: Unexpected error fetching messages: {e}", exc_info=True
        )
        raise ProviderAPIError(
            f"DisposableMail: Unexpected error fetching messages: {e}"
        ) from e

    return all_provider_messages
