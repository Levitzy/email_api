import asyncio
import json
import uuid
import re
from urllib.parse import quote as url_quote, unquote as url_unquote
from email.utils import parseaddr
from email import message_from_string
from email.message import Message as EmailMessageClass  # Alias to avoid conflict
from typing import Any, Dict, List, Tuple, Optional

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
DISPOSABLEMAIL_DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
    "Accept-Encoding": "gzip, deflate, br, zstd",
}


async def setup_disposablemail(
    custom_name: Optional[str] = None, **kwargs
) -> Tuple[str, str, Dict[str, Any]]:
    sess = make_requests_session()
    provider_data = {}
    email_address = ""

    if custom_name:
        try:
            check_headers = DISPOSABLEMAIL_DEFAULT_HEADERS.copy()
            check_headers.update(
                {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                    "Origin": DISPOSABLEMAIL_BASE_URL,
                }
            )
            check_payload = {"email": custom_name, "format": "json"}
            check_res = await asyncio.to_thread(
                sess.post,
                f"{DISPOSABLEMAIL_BASE_URL}/index/email-check/",
                data=check_payload,
                headers=check_headers,
                timeout=15,
            )
            check_res.raise_for_status()
            if check_res.text != "ok":
                raise ProviderAPIError(
                    f"DisposableMail: Custom email name '{custom_name}' not available or invalid format. Response: {check_res.text}"
                )

            create_headers = check_headers
            create_payload = {"emailInput": custom_name, "format": "json"}
            create_res = await asyncio.to_thread(
                sess.post,
                f"{DISPOSABLEMAIL_BASE_URL}/index/new-email/",
                data=create_payload,
                headers=create_headers,
                timeout=15,
            )
            create_res.raise_for_status()

            tma_cookie_str = None
            if "set-cookie" in create_res.headers:
                cookies_header = create_res.headers["set-cookie"]
                # Handle cases where cookies are comma-separated or multiple headers
                if isinstance(cookies_header, str):
                    cookies = cookies_header.split(", ")
                    for cookie_part in cookies:
                        if cookie_part.strip().startswith("TMA="):
                            tma_cookie_str = cookie_part.split(";")[0]
                            break
                elif isinstance(
                    cookies_header, list
                ):  # Should not happen with requests.Response.headers
                    for c_header in cookies_header:
                        cookies = c_header.split(", ")
                        for cookie_part in cookies:
                            if cookie_part.strip().startswith("TMA="):
                                tma_cookie_str = cookie_part.split(";")[0]
                                break
                        if tma_cookie_str:
                            break

            if not tma_cookie_str:  # Fallback using session cookies
                raw_cookies = sess.cookies.get_dict(domain="www.disposablemail.com")
                if "TMA" in raw_cookies:
                    tma_cookie_str = f"TMA={raw_cookies['TMA']}"

            if not tma_cookie_str or not tma_cookie_str.startswith("TMA="):
                raise ProviderAPIError(
                    "DisposableMail: Failed to retrieve TMA cookie for custom email."
                )

            email_address_encoded = tma_cookie_str.split("=")[1]
            email_address = url_unquote(email_address_encoded)

            provider_data = {
                "type": "custom",
                "email": email_address,
                "tma_cookie_value": tma_cookie_str,
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
            home_headers = DISPOSABLEMAIL_DEFAULT_HEADERS.copy()
            home_headers.update(
                {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                    "Referer": f"{DISPOSABLEMAIL_BASE_URL}/",
                }
            )
            home_res = await asyncio.to_thread(
                sess.get, DISPOSABLEMAIL_BASE_URL, headers=home_headers, timeout=15
            )
            home_res.raise_for_status()

            phpsessid_cookie_str = None
            raw_cookies_home = sess.cookies.get_dict(domain="www.disposablemail.com")
            if "PHPSESSID" in raw_cookies_home:
                phpsessid_cookie_str = f"PHPSESSID={raw_cookies_home['PHPSESSID']}"
            else:
                all_cookies_from_header = home_res.headers.getlist("Set-Cookie")
                for c_header in all_cookies_from_header:
                    cookies = c_header.split(", ")
                    for cookie_part in cookies:
                        if cookie_part.strip().startswith("PHPSESSID="):
                            phpsessid_cookie_str = cookie_part.split(";")[0]
                            break
                    if phpsessid_cookie_str:
                        break

            if not phpsessid_cookie_str:
                raise ProviderAPIError(
                    "DisposableMail: Failed to retrieve PHPSESSID cookie."
                )

            csrf_match = re.search(r'const CSRF\s*=\s*"(.+?)"', home_res.text)
            if not csrf_match:
                raise ProviderAPIError("DisposableMail: Failed to retrieve CSRF token.")
            csrf_token = csrf_match.group(1)

            inbox_headers = DISPOSABLEMAIL_DEFAULT_HEADERS.copy()
            inbox_headers.update(
                {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": f"{DISPOSABLEMAIL_BASE_URL}/",
                    "Cookie": phpsessid_cookie_str,
                }
            )

            inbox_res = await asyncio.to_thread(
                sess.get,
                f"{DISPOSABLEMAIL_BASE_URL}/index/index?csrf_token={csrf_token}",
                headers=inbox_headers,
                timeout=15,
            )
            inbox_res.raise_for_status()
            inbox_data = inbox_res.json()

            email_address = inbox_data.get("email")
            password = inbox_data.get("heslo")

            if not email_address:
                raise ProviderAPIError(
                    "DisposableMail: Failed to generate random email address."
                )

            provider_data = {
                "type": "default",
                "email": email_address,
                "password": password,
                "phpsessid_cookie_value": phpsessid_cookie_str,
                "csrf_token": csrf_token,
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
    sess = make_requests_session()
    all_provider_messages = []

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

    try:
        tma_cookie_for_request = f"TMA={url_quote(current_email_address)}"

        summary_fetch_headers = DISPOSABLEMAIL_DEFAULT_HEADERS.copy()
        summary_fetch_headers.update(
            {
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"{DISPOSABLEMAIL_BASE_URL}/",
                "Cookie": tma_cookie_for_request,
            }
        )

        LOGGER.info(
            f"DisposableMail: Fetching message summaries for {current_email_address}"
        )
        summary_res = await asyncio.to_thread(
            sess.get,
            f"{DISPOSABLEMAIL_BASE_URL}/index/refresh",
            headers=summary_fetch_headers,
            timeout=15,
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
                        download_headers = summary_fetch_headers.copy()

                        eml_content_res = await asyncio.to_thread(
                            sess.get, download_url, headers=download_headers, timeout=20
                        )
                        eml_content_res.raise_for_status()

                        raw_eml_text = eml_content_res.text
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
                            payload = parsed_eml.get_payload(decode=True)
                            try:
                                decoded_payload = payload.decode(charset, "replace")
                            except Exception as e_decode:
                                LOGGER.warning(
                                    f"DisposableMail: Error decoding non-multipart payload for msg {message_id_to_use}: {e_decode}"
                                )
                                decoded_payload = parsed_eml.get_payload(decode=False)

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
