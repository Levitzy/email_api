import asyncio
import json
import uuid
import re
import hashlib
from urllib.parse import quote as url_quote, unquote as url_unquote
from email.utils import parseaddr
from email import message_from_string
from email.message import Message as EmailMessageClass
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

DISPOSABLEMAIL_BASE_URL = "https://www.disposablemail.com"
DISPOSABLEMAIL_DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


async def setup_disposablemail(
    custom_name: Optional[str] = None, **kwargs
) -> Tuple[str, str, Dict[str, Any]]:
    """Setup disposablemail session with improved error handling and reliability."""
    sess = make_requests_session()
    sess.headers.update(DISPOSABLEMAIL_DEFAULT_HEADERS)
    provider_data = {}
    email_address = ""

    try:
        if custom_name:
            email_address, provider_data = await _setup_custom_email(sess, custom_name)
        else:
            email_address, provider_data = await _setup_random_email(sess)

        return f"biar-{uuid.uuid4()}", email_address, provider_data

    except requests.RequestException as e:
        error_msg = f"DisposableMail: Network error during setup: {str(e)}"
        LOGGER.error(error_msg)
        raise ProviderNetworkError(error_msg) from e
    except Exception as e:
        error_msg = f"DisposableMail: Unexpected error during setup: {str(e)}"
        LOGGER.error(error_msg, exc_info=True)
        raise ProviderAPIError(error_msg) from e


async def _setup_custom_email(
    sess: requests.Session, custom_name: str
) -> Tuple[str, Dict[str, Any]]:
    """Setup custom email with improved validation and error handling."""
    try:
        # Validate custom name format
        if not re.match(r"^[a-zA-Z0-9._-]+$", custom_name):
            raise ProviderAPIError(
                f"DisposableMail: Custom email name '{custom_name}' contains invalid characters. Use only letters, numbers, dots, hyphens, and underscores."
            )

        # Check email availability
        check_headers = DISPOSABLEMAIL_DEFAULT_HEADERS.copy()
        check_headers.update(
            {
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
                "Origin": DISPOSABLEMAIL_BASE_URL,
                "Referer": f"{DISPOSABLEMAIL_BASE_URL}/",
            }
        )

        check_payload = {"email": custom_name, "format": "json"}

        LOGGER.info(
            f"DisposableMail: Checking availability for custom name: {custom_name}"
        )
        check_res = await asyncio.to_thread(
            sess.post,
            f"{DISPOSABLEMAIL_BASE_URL}/index/email-check/",
            data=check_payload,
            headers=check_headers,
            timeout=20,
        )
        check_res.raise_for_status()

        if check_res.text.strip().lower() != "ok":
            raise ProviderAPIError(
                f"DisposableMail: Custom email name '{custom_name}' is not available. Response: {check_res.text}"
            )

        # Create custom email
        create_payload = {"emailInput": custom_name, "format": "json"}
        create_res = await asyncio.to_thread(
            sess.post,
            f"{DISPOSABLEMAIL_BASE_URL}/index/new-email/",
            data=create_payload,
            headers=check_headers,
            timeout=20,
        )
        create_res.raise_for_status()

        # Extract TMA cookie
        tma_cookie_value = _extract_tma_cookie(sess, create_res)
        if not tma_cookie_value:
            raise ProviderAPIError(
                "DisposableMail: Failed to retrieve TMA cookie for custom email"
            )

        email_address = url_unquote(tma_cookie_value)

        # Validate email format
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email_address):
            raise ProviderAPIError(
                f"DisposableMail: Invalid email format received: {email_address}"
            )

        provider_data = {
            "type": "custom",
            "email": email_address,
            "tma_cookie_value": f"TMA={tma_cookie_value}",
        }

        LOGGER.info(
            f"DisposableMail: Successfully created custom email: {email_address}"
        )
        return email_address, provider_data

    except requests.RequestException as e:
        raise ProviderNetworkError(
            f"DisposableMail (custom): Network error: {e}"
        ) from e
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
        raise ProviderAPIError(
            f"DisposableMail (custom): API response error: {e}"
        ) from e


async def _setup_random_email(sess: requests.Session) -> Tuple[str, Dict[str, Any]]:
    """Setup random email with improved error handling."""
    try:
        # Get homepage and extract session
        home_headers = DISPOSABLEMAIL_DEFAULT_HEADERS.copy()
        home_res = await asyncio.to_thread(
            sess.get, DISPOSABLEMAIL_BASE_URL, headers=home_headers, timeout=20
        )
        home_res.raise_for_status()

        # Extract PHPSESSID cookie
        phpsessid_cookie = _extract_phpsessid_cookie(sess, home_res)
        if not phpsessid_cookie:
            raise ProviderAPIError(
                "DisposableMail: Failed to retrieve PHPSESSID cookie"
            )

        # Extract CSRF token
        csrf_token = _extract_csrf_token(home_res.text)
        if not csrf_token:
            raise ProviderAPIError("DisposableMail: Failed to retrieve CSRF token")

        # Get random email
        inbox_headers = DISPOSABLEMAIL_DEFAULT_HEADERS.copy()
        inbox_headers.update(
            {
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"{DISPOSABLEMAIL_BASE_URL}/",
                "Cookie": phpsessid_cookie,
            }
        )

        LOGGER.info("DisposableMail: Requesting random email address")
        inbox_res = await asyncio.to_thread(
            sess.get,
            f"{DISPOSABLEMAIL_BASE_URL}/index/index?csrf_token={csrf_token}",
            headers=inbox_headers,
            timeout=20,
        )
        inbox_res.raise_for_status()

        try:
            inbox_data = inbox_res.json()
        except json.JSONDecodeError as e:
            LOGGER.error(
                f"DisposableMail: Invalid JSON response: {inbox_res.text[:200]}"
            )
            raise ProviderAPIError(
                f"DisposableMail: Invalid JSON response from server"
            ) from e

        email_address = inbox_data.get("email")
        password = inbox_data.get("heslo")

        if not email_address:
            raise ProviderAPIError(
                "DisposableMail: Failed to generate random email address"
            )

        # Validate email format
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email_address):
            raise ProviderAPIError(
                f"DisposableMail: Invalid email format received: {email_address}"
            )

        provider_data = {
            "type": "default",
            "email": email_address,
            "password": password,
            "phpsessid_cookie_value": phpsessid_cookie,
            "csrf_token": csrf_token,
        }

        LOGGER.info(
            f"DisposableMail: Successfully created random email: {email_address}"
        )
        return email_address, provider_data

    except requests.RequestException as e:
        raise ProviderNetworkError(
            f"DisposableMail (default): Network error: {e}"
        ) from e
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
        raise ProviderAPIError(
            f"DisposableMail (default): API response error: {e}"
        ) from e


def _extract_tma_cookie(
    sess: requests.Session, response: requests.Response
) -> Optional[str]:
    """Extract TMA cookie value with multiple fallback methods."""
    # Method 1: From Set-Cookie header
    set_cookie_header = response.headers.get("set-cookie", "")
    if set_cookie_header:
        for cookie_part in set_cookie_header.split(","):
            cookie_part = cookie_part.strip()
            if cookie_part.startswith("TMA="):
                return cookie_part.split("=")[1].split(";")[0]

    # Method 2: From session cookies
    cookies_dict = sess.cookies.get_dict(domain="www.disposablemail.com")
    if "TMA" in cookies_dict:
        return cookies_dict["TMA"]

    # Method 3: From all session cookies (broader search)
    for cookie in sess.cookies:
        if cookie.name == "TMA":
            return cookie.value

    return None


def _extract_phpsessid_cookie(
    sess: requests.Session, response: requests.Response
) -> Optional[str]:
    """Extract PHPSESSID cookie value with multiple fallback methods."""
    # Method 1: From session cookies
    cookies_dict = sess.cookies.get_dict(domain="www.disposablemail.com")
    if "PHPSESSID" in cookies_dict:
        return f"PHPSESSID={cookies_dict['PHPSESSID']}"

    # Method 2: From Set-Cookie header
    set_cookie_header = response.headers.get("set-cookie", "")
    if set_cookie_header:
        for cookie_part in set_cookie_header.split(","):
            cookie_part = cookie_part.strip()
            if cookie_part.startswith("PHPSESSID="):
                return cookie_part.split(";")[0]

    # Method 3: From all session cookies (broader search)
    for cookie in sess.cookies:
        if cookie.name == "PHPSESSID":
            return f"PHPSESSID={cookie.value}"

    return None


def _extract_csrf_token(html_content: str) -> Optional[str]:
    """Extract CSRF token from HTML content with multiple patterns."""
    patterns = [
        r'const CSRF\s*=\s*["\'](.+?)["\']',
        r'var CSRF\s*=\s*["\'](.+?)["\']',
        r'csrf_token["\']?\s*[:=]\s*["\'](.+?)["\']',
        r'name=["\']csrf_token["\'][^>]*value=["\'](.+?)["\']',
        r'value=["\'](.+?)["\'][^>]*name=["\']csrf_token["\']',
    ]

    for pattern in patterns:
        match = re.search(pattern, html_content, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


async def fetch_disposablemail_messages(
    provider_data: Dict[str, Any],
    active_sessions_ref: Dict[str, Any] = None,
    save_sessions_func: callable = None,
) -> List[Dict[str, Any]]:
    """Fetch messages with improved error handling and parsing."""
    sess = make_requests_session()
    sess.headers.update(DISPOSABLEMAIL_DEFAULT_HEADERS)
    all_provider_messages = []

    # Validate session context
    api_session_id = provider_data.get("api_session_id")
    if not api_session_id or api_session_id not in active_sessions_ref:
        raise ProviderAPIError("DisposableMail: API session context missing or invalid")

    session_info = active_sessions_ref.get(api_session_id)
    if not session_info:
        raise ProviderAPIError("DisposableMail: Active session not found")

    current_email_address = session_info.get("email_address")
    if not current_email_address:
        raise ProviderAPIError("DisposableMail: Email address not found in session")

    try:
        # Prepare request headers and cookies
        tma_cookie = f"TMA={url_quote(current_email_address)}"
        fetch_headers = DISPOSABLEMAIL_DEFAULT_HEADERS.copy()
        fetch_headers.update(
            {
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"{DISPOSABLEMAIL_BASE_URL}/",
                "Cookie": tma_cookie,
            }
        )

        LOGGER.info(f"DisposableMail: Fetching messages for {current_email_address}")

        # Fetch message summaries with retry logic
        message_summaries = await _fetch_with_retry(
            sess, f"{DISPOSABLEMAIL_BASE_URL}/index/refresh", fetch_headers
        )

        if not isinstance(message_summaries, list):
            if isinstance(message_summaries, dict) and message_summaries.get("error"):
                LOGGER.warning(
                    f"DisposableMail: API error: {message_summaries.get('error')}"
                )
                return []
            else:
                LOGGER.warning(
                    f"DisposableMail: Unexpected response format: {type(message_summaries)}"
                )
                return []

        # Process each message
        for msg_summary in message_summaries:
            if not isinstance(msg_summary, dict):
                LOGGER.warning(
                    f"DisposableMail: Invalid message summary format: {msg_summary}"
                )
                continue

            try:
                processed_message = await _process_message_summary(
                    sess, msg_summary, fetch_headers
                )
                if processed_message:
                    all_provider_messages.append(processed_message)
            except Exception as e:
                LOGGER.error(
                    f"DisposableMail: Error processing message: {e}", exc_info=True
                )
                continue

        LOGGER.info(
            f"DisposableMail: Successfully fetched {len(all_provider_messages)} messages"
        )

    except requests.RequestException as e:
        LOGGER.error(f"DisposableMail: Network error: {e}")
        raise ProviderNetworkError(f"DisposableMail: Network error: {e}") from e
    except Exception as e:
        LOGGER.error(f"DisposableMail: Unexpected error: {e}", exc_info=True)
        raise ProviderAPIError(f"DisposableMail: Unexpected error: {e}") from e

    return all_provider_messages


async def _fetch_with_retry(
    sess: requests.Session, url: str, headers: Dict[str, str], max_retries: int = 3
) -> Any:
    """Fetch URL with retry logic."""
    last_error = None

    for attempt in range(max_retries):
        try:
            await asyncio.sleep(0.5 * (attempt + 1))  # Progressive delay

            response = await asyncio.to_thread(
                sess.get, url, headers=headers, timeout=20
            )
            response.raise_for_status()

            return response.json()

        except requests.RequestException as e:
            last_error = e
            LOGGER.warning(f"DisposableMail: Fetch attempt {attempt + 1} failed: {e}")
            if attempt == max_retries - 1:
                break
        except json.JSONDecodeError as e:
            last_error = e
            LOGGER.error(
                f"DisposableMail: Invalid JSON response on attempt {attempt + 1}"
            )
            if attempt == max_retries - 1:
                break

    raise ProviderNetworkError(
        f"DisposableMail: All fetch attempts failed. Last error: {last_error}"
    )


async def _process_message_summary(
    sess: requests.Session, msg_summary: Dict[str, Any], base_headers: Dict[str, str]
) -> Optional[Dict[str, Any]]:
    """Process individual message summary with improved error handling."""
    try:
        # Extract basic message info
        provider_id = msg_summary.get("id")
        mail_from = msg_summary.get("od", "")
        mail_subject = msg_summary.get("predmet", "")
        mail_date = msg_summary.get("kdy", "")

        # Generate message ID
        if provider_id is not None:
            message_id = str(provider_id)
        else:
            # Generate fallback ID based on message content
            content_hash = hashlib.md5(
                f"{mail_from}|{mail_subject}|{mail_date}".encode(
                    "utf-8", errors="ignore"
                )
            ).hexdigest()[:12]
            message_id = f"msg_{content_hash}"
            LOGGER.info(
                f"DisposableMail: Generated fallback ID {message_id} for message without provider ID"
            )

        # Initialize message content
        email_body = ""
        email_html = None

        # Try to fetch full message content
        if provider_id:
            try:
                email_body, email_html = await _fetch_message_content(
                    sess, str(provider_id), base_headers
                )
            except Exception as e:
                LOGGER.warning(
                    f"DisposableMail: Failed to fetch content for message {message_id}: {e}"
                )

        # Format the message
        formatted_message = {
            "id": message_id,
            "from": mail_from if mail_from else None,
            "subject": mail_subject if mail_subject else "(No Subject)",
            "date": _format_timestamp_iso(mail_date),
            "body": email_body.strip() if email_body else "",
            "html": email_html,
            "raw": msg_summary,
        }

        return formatted_message

    except Exception as e:
        LOGGER.error(
            f"DisposableMail: Error processing message summary: {e}", exc_info=True
        )
        return None


async def _fetch_message_content(
    sess: requests.Session, message_id: str, base_headers: Dict[str, str]
) -> Tuple[str, Optional[str]]:
    """Fetch full message content with improved EML parsing."""
    try:
        download_url = f"{DISPOSABLEMAIL_BASE_URL}/download-email/{message_id}"
        download_headers = base_headers.copy()

        response = await asyncio.to_thread(
            sess.get, download_url, headers=download_headers, timeout=25
        )
        response.raise_for_status()

        # Parse EML content
        eml_content = response.text
        if not eml_content.strip():
            LOGGER.warning(
                f"DisposableMail: Empty EML content for message {message_id}"
            )
            return "", None

        return _parse_eml_content(eml_content, message_id)

    except requests.RequestException as e:
        LOGGER.warning(
            f"DisposableMail: Network error fetching message {message_id}: {e}"
        )
        return "", None
    except Exception as e:
        LOGGER.error(
            f"DisposableMail: Error fetching message {message_id}: {e}", exc_info=True
        )
        return "", None


def _parse_eml_content(eml_content: str, message_id: str) -> Tuple[str, Optional[str]]:
    """Parse EML content with robust error handling."""
    try:
        parsed_eml = message_from_string(eml_content)
        email_body = ""
        email_html = None

        if parsed_eml.is_multipart():
            for part in parsed_eml.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # Skip attachments
                if "attachment" in content_disposition.lower():
                    continue

                charset = part.get_content_charset() or "utf-8"

                try:
                    if content_type == "text/plain" and not email_body:
                        payload = part.get_payload(decode=True)
                        if payload:
                            email_body = payload.decode(charset, errors="replace")
                    elif content_type == "text/html" and not email_html:
                        payload = part.get_payload(decode=True)
                        if payload:
                            email_html = payload.decode(charset, errors="replace")
                except Exception as e:
                    LOGGER.warning(
                        f"DisposableMail: Error decoding part for message {message_id}: {e}"
                    )
                    # Try fallback decoding
                    try:
                        payload = part.get_payload(decode=False)
                        if isinstance(payload, str):
                            if content_type == "text/plain" and not email_body:
                                email_body = payload
                            elif content_type == "text/html" and not email_html:
                                email_html = payload
                    except Exception:
                        continue
        else:
            # Single part message
            content_type = parsed_eml.get_content_type()
            charset = parsed_eml.get_content_charset() or "utf-8"

            try:
                payload = parsed_eml.get_payload(decode=True)
                if payload:
                    decoded_payload = payload.decode(charset, errors="replace")
                else:
                    decoded_payload = parsed_eml.get_payload(decode=False)
                    if not isinstance(decoded_payload, str):
                        decoded_payload = str(decoded_payload)

                if content_type == "text/html":
                    email_html = decoded_payload
                    # Extract plain text from HTML as fallback
                    email_body = re.sub(r"<[^>]+>", "", decoded_payload)
                    email_body = re.sub(r"\s+", " ", email_body).strip()
                else:
                    email_body = decoded_payload

            except Exception as e:
                LOGGER.warning(
                    f"DisposableMail: Error decoding single-part message {message_id}: {e}"
                )
                # Fallback to raw payload
                try:
                    email_body = str(parsed_eml.get_payload(decode=False))
                except Exception:
                    email_body = ""

        return email_body, email_html

    except Exception as e:
        LOGGER.error(
            f"DisposableMail: Error parsing EML for message {message_id}: {e}",
            exc_info=True,
        )
        return "", None
