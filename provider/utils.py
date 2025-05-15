import logging
import random
import string
import re
from datetime import datetime, timezone, timedelta
from typing import Optional, Union, Any, Dict, List

import requests

LOGGER = logging.getLogger("provider_utils")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="[%X]",
)


class BaseProviderError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class ProviderNetworkError(BaseProviderError):
    def __init__(
        self, message: str = "A network error occurred with the email provider."
    ):
        super().__init__(message, status_code=503)


class ProviderAPIError(BaseProviderError):
    def __init__(
        self,
        message: str = "The email provider's API returned an error or unexpected response.",
    ):
        super().__init__(message, status_code=502)


def _rand_string(n: int = 10) -> str:
    return "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(n)
    )


def _format_timestamp_iso(
    timestamp_input: Optional[Union[str, int, float]],
) -> Optional[str]:
    if timestamp_input is None:
        return None
    if isinstance(timestamp_input, str) and not timestamp_input.strip():
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
        match = re.match(
            r"(\d+)\s+(sec|min|hour|day)s?\.\s+ago", timestamp_input, re.IGNORECASE
        )
        if match:
            value = int(match.group(1))
            unit = match.group(2).lower()
            now = datetime.now(timezone.utc)
            if unit == "sec":
                dt_obj = now - timedelta(seconds=value)
            elif unit == "min":
                dt_obj = now - timedelta(minutes=value)
            elif unit == "hour":
                dt_obj = now - timedelta(hours=value)
            elif unit == "day":
                dt_obj = now - timedelta(days=value)

        if not dt_obj:
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

        if dt_obj is None and not match:
            try:
                from dateutil import parser

                dt_obj = parser.parse(timestamp_input)
            except ImportError:
                LOGGER.warning(
                    f"dateutil not installed, could not parse: {timestamp_input}. Returning as is."
                )
                return timestamp_input
            except Exception as e_du:
                LOGGER.warning(
                    f"Could not parse with dateutil: {timestamp_input} - {e_du}. Returning as is."
                )
                return timestamp_input
    else:
        LOGGER.warning(
            f"Unsupported timestamp type: {type(timestamp_input)}, value: {timestamp_input}. Returning as is."
        )
        return str(timestamp_input)

    if dt_obj:
        if dt_obj.tzinfo is None or dt_obj.tzinfo.utcoffset(dt_obj) is None:
            dt_obj = dt_obj.replace(tzinfo=timezone.utc)
        else:
            dt_obj = dt_obj.astimezone(timezone.utc)
        return dt_obj.isoformat()

    LOGGER.warning(
        f"Failed to format timestamp after parsing attempts: {timestamp_input}. Returning as is."
    )
    return str(timestamp_input)


def make_requests_session(timeout: int = 15) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": "TempMailAPI/1.0 (Python Requests)"})
    return session
