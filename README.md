```markdown
# Temp Mail API

**A robust FastAPI-based API for generating temporary email addresses and managing inboxes from multiple providers.**

This API allows you to programmatically create disposable email addresses, fetch incoming messages, and manage their history, making it ideal for testing, automation, or any scenario requiring temporary email accounts.

## Table of Contents

*   [Features](#features)
*   [Prerequisites](#prerequisites)
*   [Installation](#installation)
*   [Running the API](#running-the-api)
    *   [Interactive Documentation](#interactive-documentation)
*   [Configuration](#configuration)
*   [Available Providers](#available-providers)
*   [API Endpoints](#api-endpoints)
    *   [General](#general)
        *   [GET /providers](#1-get-providers)
    *   [Email Session Management](#email-session-management)
        *   [GET / POST /gen](#2-get--post-gen)
        *   [POST /sessions](#3-post-sessions)
        *   [GET /sessions/{api\_session\_id}/messages](#4-get-sessionsapi_session_idmessages)
        *   [DELETE /sessions/{api\_session\_id}](#5-delete-sessionsapi_session_id)
    *   [Message History](#message-history)
        *   [GET /history](#6-get-history)
        *   [POST /history/export](#7-post-historyexport)
        *   [DELETE /history](#8-delete-history)
    *   [API Configuration](#api-configuration)
        *   [GET /config](#9-get-config)
        *   [PATCH /config](#10-patch-config)
*   [Error Handling](#error-handling)
*   [Disclaimer](#disclaimer)

## Features

*   **Multiple Provider Support:** Generate emails from various temporary email services.
*   **Flexible Email Generation:**
    *   Choose a specific provider.
    *   Select a random provider.
    *   Use a configurable default provider.
*   **Inbox Management:** Fetch new messages from generated email addresses.
*   **Message History:**
    *   Optionally save received messages.
    *   View message history with pagination.
    *   Export history to a JSON file.
    *   Clear message history.
*   **API Configuration:** Customize default provider, history limits, and message saving behavior.
*   **Asynchronous Operations:** Built with FastAPI and `asyncio` for non-blocking I/O.
*   **Automatic Documentation:** Interactive API documentation (Swagger UI & ReDoc) out-of-the-box.

## Prerequisites

*   Python 3.7+
*   pip (Python package installer)

## Installation

1.  **Clone the Repository (or save `main.py`):**
    If you have the project in a Git repository:
    ```bash
    git clone <your-repo-url>
    cd <your-repo-directory>
    ```
    Otherwise, ensure `main.py` is in your working directory.

2.  **Create a `requirements.txt` file:**
    Create a file named `requirements.txt` in your project directory with the following content:
    ```txt
    fastapi
    uvicorn[standard]
    requests
    pydantic
    python-dateutil
    ```

3.  **Install Dependencies:**
    Navigate to your project directory in the terminal and run:
    ```bash
    pip install -r requirements.txt
    ```

## Running the API

To start the API server, use Uvicorn (an ASGI server):

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

*   `main:app`: Refers to the `app` instance in your `main.py` file.
*   `--reload`: Enables auto-reloading on code changes (useful for development).
*   `--host 0.0.0.0`: Makes the API accessible from your local network. Use `127.0.0.1` or `localhost` to restrict access to your machine only.
*   `--port 8000`: Specifies the port the API will listen on.

The API will be accessible at `http://localhost:8000` (or `http://<your-ip>:8000` if using `0.0.0.0`).

### Interactive Documentation

FastAPI provides automatic interactive API documentation. Once the server is running, you can access:

*   **Swagger UI:** `http://localhost:8000/docs`
*   **ReDoc:** `http://localhost:8000/redoc`

These interfaces allow you to explore and test the API endpoints directly from your browser.

## Configuration

The API uses a JSON configuration file located at `~/.config/tempmail-api/config.json`.
If the directory or file doesn't exist, it will be created with default values when the API first needs to access or modify the configuration.

**Default `config.json` structure:**

```json
{
  "default_provider": "mail.tm",
  "max_history_entries": 100,
  "save_messages": true
}
```

*   **`default_provider` (string):** The email provider to use by default for the `/gen` endpoint if no specific provider is requested. Must be one of the keys from the available providers (see `/providers` endpoint).
*   **`max_history_entries` (integer):** The maximum number of messages to store in the `history.json` file. Older entries are pruned when this limit is exceeded.
*   **`save_messages` (boolean):** If `true`, received messages will be saved to `~/.config/tempmail-api/history.json`.

You can modify these settings via the `/config` API endpoint or by editing the `config.json` file directly (requires an API restart if edited manually).

## Available Providers

The API dynamically loads supported email providers. To get the current list of available provider keys, use the `/providers` endpoint. As of the last update, common providers include:

*   `guerrillamail`
*   `mail.tm`
*   `mail.gw`
*   `tempmail.lol`
*   `dropmail.me`

## API Endpoints

Below is a detailed description of the available API endpoints.

---

### General

#### 1. `GET /providers`

*   **Summary:** Lists all available email provider keys that can be used for generating email addresses.
*   **Parameters:** None
*   **Example Request:**
    ```bash
    curl -X GET "http://localhost:8000/providers"
    ```
*   **Example Success Response (200 OK):**
    ```json
    [
      "guerrillamail",
      "mail.tm",
      "mail.gw",
      "tempmail.lol",
      "dropmail.me"
    ]
    ```

---

### Email Session Management

#### 2. `GET / POST /gen`

*   **Summary:** Generates a new temporary email address and creates an API session. This is the recommended endpoint for creating emails due to its flexibility.
*   **HTTP Methods:** `GET`, `POST`
*   **Description:**
    *   If `provider_name` is specified and valid, that provider is used.
    *   If `provider_name` is 'random', a random available provider is chosen.
    *   If `provider_name` is omitted:
        1.  Tries to use the `default_provider` from the API configuration.
        2.  If the default is not set or invalid, a random provider is chosen.
*   **Query Parameters:**
    | Parameter       | Type    | Optional | Default | Description                                                                                                                               |
    |-----------------|---------|----------|---------|-------------------------------------------------------------------------------------------------------------------------------------------|
    | `provider_name` | string  | Yes      | `None`  | Name of the provider (e.g., 'mail.tm'), 'random', or omit for default/random. See `/providers` for available keys.                         |
    | `rush_mode`     | boolean | Yes      | `false` | For `tempmail.lol` provider only: Use "rush mode" for potentially faster (but possibly less stable) address generation.                   |
*   **Example Requests:**
    *   Using default or random provider:
        ```bash
        curl -X GET "http://localhost:8000/gen"
        ```
    *   Using a specific provider (`mail.tm`):
        ```bash
        curl -X POST "http://localhost:8000/gen?provider_name=mail.tm"
        ```
    *   Using `tempmail.lol` with rush mode:
        ```bash
        curl -X GET "http://localhost:8000/gen?provider_name=tempmail.lol&rush_mode=true"
        ```
*   **Example Success Response (201 Created):**
    ```json
    {
      "api_session_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
      "email_address": "user123@tempdomain.com",
      "provider": "mail.tm",
      "created_at": "2024-05-12T08:00:00.123456+00:00",
      "expires_at": "2024-05-12T09:00:00.000000+00:00"
    }
    ```
    *(Note: `expires_at` may be `null` if the provider does not specify an expiration time.)*

#### 3. `POST /sessions`

*   **Summary:** (Legacy) Generates a new temporary email address, requiring a specific provider name.
*   **Description:** This endpoint is kept for backward compatibility. For more flexibility, use `/gen`.
*   **Query Parameters:**
    | Parameter       | Type    | Optional | Default | Description                                                                 |
    |-----------------|---------|----------|---------|-----------------------------------------------------------------------------|
    | `provider_name` | string  | No       |         | Name of the email provider. See `/providers` for available keys.            |
    | `rush_mode`     | boolean | Yes      | `false` | For `tempmail.lol` provider: Use rush mode for faster address generation. |
*   **Example Request:**
    ```bash
    curl -X POST "http://localhost:8000/sessions?provider_name=mail.tm"
    ```
*   **Example Success Response (201 Created):** (Same structure as `/gen` response)

#### 4. `GET /sessions/{api_session_id}/messages`

*   **Summary:** Fetches new, unread messages for a given API session.
*   **Path Parameters:**
    | Parameter        | Type   | Description                                  |
    |------------------|--------|----------------------------------------------|
    | `api_session_id` | string | The unique ID of the API session (from `/gen` or `/sessions`). |
*   **Example Request:**
    ```bash
    curl -X GET "http://localhost:8000/sessions/a1b2c3d4-e5f6-7890-1234-567890abcdef/messages"
    ```
*   **Example Success Response (200 OK):**
    ```json
    [
      {
        "id": "msg_unique_id_123",
        "from": "sender@example.com",
        "to": "user123@tempdomain.com", // May be null for some providers
        "subject": "Welcome Email",
        "date": "2024-05-12T08:05:30+00:00",
        "body": "This is the plain text content of the email...",
        "html": "<p>This is the <b>HTML</b> content of the email...</p>",
        "raw": {
          "provider_specific_field": "value",
          "...": "..."
        }
      }
    ]
    ```
    *(The list will be empty `[]` if no new messages are found.)*

#### 5. `DELETE /sessions/{api_session_id}`

*   **Summary:** Deletes an active email session. This invalidates the `api_session_id` for future message fetching.
*   **Path Parameters:**
    | Parameter        | Type   | Description                                  |
    |------------------|--------|----------------------------------------------|
    | `api_session_id` | string | The unique ID of the API session to delete. |
*   **Example Request:**
    ```bash
    curl -X DELETE "http://localhost:8000/sessions/a1b2c3d4-e5f6-7890-1234-567890abcdef"
    ```
*   **Example Success Response:** `204 No Content` (No response body)

---

### Message History

*(These endpoints interact with `~/.config/tempmail-api/history.json` if `save_messages` is enabled in the config.)*

#### 6. `GET /history`

*   **Summary:** Retrieves saved message history with pagination.
*   **Query Parameters:**
    | Parameter   | Type    | Optional | Default | Description                               |
    |-------------|---------|----------|---------|-------------------------------------------|
    | `page`      | integer | Yes      | `1`     | Page number for pagination (must be >=1). |
    | `page_size` | integer | Yes      | `20`    | Number of entries per page (1-100).       |
*   **Example Request:**
    ```bash
    curl -X GET "http://localhost:8000/history?page=1&page_size=10"
    ```
*   **Example Success Response (200 OK):**
    ```json
    [
      {
        "provider": "mail.tm",
        "address": "user123@tempdomain.com",
        "timestamp": "2024-05-12T08:05:35.789Z", // Timestamp when message was saved to history
        "message": {
          "id": "msg_unique_id_123",
          "from": "sender@example.com",
          "to": "user123@tempdomain.com",
          "subject": "Welcome Email",
          "date": "2024-05-12T08:05:30+00:00", // Original message timestamp
          "body": "This is the plain text content...",
          "html": "<p>This is the HTML content...</p>",
          "raw": { "...": "..." }
        }
      }
      // ... more history entries
    ]
    ```

#### 7. `POST /history/export`

*   **Summary:** Exports the entire message history to a JSON file on the server.
*   **Query Parameters:**
    | Parameter         | Type   | Optional | Default             | Description                                                                |
    |-------------------|--------|----------|---------------------|----------------------------------------------------------------------------|
    | `output_filename` | string | Yes      | `email_export.json` | Filename for the export. Saved in the API's config directory (`~/.config/tempmail-api/`). |
*   **Example Request:**
    ```bash
    curl -X POST "http://localhost:8000/history/export?output_filename=my_email_archive.json"
    ```
*   **Example Success Response (200 OK):**
    ```json
    {
      "message": "Successfully exported history to /home/user/.config/tempmail-api/my_email_archive.json"
    }
    ```

#### 8. `DELETE /history`

*   **Summary:** Clears all saved message history from `history.json`.
*   **Example Request:**
    ```bash
    curl -X DELETE "http://localhost:8000/history"
    ```
*   **Example Success Response (200 OK):**
    ```json
    {
      "message": "Message history cleared successfully."
    }
    ```
    *(If no history exists, the message might be "No message history to clear.")*

---

### API Configuration

#### 9. `GET /config`

*   **Summary:** Retrieves the current API configuration.
*   **Example Request:**
    ```bash
    curl -X GET "http://localhost:8000/config"
    ```
*   **Example Success Response (200 OK):**
    ```json
    {
      "default_provider": "mail.tm",
      "max_history_entries": 100,
      "save_messages": true
    }
    ```

#### 10. `PATCH /config`

*   **Summary:** Updates parts of the API configuration.
*   **Request Body (JSON):** Provide only the fields you want to update.
    ```json
    {
      "default_provider": "tempmail.lol", // Optional
      "max_history_entries": 50,         // Optional, must be > 0
      "save_messages": false             // Optional
    }
    ```
*   **Example Request:**
    ```bash
    curl -X PATCH "http://localhost:8000/config" \
         -H "Content-Type: application/json" \
         -d '{
               "default_provider": "tempmail.lol",
               "max_history_entries": 50
             }'
    ```
*   **Example Success Response (200 OK):** (Returns the full, updated configuration)
    ```json
    {
      "default_provider": "tempmail.lol",
      "max_history_entries": 50,
      "save_messages": true
    }
    ```

## Error Handling

The API uses standard HTTP status codes to indicate the success or failure of a request.

*   **`200 OK`**: Request successful.
*   **`201 Created`**: Resource created successfully (e.g., new email session).
*   **`204 No Content`**: Request successful, no response body needed (e.g., after deleting a session).
*   **`400 Bad Request`**: The request was malformed, such as invalid input parameters or an unsupported provider name.
*   **`404 Not Found`**: The requested resource could not be found (e.g., an invalid `api_session_id` or history file not present).
*   **`422 Unprocessable Entity`**: The request was well-formed but contained semantic errors (e.g., validation errors for request body fields).
*   **`500 Internal Server Error`**: An unexpected error occurred on the server side.
*   **`502 Bad Gateway`**: An error occurred when communicating with the upstream email provider's API (custom `APIError`).
*   **`503 Service Unavailable`**: A network error prevented communication with the upstream email provider (custom `NetworkError`).

Error responses are typically in JSON format with a `detail` field explaining the error:
```json
{
  "detail": "A human-readable error message."
}
```
For validation errors (422), the `detail` field might contain a more structured list of errors.

## Disclaimer

*   This API relies on third-party temporary email services. Their availability and terms of service can change without notice.
*   Temporary email addresses are, by nature, ephemeral and often public. Do not use them for sensitive information or critical account registrations.
*   The API maintainers are not responsible for the content received through these temporary email services or for any misuse of the API.
*   Use this API responsibly and respect the terms of service of the underlying email providers.
```