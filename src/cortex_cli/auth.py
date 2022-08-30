# Copyright 2021-2022 IQM client developers
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Authorization and session management for Cortex CLI.
"""

import json
import time
from base64 import b64decode
from enum import Enum
from typing import Optional

import requests
from pydantic import BaseModel, Field

REFRESH_MARGIN_SECONDS = 15
AUTH_REQUESTS_TIMEOUT = 20


class ClientAuthenticationError(RuntimeError):
    """Something went wrong with user authentication.
    """


class GrantType(str, Enum):
    """
    Type of token request.
    """
    PASSWORD = 'password'
    REFRESH = 'refresh_token'


class AuthRequest(BaseModel):
    """Request sent to authentication server for access token and refresh token, or for terminating the session.
    * Token request with grant type ``'password'`` starts a new session in the authentication server.
      It uses fields ``client_id``, ``grant_type``, ``username`` and ``password``.
    * Token request with grant type ``'refresh_token'`` is used for maintaining an existing session.
      It uses field ``client_id``, ``grant_type``, ``refresh_token``.
    * Logout request uses only fields ``client_id`` and ``refresh_token``.
    """
    client_id: str = Field(..., description='name of the client for all request types')
    'name of the client for all request types'
    grant_type: Optional[GrantType] = Field(
        None,
        description="type of token request, in ``{'password', 'refresh_token'}``"
    )
    "type of token request, in ``{'password', 'refresh_token'}``"
    username: Optional[str] = Field(None, description="username for grant type ``'password'``")
    "username for grant type ``'password'``"
    password: Optional[str] = Field(None, description="password for grant type ``'password'``")
    "password for grant type ``'password'``"
    refresh_token: Optional[str] = Field(
        None,
        description="refresh token for grant type ``'refresh_token'`` and logout request")
    "refresh token for grant type ``'refresh_token'`` and logout request"


def login_request(url: str, realm: str, client_id: str, username: str, password: str) -> dict[str, str]:
    """Sends login request to the authentication server.

    Raises:
        ClientAuthenticationError: obtaining the tokens failed

    Returns:
        Tokens dictionary
    """

    data = AuthRequest(
        client_id=client_id,
        grant_type=GrantType.PASSWORD,
        username=username,
        password=password
    )

    request_url = f'{url}/realms/{realm}/protocol/openid-connect/token'
    result = requests.post(request_url, data=data.dict(exclude_none=True), timeout=AUTH_REQUESTS_TIMEOUT)
    if result.status_code != 200:
        raise ClientAuthenticationError(f'Failed to authenticate, {result.text}')
    tokens = result.json()
    return tokens


def refresh_request(url: str, realm: str, client_id: str, refresh_token: str) -> Optional[dict[str, str]]:
    """Sends refresh request to the authentication server.

    Raises:
        ClientAuthenticationError: updating the tokens failed

    Returns:
        Tokens dictionary, or None if refresh_token is expired.
    """

    if not token_is_valid(refresh_token):
        return None

    # Update tokens using existing refresh_token
    data = AuthRequest(
        client_id=client_id,
        grant_type=GrantType.REFRESH,
        refresh_token=refresh_token
    )

    request_url = f'{url}/realms/{realm}/protocol/openid-connect/token'
    result = requests.post(request_url, data=data.dict(exclude_none=True), timeout=AUTH_REQUESTS_TIMEOUT)
    if result.status_code != 200:
        raise ClientAuthenticationError(f'Failed to update tokens, {result.text}')
    tokens = result.json()
    return tokens


def logout_request(url: str, realm: str, client_id: str, refresh_token: str) -> bool:
    """Sends logout request to the authentication server.

    Raises:
        ClientAuthenticationError: updating the tokens failed

    Returns:
        True if logout was successful
    """
    data = AuthRequest(
        client_id=client_id,
        refresh_token=refresh_token
    )
    request_url = f'{url}/realms/{realm}/protocol/openid-connect/logout'
    result = requests.post(request_url, data=data.dict(exclude_none=True), timeout=AUTH_REQUESTS_TIMEOUT)

    if result.status_code != 204:
        raise ClientAuthenticationError(f'Failed to logout, {result.text}')
    return True


def time_left_seconds(token: str) -> int:
    """Check how much time is left until the token expires.

    Returns:
        Time left on token in seconds.
    """
    _, body, _ = token.split('.', 2)
    # Add padding to adjust body length to a multiple of 4 chars as required by base64 decoding
    body += '=' * (-len(body) % 4)
    exp_time = int(json.loads(b64decode(body)).get('exp', '0'))
    return max(0, exp_time - int(time.time()))


def token_is_valid(refresh_token: str) -> bool:
    """Check if token is not about to expire.

    Returns:
        True if token is still valid, False otherwise.
    """
    return time_left_seconds(refresh_token) > REFRESH_MARGIN_SECONDS
