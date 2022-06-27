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

REFRESH_MARGIN_SECONDS = 5

class ClientConfigurationError(RuntimeError):
    """Wrong configuration provided.
    """

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


class Credentials(BaseModel):
    """Credentials and tokens for maintaining a session with the authentication server.
    * Fields ``auth:server_url``, ``username`` and ``password`` are provided by the user.
    * Fields ``access_token`` and ``refresh_token`` are loaded from the authentication server and
      refreshed periodically.
    """
    auth_server_url: str = Field(..., description='Base URL of the authentication server')
    'Base URL of the authentication server'
    username: str = Field(..., description='username for logging in to the server')
    'username for logging in to the server'
    password: str = Field(..., description='password for logging in to the server')
    'password for logging in to the server'
    access_token: Optional[str] = Field(None, description='current access token of the session')
    'current access token of the session'
    refresh_token: Optional[str] = Field(None, description='current refresh token of the session')
    'current refresh token of the session'


def _get_credentials(credentials: dict[str, str]) -> Optional[Credentials]:
    """Try to obtain credentials from arguments

    Args:
        credentials: dict of credentials provided as arguments

    Returns:
        Credentials with token fields cleared, or None if ``auth_server_url`` was not set.
    """
    auth_server_url = credentials.get('auth_server_url')
    username = credentials.get('username')
    password = credentials.get('password')
    if not auth_server_url:
        return None
    if not username or not password:
        raise ClientConfigurationError('Auth server URL is set but no username or password')
    return Credentials(auth_server_url=auth_server_url, username=username, password=password)

def _time_left_seconds(token: str) -> int:
    """Check how much time is left until the token expires.

    Returns:
        Time left on token in seconds.
    """
    _, body, _ = token.split('.', 2)
    # Add padding to adjust body length to a multiple of 4 chars as required by base64 decoding
    body += '=' * (-len(body) % 4)
    exp_time = int(json.loads(b64decode(body)).get('exp', '0'))
    return max(0, exp_time - int(time.time()))

def login_request(url, realm, client_id, username, password) -> dict:
    """Sends login request to the authentication server.

    Raises:
        ClientAuthenticationError: updating the tokens failed

    Returns:
        Tokens dictionary
    """
    data = AuthRequest(
        client_id = client_id,
        grant_type = GrantType.PASSWORD,
        username = username,
        password = password
    )

    request_url = f'{url}/realms/{realm}/protocol/openid-connect/token'
    result = requests.post(request_url, data=data.dict(exclude_none=True))
    if result.status_code != 200:
        raise ClientAuthenticationError(f'Failed to update tokens, {result.text}')
    tokens = result.json()
    return tokens

def refresh_tokens(url, realm, client_id, refresh_token):
    """Update access token and refresh token.

    Uses refresh token to request new tokens from authentication server.

    Raises:
        ClientAuthenticationError: updating the tokens failed
    """
    data = AuthRequest(
        client_id = client_id,
        grant_type=GrantType.REFRESH,
        refresh_token=refresh_token
    )

    request_url = f'{url}/realms/{realm}/protocol/openid-connect/token'
    result = requests.post(request_url, data=data.dict(exclude_none=True))

    if result.status_code != 200:
        raise ClientAuthenticationError(f'Failed to update tokens, {result.text}')
    tokens = result.json()
    return tokens

def logout_request(url, realm, client_id, refresh_token) -> bool:
    """Sends logout request to the authentication server.

    Raises:
        ClientAuthenticationError: updating the tokens failed

    Returns:
        True if logout was successful
    """
    data = AuthRequest(
        client_id = client_id,
        refresh_token = refresh_token
    )
    request_url = f'{url}realms/{realm}/protocol/openid-connect/logout'
    result = requests.post(request_url, data=data.dict(exclude_none=True))
    # pprint(vars(result))
    if result.status_code in (200, 204):
        print('Logged out')
    else:
        raise ClientAuthenticationError(f'Failed to logout, {result.text}')
    return True
