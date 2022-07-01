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
Mocks server calls for testing
"""

import json
import os
import signal
import time
from base64 import b64encode
from typing import Optional

import pytest
import requests
from mockito import expect, mock, when
from requests import HTTPError

from cortex_cli import token_manager
from cortex_cli.auth import AuthRequest, GrantType
from cortex_cli.cortex_cli import DEFAULT_CLIENT_ID, DEFAULT_REALM_NAME


@pytest.fixture()
def credentials():
    """Sample credentials for logging in"""
    return {
        'auth_server_url': 'http://localhost',
        'username': 'some_username',
        'password': 'some_password',
    }

@pytest.fixture
def config_dict():
    """
    Reads and parses config file into a dictionary
    """
    config_path = os.path.dirname(os.path.realpath(__file__)) + '/resources/config.json'
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.loads(f.read())

@pytest.fixture
def tokens_dict():
    tokens_path = os.path.dirname(os.path.realpath(__file__)) + '/resources/tokens.json'
    with open(tokens_path, 'r', encoding='utf-8') as f:
        return json.loads(f.read())

class MockJsonResponse:
    def __init__(self, status_code: int, json_data: dict):
        self.status_code = status_code
        self.json_data = json_data

    @property
    def text(self):
        return json.dumps(self.json_data)

    def json(self):
        return self.json_data

    def raise_for_status(self):
        if 400 <= self.status_code < 600:
            raise HTTPError('')


def prepare_tokens(
        access_token_lifetime: int,
        refresh_token_lifetime: int,
        previous_refresh_token: Optional[str] = None,
        status_code: int = 200,
        **credentials
) -> dict[str, str]:
    """Prepare tokens and set them to be returned for a token request.

    Args:
        access_token_lifetime: seconds from current time to access token expire time
        refresh_token_lifetime: seconds from current time to refresh token expire time
        previous_refresh_token: refresh token to be used in refresh request
        status_code: status code to return for token request
        credentials: dict containing auth_server_url, username and password

    Returns:
         Prepared tokens as a dict.
    """
    if previous_refresh_token is None:
        request_data = AuthRequest(
            client_id=DEFAULT_CLIENT_ID,
            grant_type=GrantType.PASSWORD,
            username=credentials['username'],
            password=credentials['password']
        )
    else:
        request_data = AuthRequest(
            client_id=DEFAULT_CLIENT_ID,
            grant_type=GrantType.REFRESH,
            refresh_token=previous_refresh_token
        )

    tokens = {
        'access_token': make_token('Bearer', access_token_lifetime),
        'refresh_token': make_token('Refresh', refresh_token_lifetime)
    }
    when(requests).post(
        f'{credentials["auth_server_url"]}/realms/{DEFAULT_REALM_NAME}/protocol/openid-connect/token',
        data=request_data.dict(exclude_none=True)
    ).thenReturn(MockJsonResponse(status_code, tokens))

    return tokens


def make_token(token_type: str, lifetime: int) -> str:
    """Encode given token type and expire time as a token.

    Args:
        token_type: 'Bearer' for access tokens, 'Refresh' for refresh tokens
        lifetime: seconds from current time to token's expire time

    Returns:
        Encoded token
    """
    empty = b64encode('{}'.encode('utf-8')).decode('utf-8')
    body = f'{{ "typ": "{token_type}", "exp": {int(time.time()) + lifetime} }}'
    body = b64encode(body.encode('utf-8')).decode('utf-8')
    return f'{empty}.{body}.{empty}'


def expect_refresh(auth_server_url: str, realm: str, refresh_token: str, status_code: int = 200):
    """Prepare for refresh request.

    Args:
        auth_server_url: base URL of the authentication server
        refresh_token: refresh token expected to be used in the request
    """
    request_data = AuthRequest(
            client_id=DEFAULT_CLIENT_ID,
            grant_type=GrantType.REFRESH,
            refresh_token=refresh_token
        )
    tokens = {
        'access_token': make_token('Bearer', 300),
        'refresh_token': make_token('Refresh', 300)
    }
    expect(requests, times=1).post(
        f'{auth_server_url}/realms/{realm}/protocol/openid-connect/token',
        data=request_data.dict(exclude_none=True)
    ).thenReturn(MockJsonResponse(status_code, tokens))
    return tokens

def expect_logout(auth_server_url: str, realm: str, client_id: str, refresh_token: str, status_code: int = 204):
    """Prepare for logout request.

    Args:
        auth_server_url: base URL of the authentication server
        refresh_token: refresh token expected to be used in the request
    """
    request_data = AuthRequest(client_id=client_id, refresh_token=refresh_token)
    expect(requests, times=1).post(
        f'{auth_server_url}/realms/{realm}/protocol/openid-connect/logout',
        data=request_data.dict(exclude_none=True)
    ).thenReturn(
        mock({'status_code': status_code, 'text': '{}'})
    )

def expect_check_pid(pid):
    when(token_manager).check_pid(pid).thenReturn(True)

def expect_kill_by_pid(pid):
    when(token_manager).kill_by_pid(pid).thenReturn(True)

def expect_os_kill_to_succeed(pid):
    when(os).kill(pid, signal.SIGTERM).thenReturn(True)

# write file fail