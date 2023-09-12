# Copyright 2021-2023 IQM client developers
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
Mocks server and system calls for testing
"""

from base64 import b64encode
import json
import os
import time
from typing import Optional
from uuid import UUID

from mockito import expect, mock, when
from psutil import Process
import pytest
import requests
from requests import HTTPError

from iqm.cortex_cli import auth
from iqm.cortex_cli.auth import AuthRequest, GrantType
from iqm.cortex_cli.cortex_cli import CLIENT_ID, REALM_NAME

existing_run = UUID('3c3fcda3-e860-46bf-92a4-bcc59fa76ce9')
AUTH_REQUESTS_TIMEOUT = 20


def resources_path():
    """Get path to tests/resources directory from current location"""
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'resources')


@pytest.fixture()
def credentials():
    """Sample credentials for logging in"""
    return {
        'auth_server_url': 'http://example.com',
        'username': 'some_username',
        'password': 'some_password',
    }


@pytest.fixture
def config_dict():
    """Reads and parses config file into a dictionary"""
    config_file = os.path.join(resources_path(), 'config.json')
    with open(config_file, 'r', encoding='utf-8') as file:
        return json.loads(file.read())


@pytest.fixture
def tokens_dict():
    """Reads and parses tokens file into a dictionary"""
    tokens_file = os.path.join(resources_path(), 'tokens.json')
    with open(tokens_file, 'r', encoding='utf-8') as file:
        return json.loads(file.read())


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


def prepare_tokens(
    access_token_lifetime: int,
    refresh_token_lifetime: int,
    previous_refresh_token: Optional[str] = None,
    status_code: int = 200,
    response_data: Optional[dict] = None,
    **credentials,
) -> dict[str, str]:
    """Prepare tokens and set them to be returned for a token request.

    Args:
        access_token_lifetime: seconds from current time to access token expire time
        refresh_token_lifetime: seconds from current time to refresh token expire time
        previous_refresh_token: refresh token to be used in refresh request
        status_code: status code to return for token request
        response_data: data to return for token request if other than the tokens
        credentials: dict containing auth_server_url, username and password

    Returns:
         Prepared tokens as a dict.
    """
    if previous_refresh_token is None:
        request_data = AuthRequest(
            client_id=CLIENT_ID,
            grant_type=GrantType.PASSWORD,
            username=credentials['username'],
            password=credentials['password'],
        )
    else:
        request_data = AuthRequest(
            client_id=CLIENT_ID, grant_type=GrantType.REFRESH, refresh_token=previous_refresh_token
        )

    tokens = {
        'access_token': make_token('Bearer', access_token_lifetime),
        'refresh_token': make_token('Refresh', refresh_token_lifetime),
    }
    if response_data is None:
        response_data = tokens

    when(requests).post(
        f'{credentials["auth_server_url"]}/realms/{REALM_NAME}/protocol/openid-connect/token',
        data=request_data.dict(exclude_none=True),
        timeout=AUTH_REQUESTS_TIMEOUT,
    ).thenReturn(MockJsonResponse(status_code, response_data))

    return tokens


def prepare_auth_server_urls(
    config_dict: dict[str, str], invalid_url: str = 'http://invalid.com', invalid_realm: str = 'invalid'
):
    """Patch requests.get to return correct status for auth server URL checks"""
    valid_url = config_dict['auth_server_url']
    valid_realm = config_dict['realm']
    found = MockJsonResponse(200, {'public_key': 'some-key'})
    not_found = MockJsonResponse(404, {'detail': 'not found'})
    when(requests).get(f'{valid_url}/realms/master', timeout=AUTH_REQUESTS_TIMEOUT).thenReturn(found)
    when(requests).get(f'{valid_url}/realms/{valid_realm}', timeout=AUTH_REQUESTS_TIMEOUT).thenReturn(found)
    when(requests).get(f'{valid_url}/realms/{invalid_realm}', timeout=AUTH_REQUESTS_TIMEOUT).thenReturn(not_found)
    when(requests).get(f'{invalid_url}/realms/master', timeout=AUTH_REQUESTS_TIMEOUT).thenReturn(not_found)
    when(requests).get(f'{invalid_url}/realms/{valid_realm}', timeout=AUTH_REQUESTS_TIMEOUT).thenReturn(not_found)
    when(requests).get(f'{invalid_url}/realms/{invalid_realm}', timeout=AUTH_REQUESTS_TIMEOUT).thenReturn(not_found)


def expect_logout(auth_server_url: str, realm: str, client_id: str, refresh_token: str, status_code: int = 204):
    """Prepare for logout request.

    Args:
        auth_server_url: base URL of the authentication server
        realm: realm name on the authentication server
        client_id: cliend ID on the authentication srver
        refresh_token: refresh token to be used in the request
    """
    request_data = AuthRequest(client_id=client_id, refresh_token=refresh_token)
    expect(requests, times=1).post(
        f'{auth_server_url}/realms/{realm}/protocol/openid-connect/logout',
        data=request_data.dict(exclude_none=True),
        timeout=AUTH_REQUESTS_TIMEOUT,
    ).thenReturn(mock({'status_code': status_code, 'text': '{}'}))


def expect_token_is_valid(token: str, result: bool = True):
    """
    Prepare for token_is_valid call
    """
    when(auth).token_is_valid(token).thenReturn(result)


def expect_process_terminate():
    """
    Prepare for Process(pid).terminate call
    """
    when(Process).terminate().thenReturn(None)
