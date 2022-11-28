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
Mocks server and system calls for testing
"""

from base64 import b64encode
import json
import os
import time
from typing import Optional
from unittest import mock as umock
from uuid import UUID

from mockito import expect, mock, when
from psutil import Process
import pytest
import requests
from requests import HTTPError

from cortex_cli import auth
from cortex_cli.auth import AuthRequest, GrantType
from cortex_cli.cortex_cli import CLIENT_ID, REALM_NAME

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


@pytest.fixture()
def mock_environment_vars_for_backend(credentials):
    """
    Mocks environment variables
    """
    with umock.patch.dict(os.environ, {'IQM_SERVER_URL': credentials['auth_server_url']}):
        yield


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
    **credentials,
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
    when(requests).post(
        f'{credentials["auth_server_url"]}/realms/{REALM_NAME}/protocol/openid-connect/token',
        data=request_data.dict(exclude_none=True),
        timeout=AUTH_REQUESTS_TIMEOUT,
    ).thenReturn(MockJsonResponse(status_code, tokens))

    return tokens


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


def expect_jobs_requests(iqm_server_url, valid_circuit_qasm_result_file=None, calibration_set_id=None):
    """
    Prepare for job submission requests.
    """
    success_submit_result = {'id': str(existing_run)}
    success_submit_response = mock({'status_code': 201, 'text': json.dumps(success_submit_result)})
    when(success_submit_response).json().thenReturn(success_submit_result)
    when(requests).post(f'{iqm_server_url}/jobs', ...).thenReturn(success_submit_response)

    running_result = {'status': 'pending', 'metadata': {'circuits': [], 'shots': 42}}
    running_response = mock({'status_code': 200, 'text': json.dumps(running_result)})
    when(running_response).json().thenReturn(running_result)

    if valid_circuit_qasm_result_file is not None:
        with open(valid_circuit_qasm_result_file, 'r', encoding='utf-8') as file:
            success_get_result = json.loads(file.read())
    else:
        success_get_result = {
            'status': 'ready',
            'measurements': [{'result': [[1, 0, 1, 1, 0], [1, 0, 0, 1, 1], [1, 0, 1, 1, 1], [1, 0, 1, 1, 0]]}],
            'metadata': {'circuits': [], 'shots': 42, 'calibration_set_id': calibration_set_id},
        }
    success_get_response = mock({'status_code': 200, 'text': json.dumps(success_get_result)})
    when(success_get_response).json().thenReturn(success_get_result)

    when(requests).get(f'{iqm_server_url}/jobs/{existing_run}', ...).thenReturn(running_response).thenReturn(
        success_get_response
    )


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
