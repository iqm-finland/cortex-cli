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
Tests for Cortex CLI's auth logic
"""

import json

from click.testing import CliRunner
from mockito import unstub
from pytest import raises
import os

from cortex_cli.auth import (ClientAuthenticationError, login_request,
                             logout_request, refresh_request, token_is_valid)
from cortex_cli.cortex_cli import (DEFAULT_CLIENT_ID, DEFAULT_REALM_NAME,
                                   cortex_cli)
from cortex_cli.token_manager import check_pid
from tests.conftest import expect_logout, expect_refresh, prepare_tokens

def test_token_is_valid(credentials):
    """
    Test that valid refreshed token is recognized as valid.
    """
    tokens = prepare_tokens(300, 3600, **credentials)
    result = token_is_valid(tokens['refresh_token'])
    assert result is True

def test_login_request(credentials):
    """
    Tests that login request receives expected tokens.
    """
    expected_tokens = prepare_tokens(300, 3600, **credentials)

    url = credentials['auth_server_url']
    username = credentials['username']
    password = credentials['password']
    tokens = login_request(url, DEFAULT_REALM_NAME, DEFAULT_CLIENT_ID, username, password)
    assert tokens == expected_tokens
    unstub()

def test_refresh_request(config_dict, credentials):
    """
    Tests that refresh requests receives expected tokens when refresh is possible.
    """
    tokens = prepare_tokens(300, 3600, **credentials)
    url = credentials['auth_server_url']
    realm = config_dict['realm']
    refresh_token = tokens['refresh_token']
    client_id = config_dict['client_id']
    expected_tokens = expect_refresh(url, realm, refresh_token)
    result = refresh_request(url, realm, client_id, refresh_token)
    assert result == expected_tokens
    unstub()


def test_logout_request(config_dict, credentials):
    """
    Tests that logout request succeeds.
    """
    tokens = prepare_tokens(300, 3600, **credentials)
    url = credentials['auth_server_url']
    realm = config_dict['realm']
    client_id = config_dict['client_id']
    refresh_token = tokens['refresh_token']
    expect_logout(url, realm, client_id, refresh_token)
    result = logout_request(url, realm, client_id, refresh_token)
    assert result is True
    unstub()


def test_raises_client_authentication_error_if_login_fails(credentials):
    """
    Tests that authentication failure raises ClientAuthenticationError
    """
    prepare_tokens(300, 3600, status_code=401, **credentials)
    with raises(ClientAuthenticationError):
        url = credentials['auth_server_url']
        username = credentials['username']
        password = credentials['password']
        login_request(url, DEFAULT_REALM_NAME, DEFAULT_CLIENT_ID, username, password)
    unstub()


def test_raises_client_authentication_error_if_refresh_fails(credentials):
    """
    Tests that authentication failure raises ClientAuthenticationError
    """
    url = credentials['auth_server_url']
    tokens = expect_refresh(url, DEFAULT_REALM_NAME, "bad_refresh_token", status_code=401)


    with raises(ClientAuthenticationError):
        refresh_request(url, DEFAULT_REALM_NAME, DEFAULT_CLIENT_ID, "bad_refresh_token")
    unstub()

def test_raises_client_authentication_error_if_logout_fails(credentials):
    """
    Tests that authentication failure raises ClientAuthenticationError
    """
    url = credentials['auth_server_url']
    tokens = expect_logout(url, DEFAULT_REALM_NAME, DEFAULT_CLIENT_ID, "bad_refresh_token", status_code=401)


    with raises(ClientAuthenticationError):
        logout_request(url, DEFAULT_REALM_NAME, DEFAULT_CLIENT_ID, "bad_refresh_token")
    unstub()
