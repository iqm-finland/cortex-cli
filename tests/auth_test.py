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

from mockito import unstub
from pytest import raises

from cortex_cli.auth import (ClientAuthenticationError, login_request,
                             logout_request, refresh_request, token_is_valid)
from tests.conftest import expect_logout, expect_token_is_valid, prepare_tokens


def test_login_request(credentials, config_dict):
    """
    Tests that login request produces expected tokens.
    """
    base_url, realm, client_id = config_dict['base_url'], config_dict['realm'], config_dict['client_id']
    username, password = credentials['username'], credentials['password']
    expected_tokens = prepare_tokens(300, 3600, **credentials)
    tokens = login_request(base_url, realm, client_id, username, password)

    assert tokens == expected_tokens
    unstub()


def test_refresh_request(credentials, config_dict, tokens_dict):
    """
    Tests that refresh request produces expected tokens.
    """
    base_url, realm, client_id = config_dict['base_url'], config_dict['realm'], config_dict['client_id']
    refresh_token = tokens_dict['refresh_token']
    expect_token_is_valid(refresh_token)
    expected_tokens = prepare_tokens(300, 3600, **credentials, previous_refresh_token = refresh_token)
    result = refresh_request(base_url, realm, client_id, refresh_token)

    assert result == expected_tokens
    unstub()


def test_refresh_request_handles_expired_token(config_dict, tokens_dict):
    """
    Tests that refresh request is not made when token is expired.
    """
    base_url, realm, client_id = config_dict['base_url'], config_dict['realm'], config_dict['client_id']
    refresh_token = tokens_dict['refresh_token']
    result = refresh_request(base_url, realm, client_id, refresh_token)

    assert result is None
    unstub()


def test_logout_request(credentials, config_dict):
    """
    Tests that logout request succeeds.
    """
    base_url, realm, client_id = config_dict['base_url'], config_dict['realm'], config_dict['client_id']
    tokens = prepare_tokens(300, 3600, **credentials)
    refresh_token = tokens['refresh_token']
    expect_logout(base_url, realm, client_id, refresh_token)
    result = logout_request(base_url, realm, client_id, refresh_token)

    assert result is True
    unstub()


def test_raises_client_authentication_error_if_login_fails(credentials, config_dict):
    """
    Tests that authentication failure at login raises ClientAuthenticationError.
    """
    base_url, realm, client_id = config_dict['base_url'], config_dict['realm'], config_dict['client_id']
    username, password = credentials['username'], credentials['password']
    prepare_tokens(300, 3600, status_code=401, **credentials)

    with raises(ClientAuthenticationError):
        login_request(base_url, realm, client_id, username, password)
    unstub()


def test_raises_client_authentication_error_if_refresh_fails(credentials, config_dict, tokens_dict):
    """
    Tests that authentication failure at refresh raises ClientAuthenticationError
    """
    base_url, realm, client_id = config_dict['base_url'], config_dict['realm'], config_dict['client_id']
    refresh_token = tokens_dict['refresh_token']
    expect_token_is_valid(refresh_token)
    prepare_tokens(300, 3600, status_code=401, previous_refresh_token = refresh_token, **credentials)

    with raises(ClientAuthenticationError):
        refresh_request(base_url, realm, client_id, refresh_token)
    unstub()


def test_raises_client_authentication_error_if_logout_fails(config_dict, tokens_dict):
    """
    Tests that authentication failure at logout raises ClientAuthenticationError
    """
    base_url, realm, client_id = config_dict['base_url'], config_dict['realm'], config_dict['client_id']
    refresh_token = tokens_dict['refresh_token']
    expect_logout(base_url, realm, client_id, refresh_token, status_code=401)

    with raises(ClientAuthenticationError):
        logout_request(base_url, realm, client_id, refresh_token)
    unstub()


def test_token_is_valid(credentials):
    """
    Test that valid refreshed token is recognized as valid.
    """
    tokens = prepare_tokens(300, 3600, **credentials)
    result = token_is_valid(tokens['refresh_token'])

    assert result is True
    unstub()
