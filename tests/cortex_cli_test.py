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
Tests for Cortex CLI's commands
"""

import json
import os

from click.testing import CliRunner
from mockito import unstub
from pytest import raises

from cortex_cli.cortex_cli import cortex_cli, DEFAULT_REALM_NAME, DEFAULT_CLIENT_ID
from cortex_cli.auth import ClientAuthenticationError, Credentials, login_request
from tests.conftest import prepare_tokens

# CLI TESTS
def test_no_command():
    result = CliRunner().invoke(cortex_cli)
    assert result.exit_code == 0
    assert 'Usage: cortex' in result.output
    assert 'Interact with an IQM quantum computer with Cortex CLI' in result.output

def test_init(config_dict):
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cortex_cli,
            ['init',
            '--config-path', 'config.json',
            '--tokens-path', config_dict['tokens_path'],
            '--url', config_dict['url'],
            '--realm', config_dict['realm'],
            '--client-id', config_dict['client_id'],
            '--username', config_dict['username']
            ])
        assert result.exit_code == 0
        assert 'Cortex CLI initialized successfully' in result.output
        with open('config.json', 'r', encoding='utf-8') as config_file:
            loaded_config = json.load(config_file)
            assert loaded_config == config_dict

def test_auth_status_not_running():
    result = CliRunner().invoke(cortex_cli, ['auth', 'status'])
    assert result.exit_code == 0
    assert 'Token manager: NOT RUNNING' in result.output

def test_auth_login_and_status(credentials):
    expected_tokens = prepare_tokens(300, 3600, **credentials)
    runner = CliRunner()

    with runner.isolated_filesystem():
        config_json = json.dumps({
            "url": credentials['auth_server_url'],
            "realm": DEFAULT_REALM_NAME,
            "client_id": DEFAULT_CLIENT_ID,
            "username": credentials['username'],
            "tokens_path": "tokens.json"
        })
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(config_json)

        result = runner.invoke(cortex_cli,
            ['auth', 'login',
            '--config-path', 'config.json',
            '--username', credentials['username'],
            '--password', credentials['password'],
            '--no-refresh', # do not daemonize
            ])

        assert result.exit_code == 0
        with open("tokens.json", 'r', encoding='utf-8') as file:
            tokens = json.loads(file.read())

        assert tokens['access_token'] == expected_tokens['access_token']
        assert tokens['refresh_token'] == expected_tokens['refresh_token']

        result = runner.invoke(cortex_cli,
            ['auth', 'status',
            '--config-path', 'config.json'
            ])
        assert result.exit_code == 0
        assert 'Token manager: NOT RUNNING' in result.output

    unstub()

# def test_auth_logout(credentials, settings_dict):
#     """
#     Tests that calling ``close`` will terminate the session and clear tokens
#     """


# AUTH FUNCTIONS TESTS
def test_login_request(credentials, config_file_path):
    """
    Tests that if the client is initialized with credentials, they are used correctly
    """
    expected_tokens = prepare_tokens(300, 3600, **credentials)
    tokens = login_request(credentials["auth_server_url"], DEFAULT_REALM_NAME, DEFAULT_CLIENT_ID, credentials["username"], credentials["password"])
    assert tokens == expected_tokens
    unstub()

def test_raises_client_authentication_error_if_authentication_fails(credentials):
    """
    Tests that authentication failure raises ClientAuthenticationError
    """
    prepare_tokens(300, 3600, status_code=401, **credentials)
    with raises(ClientAuthenticationError):
        login_request(credentials["auth_server_url"], DEFAULT_REALM_NAME, DEFAULT_CLIENT_ID, credentials["username"], credentials["password"])
    unstub()
