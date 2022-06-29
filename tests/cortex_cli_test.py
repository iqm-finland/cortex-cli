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
from cortex_cli.auth import ClientAuthenticationError, Credentials, login_request, logout_request, refresh_request
from tests.conftest import prepare_tokens, expect_logout, expect_refresh

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
            '--client-id', config_dict['client_id']
            ])
        assert result.exit_code == 0
        assert 'Cortex CLI initialized successfully' in result.output
        with open('config.json', 'r', encoding='utf-8') as config_file:
            loaded_config = json.load(config_file)
            assert loaded_config == config_dict

def test_auth_status_no_tokens_file():
    result = CliRunner().invoke(cortex_cli, ['auth', 'status'])
    assert result.exit_code == 0
    assert 'Tokens file not found' in result.output

def test_auth_login_and_status(config_dict, credentials):
    expected_tokens = prepare_tokens(300, 3600, **credentials)
    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

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

def test_auth_logout_no_tokens_file(config_dict, credentials):
    """
    Tests that calling ``close`` will terminate the session and clear tokens
    """
    expected_tokens = prepare_tokens(300, 3600, **credentials)
    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

        result = runner.invoke(cortex_cli,
            ['auth', 'logout',
            '--config-path', 'config.json'
            ])
        assert result.exit_code != 0
        assert 'Error: File'
        assert 'not found' in result.output

    unstub()

def test_auth_logout_no_pid_keep_tokens(config_dict, credentials):
    """
    Tests that calling ``close`` will terminate the session and clear tokens
    """
    expected_tokens = prepare_tokens(300, 3600, **credentials)
    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

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
            ['auth', 'logout',
            '--config-path', 'config.json',
            '--keep-tokens'
            ])
        assert result.exit_code == 0
        assert 'No PID found in tokens file' in result.output

        # tokens file left unchanged
        with open("tokens.json", 'r', encoding='utf-8') as file:
            tokens = json.loads(file.read())
        assert tokens['access_token'] == expected_tokens['access_token']
        assert tokens['refresh_token'] == expected_tokens['refresh_token']

    unstub()

def test_auth_logout_no_pid_delete_tokens(config_dict, credentials):
    """
    Tests that calling ``close`` will terminate the session and clear tokens
    """
    expected_tokens = prepare_tokens(300, 3600, **credentials)
    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

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

        expect_logout(credentials['auth_server_url'], config_dict['realm'], config_dict['client_id'], tokens['refresh_token'])
        result = runner.invoke(cortex_cli,
            ['auth', 'logout',
            '--config-path', 'config.json',
            '--force'
            ])
        assert result.exit_code == 0
        assert 'Logged out successfully' in result.output

        # tokens file deleted
        with raises(FileNotFoundError):
            open("tokens.json", 'r', encoding='utf-8')

    unstub()

# AUTH FUNCTIONS TESTS
def test_login_request(credentials):
    """
    Tests that if the client is initialized with credentials, they are used correctly
    """
    expected_tokens = prepare_tokens(300, 3600, **credentials)
    tokens = login_request(credentials["auth_server_url"], DEFAULT_REALM_NAME, DEFAULT_CLIENT_ID, credentials["username"], credentials["password"])
    assert tokens == expected_tokens
    unstub()

def test_refresh_request(config_dict, credentials):
    """
    Tests that if the client is initialized with credentials, they are used correctly
    """
    tokens = prepare_tokens(300, 3600, **credentials)
    expected_tokens = expect_refresh(credentials['auth_server_url'], config_dict['realm'], config_dict['client_id'], tokens['refresh_token'])
    result = refresh_request(credentials["auth_server_url"], config_dict['realm'], config_dict['client_id'], tokens['refresh_token'])
    assert result == expected_tokens
    unstub()


def test_logout_request(config_dict, credentials):
    """
    Tests that if the client is initialized with credentials, they are used correctly
    """
    tokens = prepare_tokens(300, 3600, **credentials)
    expect_logout(credentials['auth_server_url'], config_dict['realm'], config_dict['client_id'], tokens['refresh_token'])
    result = logout_request(credentials["auth_server_url"], config_dict['realm'], config_dict['client_id'], tokens['refresh_token'])
    assert result == True
    unstub()


def test_raises_client_authentication_error_if_authentication_fails(credentials):
    """
    Tests that authentication failure raises ClientAuthenticationError
    """
    prepare_tokens(300, 3600, status_code=401, **credentials)
    with raises(ClientAuthenticationError):
        login_request(credentials["auth_server_url"], DEFAULT_REALM_NAME, DEFAULT_CLIENT_ID, credentials["username"], credentials["password"])
    unstub()
