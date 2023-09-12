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
Tests for Cortex CLI's auth logout command
"""

import json
import os

from click.testing import CliRunner
from mockito import unstub
from psutil import pid_exists
from pytest import raises

from iqm.cortex_cli.cortex_cli import cortex_cli
from tests.conftest import expect_logout, expect_process_terminate, prepare_tokens

# ``cortex auth logout`` supports four possible scenarios:
# 1. If --keep-tokens, and PID is found: kills process, keeps tokens file.
# 2. If --keep-tokens, and PID not found: do nothing.
# 3. If not --keep-tokens, and PID is found: send logout request, kill process, delete tokens file.
# 4. If not --keep-tokens, and PID is not found: send logout request, delete tokens file.

# Logout Scenario 1
def test_auth_logout_handles_keep_tokens_and_pid(config_dict, credentials):
    """
    Tests that ``cortex auth logout --keep-tokens`` handles running PID.
    """
    expected_tokens = prepare_tokens(300, 3600, **credentials)
    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

        # login and save initial tokens.json
        runner.invoke(
            cortex_cli,
            [
                'auth',
                'login',
                '--config-file',
                'config.json',
                '--username',
                credentials['username'],
                '--password',
                credentials['password'],
                '--no-refresh',  # do not start token manager
            ],
        )
        with open('tokens.json', 'r', encoding='utf-8') as file:
            tokens = json.loads(file.read())

        # emulate a running daemon by storing a real PID
        tokens['pid'] = os.getpid()
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens))

        # user runs logout, but does not confirm
        result = runner.invoke(
            cortex_cli,
            [
                'auth',
                'logout',
                '--config-file',
                'config.json',
                '--keep-tokens',
            ],
            input='n',
        )
        assert result.exit_code == 0
        assert 'Logout aborted.' in result.output

        # user runs logout, confirms via --force
        expect_process_terminate()
        result = runner.invoke(
            cortex_cli, ['auth', 'logout', '--config-file', 'config.json', '--keep-tokens', '--force']
        )
        assert result.exit_code == 0
        assert 'Token manager killed' in result.output

        assert pid_exists(tokens['pid'])

        # tokens file kept unchanged
        with open('tokens.json', 'r', encoding='utf-8') as file:
            tokens = json.loads(file.read())
        assert tokens['access_token'] == expected_tokens['access_token']
        assert tokens['refresh_token'] == expected_tokens['refresh_token']

    unstub()


# Logout Scenario 2
def test_auth_logout_handles_keep_tokens_and_no_pid(config_dict, credentials):
    """
    Tests that ``cortex auth logout --keep-tokens`` handles non-existing PID.
    """
    expected_tokens = prepare_tokens(300, 3600, **credentials)
    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

        runner.invoke(
            cortex_cli,
            [
                'auth',
                'login',
                '--config-file',
                'config.json',
                '--username',
                credentials['username'],
                '--password',
                credentials['password'],
                '--no-refresh',  # do not start token manager
            ],
        )

        result = runner.invoke(cortex_cli, ['auth', 'logout', '--config-file', 'config.json', '--keep-tokens'])
        assert result.exit_code == 0
        assert 'Nothing to do, exiting' in result.output

        # tokens file left unchanged
        with open('tokens.json', 'r', encoding='utf-8') as file:
            tokens = json.loads(file.read())
        assert tokens['access_token'] == expected_tokens['access_token']
        assert tokens['refresh_token'] == expected_tokens['refresh_token']

    unstub()


# Logout Scenario 3 (complete logout)
def test_auth_logout_handles_no_keep_tokens_and_pid(config_dict, credentials):
    """
    Tests that `cortex auth logout` performs logout request, deletes tokens and kills daemon.
    """
    tokens = prepare_tokens(300, 3600, **credentials)
    auth_server_url = credentials['auth_server_url']
    realm = config_dict['realm']
    client_id = config_dict['client_id']
    refresh_token = tokens['refresh_token']
    expect_logout(auth_server_url, realm, client_id, refresh_token)
    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

        runner.invoke(
            cortex_cli,
            [
                'auth',
                'login',
                '--config-file',
                'config.json',
                '--username',
                credentials['username'],
                '--password',
                credentials['password'],
                '--no-refresh',  # do not start token manager
            ],
        )

        with open('tokens.json', 'r', encoding='utf-8') as file:
            tokens = json.loads(file.read())

        # emulate a running daemon by storing a real PID
        tokens['pid'] = os.getpid()
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens))

        expect_process_terminate()
        result = runner.invoke(cortex_cli, ['auth', 'logout', '--config-file', 'config.json', '--force'])
        assert result.exit_code == 0
        assert 'Tokens file deleted. Logged out.' in result.output

        # tokens file deleted
        with raises(FileNotFoundError):
            with open('tokens.json', 'r', encoding='UTF-8') as file:
                file.read()

    unstub()


def test_auth_logout_succeeds_with_auth_server_not_available(credentials, config_dict, tokens_dict):
    """
    Tests that ``cortex auth logout`` deletes tokens file when authentication server fails to process request.
    """
    tokens = prepare_tokens(300, 3600, **credentials)
    url = credentials['auth_server_url']
    realm = config_dict['realm']
    client_id = config_dict['client_id']
    refresh_token = tokens['refresh_token']
    expect_logout(url, realm, client_id, refresh_token, status_code=401)

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        tokens_dict['access_token'] = tokens['access_token']
        tokens_dict['refresh_token'] = tokens['refresh_token']
        tokens_dict['pid'] = os.getpid()
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens_dict))

        runner.invoke(
            cortex_cli,
            [
                'auth',
                'login',
                '--config-file',
                'config.json',
                '--username',
                credentials['username'],
                '--password',
                credentials['password'],
                '--no-refresh',  # do not start token manager
            ],
        )

        expect_process_terminate()
        result = runner.invoke(cortex_cli, ['auth', 'logout', '--config-file', 'config.json', '--force'])
        assert result.exit_code == 0
        assert 'Tokens file deleted. Logged out.' in result.output

        # tokens file deleted
        with raises(FileNotFoundError):
            with open('tokens.json', 'r', encoding='UTF-8') as file:
                file.read()

    unstub()


# Logout Scenario 4
def test_auth_logout_handles_no_keep_tokens_and_no_pid(config_dict, tokens_dict, credentials):
    """
    Tests that ``cortex auth logout`` attempts to logout without daemon running.
    """
    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

        del tokens_dict['pid']
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens_dict))

        url = credentials['auth_server_url']
        realm = config_dict['realm']
        client_id = config_dict['client_id']
        refresh_token = tokens_dict['refresh_token']
        expect_logout(url, realm, client_id, refresh_token)
        result = runner.invoke(cortex_cli, ['auth', 'logout', '--config-file', 'config.json', '--force'])
        assert result.exit_code == 0
        assert 'No PID found in tokens file' in result.output
        assert 'Tokens file deleted. Logged out.' in result.output

        # tokens file deleted
        with raises(FileNotFoundError):
            with open('tokens.json', 'r', encoding='utf-8') as file:
                json.loads(file.read())

    unstub()


def test_auth_logout_succeeds_with_auth_server_not_available_no_pid(credentials, config_dict, tokens_dict):
    """
    Tests that ``cortex auth logout`` deletes tokens file when authentication server fails to process request.
    """
    tokens = prepare_tokens(300, 3600, **credentials)
    url = credentials['auth_server_url']
    realm = config_dict['realm']
    client_id = config_dict['client_id']
    refresh_token = tokens['refresh_token']
    expect_logout(url, realm, client_id, refresh_token, status_code=401)

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        del tokens_dict['pid']
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens_dict))

        runner.invoke(
            cortex_cli,
            [
                'auth',
                'login',
                '--config-file',
                'config.json',
                '--username',
                credentials['username'],
                '--password',
                credentials['password'],
                '--no-refresh',  # do not start token manager
            ],
        )

        result = runner.invoke(cortex_cli, ['auth', 'logout', '--config-file', 'config.json', '--force'])
        assert result.exit_code == 0
        assert 'Tokens file deleted. Logged out.' in result.output

        # tokens file deleted
        with raises(FileNotFoundError):
            with open('tokens.json', 'r', encoding='UTF-8') as file:
                file.read()

    unstub()


def test_auth_logout_fails_without_config_file():
    """
    Tests that ``cortex auth logout`` fails when tokens file doesn't exist.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cortex_cli, ['auth', 'logout', '--config-file', 'nonexisting_config.json'])
        assert result.exit_code != 0
        assert 'does not exist' in result.output


def test_auth_logout_fails_without_tokens_file(config_dict):
    """
    Tests that ``cortex auth logout`` fails when tokens file doesn't exist.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

        result = runner.invoke(cortex_cli, ['auth', 'logout', '--config-file', 'config.json'])
        assert result.exit_code == 0
        assert 'Not logged in' in result.output


def test_auth_logout_fails_with_invalid_tokens_file(config_dict, tokens_dict):
    """
    Tests that ``cortex auth logout`` reports error when tokens file is invalid.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        tokens_dict['timestamp'] = 'not a timestamp'
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens_dict))

        result = runner.invoke(
            cortex_cli,
            [
                'auth',
                'logout',
                '--config-file',
                'config.json',
                '--keep-tokens',
            ],
            input='n',
        )
        assert result.exit_code == 0
        assert 'Found invalid tokens.json' in result.output
