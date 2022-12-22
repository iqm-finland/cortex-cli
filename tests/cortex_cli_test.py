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

import datetime
import json
import os
from pathlib import Path

import click
from click.testing import CliRunner
from mockito import unstub
from psutil import pid_exists
from pytest import raises

from cortex_cli.auth import time_left_seconds
from cortex_cli.cortex_cli import _validate_path, cortex_cli
from tests.conftest import expect_logout, expect_process_terminate, expect_token_is_valid, make_token, prepare_tokens


def test_no_command():
    """
    Tests that calling ``cortex`` without commands or arguments shows help.
    """
    result = CliRunner().invoke(cortex_cli)
    assert result.exit_code == 0
    assert 'Usage: cortex' in result.output


# Tests for 'cortex init'


def test_init_saves_config_file(config_dict):
    """
    Tests that ``cortex init`` produces config file.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            cortex_cli,
            [
                'init',
                '--config-file',
                'config.json',
                '--tokens-file',
                config_dict['tokens_file'],
                '--auth-server-url',
                config_dict['auth_server_url'],
                '--realm',
                config_dict['realm'],
                '--client-id',
                config_dict['client_id'],
            ],
        )
        assert result.exit_code == 0
        assert 'Cortex CLI initialized successfully' in result.output
        with open('config.json', 'r', encoding='utf-8') as config_file:
            loaded_config = json.load(config_file)
            assert loaded_config == config_dict


def test_init_overwrites_config_file(config_dict):
    """
    Tests that ``cortex init`` prompts to overwrite, and overwrites existing config file.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        old_config_dict = config_dict.copy()
        old_config_dict['auth_server_url'] = 'https://to.be.overwritten.com'
        old_config_dict['username'] = 'to_be_overwritten'
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(old_config_dict))

        result = runner.invoke(
            cortex_cli,
            [
                'init',
                '--config-file',
                'config.json',
                '--tokens-file',
                config_dict['tokens_file'],
                '--auth-server-url',
                config_dict['auth_server_url'],
                '--realm',
                config_dict['realm'],
                '--client-id',
                config_dict['client_id'],
            ],
            input='y',
        )
        assert result.exit_code == 0
        assert 'already exists. Overwrite?' in result.output
        with open('config.json', 'r', encoding='utf-8') as config_file:
            loaded_config = json.load(config_file)
            assert loaded_config == config_dict
            assert loaded_config != old_config_dict


def test_init_kills_daemon_and_removes_token_file(config_dict, tokens_dict):
    """
    Tests that ``cortex init`` kills active token manager daemon and removes old token file.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        # emulate a running daemon by storing a real PID
        tokens_dict['pid'] = os.getpid()

        tokens_file_path = 'tokens.json'
        with open(tokens_file_path, 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_dict))

        expect_process_terminate()
        result = runner.invoke(
            cortex_cli,
            [
                'init',
                '--config-file',
                'config.json',
                '--tokens-file',
                config_dict['tokens_file'],
                '--auth-server-url',
                config_dict['auth_server_url'],
                '--realm',
                config_dict['realm'],
                '--client-id',
                config_dict['client_id'],
            ],
            input='y',
        )
        assert not Path(tokens_file_path).is_file()
        assert result.exit_code == 0
        assert 'will be killed' in result.output


# Tests for 'cortex auth status'


def test_auth_status_reports_no_config_file():
    """
    Tests that ``cortex auth status`` reports error when config file doesn't exist.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cortex_cli, ['auth', 'status', '--config-file', 'config.json'])
        assert result.exit_code != 0
        assert 'does not exist' in result.output


def test_auth_status_reports_invalid_json_config():
    """
    Tests that ``cortex auth status`` reports error when config file is not valid JSON.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write('NOT A JSON')
        result = runner.invoke(cortex_cli, ['auth', 'status', '--config-file', 'config.json'])
        assert result.exit_code != 0
        assert 'not a valid JSON file' in result.output


def test_auth_status_reports_incorrect_json_config(config_dict):
    """
    Tests that ``cortex auth status`` reports error when config file does not satisfy Cortex CLI format.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        config_dict['auth_server_url'] = 'not a url'
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        result = runner.invoke(cortex_cli, ['auth', 'status', '--config-file', 'config.json'])
        assert result.exit_code != 0
        assert 'does not satisfy Cortex CLI format' in result.output


def test_auth_status_reports_no_tokens_file(config_dict):
    """
    Tests that ``cortex auth status`` reports error when tokens file doesn't exist.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        result = runner.invoke(cortex_cli, ['auth', 'status', '--config-file', 'config.json'])
        assert result.exit_code == 0
        assert 'cortex auth login' in result.output


def test_auth_status_reports_invalid_tokens_file(config_dict, tokens_dict):
    """
    Tests that ``cortex auth status`` reports error when tokens file is invalid.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        tokens_dict['timestamp'] = 'not a timestamp'
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens_dict))
        result = runner.invoke(cortex_cli, ['auth', 'status', '--config-file', 'config.json'])
        assert result.exit_code == 0
        assert 'Provided tokens.json file is invalid' in result.output


def test_auth_status_reports_no_pid_in_tokens_file(config_dict, tokens_dict):
    """
    Tests that ``cortex auth status``reports no daemon when tokens file doesn't contain PID.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        del tokens_dict['pid']
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens_dict))
        result = runner.invoke(cortex_cli, ['auth', 'status', '--config-file', 'config.json'])
        assert result.exit_code == 0
        assert 'NOT RUNNING' in result.output


def test_auth_status_reports_running_daemon(config_dict, tokens_dict):
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        tokens_dict['pid'] = os.getpid()
        with open('tokens.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_dict))
        result = runner.invoke(cortex_cli, ['auth', 'status', '--config-file', 'config.json'])
        assert result.exit_code == 0
        assert 'RUNNING' in result.output
        assert 'NOT RUNNING' not in result.output


def test_auth_status_reports_valid_token_time(config_dict, tokens_dict):
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        with open('tokens.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_dict))

        seconds_at = time_left_seconds(tokens_dict['access_token'])
        time_left_at = str(datetime.timedelta(seconds=seconds_at))
        seconds_rt = time_left_seconds(tokens_dict['refresh_token'])
        time_left_rt = str(datetime.timedelta(seconds=seconds_rt))
        result = runner.invoke(cortex_cli, ['auth', 'status', '--config-file', 'config.json'])
        assert result.exit_code == 0
        assert f'Time left on access token (hh:mm:ss): {time_left_at}' in result.output
        assert f'Time left on refresh token (hh:mm:ss): {time_left_rt}' in result.output
        # isn't there a racing condition above?


def test_auth_status_reports_not_running_daemon(config_dict, tokens_dict):
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        del tokens_dict['pid']
        with open('tokens.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_dict))
        result = runner.invoke(cortex_cli, ['auth', 'status', '--config-file', 'config.json'])
        assert result.exit_code == 0
        assert 'NOT RUNNING' in result.output


# Tests for 'cortex auth login'


def test_auth_login_succeeds(config_dict, credentials):
    """
    Tests that ``cortex auth login`` performs authentication and saves tokens.
    """
    expected_tokens = prepare_tokens(300, 3600, **credentials)

    runner = CliRunner()
    with runner.isolated_filesystem():
        config_dict['username'] = credentials['username']
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

        result = runner.invoke(
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

        assert result.exit_code == 0
        assert 'Username: ' + credentials['username'] in result.output

        with open('tokens.json', 'r', encoding='utf-8') as file:
            tokens = json.loads(file.read())

        assert tokens['access_token'] == expected_tokens['access_token']
        assert tokens['refresh_token'] == expected_tokens['refresh_token']

    unstub()


def test_auth_login_fails(config_dict, credentials):
    """
    Tests that ``cortex auth login`` fails gracefully due to incorrect credentials.
    """
    prepare_tokens(300, 3600, status_code=401, **credentials)

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

        result = runner.invoke(
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

        assert result.exit_code != 0
        assert 'Invalid username and/or password' in result.output

    unstub()


def test_auth_login_handles_running_daemon(config_dict, tokens_dict, credentials):
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

        tokens_dict['pid'] = os.getpid()
        with open('tokens.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_dict))

        result = runner.invoke(
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

        assert 'aborted, because token manager is already running' in result.output


def test_auth_login_succeeds_without_password(config_dict, tokens_dict, credentials):
    """
    Tests that ``cortex auth login`` performs authentication without username and password
    when valid tokens are present.
    """
    refresh_token_lifetime = 3600
    access_token_lifetime = 300
    refresh_token = make_token('Refresh', refresh_token_lifetime)
    access_token = make_token('Bearer', access_token_lifetime)
    expected_tokens = prepare_tokens(
        access_token_lifetime, refresh_token_lifetime, previous_refresh_token=refresh_token, **credentials
    )
    expect_token_is_valid(refresh_token)
    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

        tokens_dict['refresh_token'] = refresh_token
        tokens_dict['access_token'] = access_token
        with open('tokens.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_dict))

        result = runner.invoke(
            cortex_cli,
            [
                'auth',
                'login',
                '--config-file',
                'config.json',
                '--no-refresh',  # do not start token manager
            ],
        )

        assert result.exit_code == 0
        with open('tokens.json', 'r', encoding='utf-8') as file:
            tokens = json.loads(file.read())

        assert tokens['access_token'] == expected_tokens['access_token']
        assert tokens['refresh_token'] == expected_tokens['refresh_token']

    unstub()


def test_auth_login_proceeds_with_login_on_invalid_tokens_json(config_dict, tokens_dict, credentials):
    """
    Tests that ``cortex auth login`` performs authentication with username and password
    when tokens file is invalid.
    """
    expected_tokens = prepare_tokens(300, 3600, **credentials)
    runner = CliRunner()

    with runner.isolated_filesystem():
        config_dict['username'] = credentials['username']
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

        del tokens_dict['pid']
        tokens_dict['timestamp'] = 'not a timestamp'
        with open('tokens.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_dict))

        result = runner.invoke(
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

        assert result.exit_code == 0
        assert 'Provided tokens.json file is invalid' in result.output
        with open('tokens.json', 'r', encoding='utf-8') as file:
            tokens = json.loads(file.read())
        assert tokens['access_token'] == expected_tokens['access_token']
        assert tokens['refresh_token'] == expected_tokens['refresh_token']

    unstub()


# Tests for 'cortex auth logout'
# ``cortex auth logout`` supports four possible scenarios:
# 1. If --keep-tokens, and PID is found: kills process, keeps tokens file.
# 2. If --keep-tokens, and PID not found: do nothing.
# 3. If not --keep-tokens, and PID is found: send logout request, kill process, delete tokens file.
# 4. If not --keep-tokens, and PID is not found: send logout request, delete tokens file.
#
# The 4 tests below cover the corresponding scenarios.

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


# Tests for utility functions


def test_validate_path_handles_ctx():
    obj = {'some_param': True}
    cmd = click.Command('prompt')
    ctx = click.Context(cmd, obj=obj)

    param = type('', (), {})()  # dummy object
    param.name = 'some_param'

    path = 'some_path'
    assert _validate_path(ctx, param, path) == path
