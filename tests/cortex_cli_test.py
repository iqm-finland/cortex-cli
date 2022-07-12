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

import click
from click.testing import CliRunner
from mockito import unstub
from pytest import raises

from cortex_cli.auth import time_left_seconds
from cortex_cli.cortex_cli import _validate_path, cortex_cli
from tests.conftest import (expect_check_pid, expect_kill_by_pid,
                            expect_logout, expect_token_is_valid,
                            prepare_tokens)


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
        result = runner.invoke(cortex_cli,
            ['init',
            '--config-file', 'config.json',
            '--tokens-file', config_dict['tokens_file'],
            '--base-url', config_dict['base_url'],
            '--realm', config_dict['realm'],
            '--client-id', config_dict['client_id']
            ])
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
        old_config_dict['base_url'] = 'https://to.be.overwritten.com'
        old_config_dict['username'] = 'to_be_overwritten'
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(old_config_dict))

        result = runner.invoke(cortex_cli,
            ['init',
            '--config-file', 'config.json',
            '--tokens-file', config_dict['tokens_file'],
            '--base-url', config_dict['base_url'],
            '--realm', config_dict['realm'],
            '--client-id', config_dict['client_id']
            ],
            input='y')
        assert result.exit_code == 0
        assert 'already exists. Overwrite?' in result.output
        with open('config.json', 'r', encoding='utf-8') as config_file:
            loaded_config = json.load(config_file)
            assert loaded_config == config_dict
            assert loaded_config != old_config_dict

def test_init_kills_daemon(config_dict, tokens_dict):
    """
    Tests that ``cortex init`` kills active token manager daemon.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('tokens.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_dict))
        good_pid = 1
        expect_check_pid(good_pid)
        expect_kill_by_pid(good_pid)
        result = runner.invoke(cortex_cli,
            ['init',
            '--config-file', 'config.json',
            '--tokens-file', config_dict['tokens_file'],
            '--base-url', config_dict['base_url'],
            '--realm', config_dict['realm'],
            '--client-id', config_dict['client_id']
            ],
            input='y')
        assert result.exit_code == 0
        assert 'will be killed' in result.output
    unstub()

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

def test_auth_status_reports_no_tokens_file(config_dict):
    """
    Tests that ``cortex auth status`` reports error when tokens file doesn't exist.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        result = runner.invoke(cortex_cli, ['auth', 'status', '--config-file', 'config.json'])
        assert result.exit_code != 0
        assert 'Tokens file not found' in result.output

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
        result = runner.invoke(cortex_cli,['auth', 'status', '--config-file', 'config.json'])
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
        result = runner.invoke(cortex_cli,['auth', 'status', '--config-file', 'config.json'])
        assert result.exit_code == 0
        assert f'Time left on access token (hh:mm:ss): {time_left_at}' in result.output
        assert f'Time left on refresh token (hh:mm:ss): {time_left_rt}' in result.output
        # isn't there a racing condition above?

def test_auth_status_reports_not_running_daemon(config_dict, tokens_dict):
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        with open('tokens.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_dict))
        result = runner.invoke(cortex_cli,['auth', 'status', '--config-file', 'config.json'])
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

        result = runner.invoke(cortex_cli,
            ['auth', 'login',
            '--config-file', 'config.json',
            '--username', credentials['username'],
            '--password', credentials['password'],
            '--no-daemon', # do not daemonize
            ])

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

        result = runner.invoke(cortex_cli,
            ['auth', 'login',
            '--config-file', 'config.json',
            '--username', credentials['username'],
            '--password', credentials['password'],
            '--no-daemon', # do not daemonize
            ])

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

        result = runner.invoke(cortex_cli,
            ['auth', 'login',
            '--config-file', 'config.json',
            '--username', credentials['username'],
            '--password', credentials['password'],
            '--no-daemon', # do not daemonize
            ])

        assert 'aborted, because token manager is already running' in result.output


def test_auth_login_succeeds_without_password(config_dict, tokens_dict, credentials):
    """
    Tests that ``cortex auth login`` performs authentication without username and password
    when valid tokens are present.
    """
    refresh_token = tokens_dict['refresh_token']
    expected_tokens = prepare_tokens(300, 3600, previous_refresh_token = refresh_token, **credentials)
    expect_token_is_valid(refresh_token)
    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

        with open('tokens.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_dict))

        result = runner.invoke(cortex_cli,
            ['auth', 'login',
            '--config-file', 'config.json',
            '--no-daemon', # do not daemonize
            ])

        assert result.exit_code == 0
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
    good_pid = 42
    expect_check_pid(good_pid)
    expect_kill_by_pid(good_pid)

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

        # login and save initial tokens.json
        runner.invoke(cortex_cli,
            ['auth', 'login',
            '--config-file', 'config.json',
            '--username', credentials['username'],
            '--password', credentials['password'],
            '--no-daemon', # do not daemonize
            ])
        with open('tokens.json', 'r', encoding='utf-8') as file:
            tokens = json.loads(file.read())

        # emulate having a daemon by adding a PID to tokens.json
        tokens['pid'] = good_pid
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens))

        # user runs logout, but does not confirm
        result = runner.invoke(cortex_cli,
            ['auth', 'logout',
            '--config-file', 'config.json',
            '--keep-tokens',
            ],
            input = 'n')
        assert result.exit_code == 0
        assert 'Logout aborted.' in result.output

        # user runs logout, confirms via --force
        result = runner.invoke(cortex_cli,
            ['auth', 'logout',
            '--config-file', 'config.json',
            '--keep-tokens',
            '--force'
            ])
        assert result.exit_code == 0

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

        runner.invoke(cortex_cli,
            ['auth', 'login',
            '--config-file', 'config.json',
            '--username', credentials['username'],
            '--password', credentials['password'],
            '--no-daemon', # do not daemonize
            ])

        result = runner.invoke(cortex_cli,
            ['auth', 'logout',
            '--config-file', 'config.json',
            '--keep-tokens'
            ])
        assert result.exit_code == 0

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
    url = credentials['base_url']
    realm = config_dict['realm']
    client_id = config_dict['client_id']
    refresh_token = tokens['refresh_token']
    expect_logout(url, realm, client_id, refresh_token)

    good_pid = 42
    expect_check_pid(good_pid)
    expect_kill_by_pid(good_pid)

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))

        runner.invoke(cortex_cli,
            ['auth', 'login',
            '--config-file', 'config.json',
            '--username', credentials['username'],
            '--password', credentials['password'],
            '--no-daemon', # do not daemonize
            ])

        with open('tokens.json', 'r', encoding='utf-8') as file:
            tokens = json.loads(file.read())

        tokens['pid'] = good_pid
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens))

        result = runner.invoke(cortex_cli,
            ['auth', 'logout',
            '--config-file', 'config.json',
            '--force'
            ])
        assert result.exit_code == 0
        assert 'Logged out successfully' in result.output

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

        url = credentials['base_url']
        realm = config_dict['realm']
        client_id = config_dict['client_id']
        refresh_token = tokens_dict['refresh_token']
        expect_logout(url, realm, client_id, refresh_token)
        result = runner.invoke(cortex_cli,
            ['auth', 'logout',
            '--config-file', 'config.json',
            '--force'
            ])
        assert result.exit_code == 0
        assert 'No PID found in tokens file' in result.output
        assert 'Logged out successfully' in result.output

        # tokens file deleted
        with raises(FileNotFoundError):
            with open('tokens.json', 'r', encoding='utf-8') as file:
                json.loads(file.read())

    unstub()

def test_auth_logout_fails_without_config_file():
    """
    Tests that ``cortex auth logout`` fails when tokens file doesn't exist.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cortex_cli,
            ['auth', 'logout',
            '--config-file', 'nonexisting_config.json'
            ])
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

        result = runner.invoke(cortex_cli,
            ['auth', 'logout',
            '--config-file', 'config.json'
            ])
        assert result.exit_code != 0
        assert 'not found' in result.output

# Logout Scenario 3 failure
def test_auth_logout_fails_by_server_response(credentials, config_dict):
    """
    Tests that ``cortex auth logout`` reports error when server fails to process request.
    """
    tokens = prepare_tokens(300, 3600, **credentials)
    url = credentials['base_url']
    realm = config_dict['realm']
    client_id = config_dict['client_id']
    refresh_token = tokens['refresh_token']
    expect_logout(url, realm, client_id, refresh_token, status_code = 401)

    good_pid = 42
    expect_check_pid(good_pid)
    expect_kill_by_pid(good_pid)

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        tokens['pid'] = good_pid
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens))

        runner.invoke(cortex_cli,
            ['auth', 'login',
            '--config-file', 'config.json',
            '--username', credentials['username'],
            '--password', credentials['password'],
            '--no-daemon', # do not daemonize
            ])

        result = runner.invoke(cortex_cli,
            ['auth', 'logout',
            '--config-file', 'config.json',
            '--force'
            ])
        assert result.exit_code != 0
        assert 'Error when logging out' in result.output

        # tokens file left unchanged
        with open('tokens.json', 'r', encoding='utf-8') as file:
            same_tokens = json.loads(file.read())
        assert same_tokens['access_token'] == tokens['access_token']
        assert same_tokens['refresh_token'] == tokens['refresh_token']

    unstub()

# Logout Scenario 4 failure
def test_auth_logout_fails_by_server_response_no_pid(credentials, config_dict, tokens_dict):
    """
    Tests that ``cortex auth logout`` reports error when server fails to process request.
    """
    tokens = prepare_tokens(300, 3600, **credentials)
    url = credentials['base_url']
    realm = config_dict['realm']
    client_id = config_dict['client_id']
    refresh_token = tokens['refresh_token']
    expect_logout(url, realm, client_id, refresh_token, status_code = 401)


    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        del tokens_dict['pid']
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens_dict))

        runner.invoke(cortex_cli,
            ['auth', 'login',
            '--config-file', 'config.json',
            '--username', credentials['username'],
            '--password', credentials['password'],
            '--no-daemon', # do not daemonize
            ])

        result = runner.invoke(cortex_cli,
            ['auth', 'logout',
            '--config-file', 'config.json',
            '--force'
            ])
        assert result.exit_code != 0
        assert 'Error when logging out' in result.output

        # tokens file left unchanged
        with open('tokens.json', 'r', encoding='utf-8') as file:
            same_tokens = json.loads(file.read())
        assert same_tokens['access_token'] == tokens['access_token']
        assert same_tokens['refresh_token'] == tokens['refresh_token']

    unstub()


# Tests for utility functions

def test_validate_path_handles_ctx():
    obj = { 'some_param' : True }
    cmd = click.Command('prompt')
    ctx = click.Context(cmd, obj = obj)

    param = type('', (), {})() # dummy object
    param.name = 'some_param'

    path = 'some_path'
    assert _validate_path(ctx, param, path) == path
