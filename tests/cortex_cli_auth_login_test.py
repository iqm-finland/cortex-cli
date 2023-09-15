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
Tests for Cortex CLI's auth login command
"""

import json
import os
import platform

from click.testing import CliRunner
from mockito import ANY, unstub, when
import pytest

from iqm.cortex_cli import cortex_cli as cortex_cli_module
from iqm.cortex_cli.cortex_cli import cortex_cli
from tests.conftest import expect_token_is_valid, make_token, prepare_tokens


@pytest.mark.parametrize('absolute_path', [True, False])
def test_auth_login_succeeds(config_dict, credentials, absolute_path):
    """
    Tests that ``cortex auth login`` performs authentication and saves tokens.
    """
    expected_tokens = prepare_tokens(300, 3600, **credentials)

    runner = CliRunner()
    with runner.isolated_filesystem():
        config_dict['username'] = credentials['username']
        if absolute_path:
            config_dict['tokens_file'] = os.path.join(os.getcwd(), config_dict['tokens_file'])  # use absolute path
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
        assert 'Failed to authenticate, invalid username and/or password' in result.output

    unstub()


def test_auth_login_can_not_access_token_endpoint(config_dict, credentials):
    """
    Tests that ``cortex auth login`` fails gracefully when token endpoint is not accessible, i.e.
    auth server is not accessible or does not have a token endpoint.
    """
    prepare_tokens(300, 3600, status_code=404, **credentials)

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
        assert (
            f'Failed to authenticate, token endpoint is not available at {config_dict["auth_server_url"]}'
            in result.output
        )

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


def test_auth_login_detects_temporary_password(config_dict, credentials):
    """
    Tests that ``cortex auth login`` fails gracefully due to temporary credentials and guides the user where to update
    them.
    """
    prepare_tokens(
        300, 3600, status_code=400, response_data={'error_description': 'Account is not fully set up'}, **credentials
    )

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

        password_update_form_url = f'{config_dict["auth_server_url"]}/realms/{config_dict["realm"]}/account'

        assert result.exit_code != 0
        assert password_update_form_url in result.output

    unstub()


def test_auth_login_starts_token_manager(config_dict, credentials):
    """
    Tests that ``cortex auth login`` succeeds and starts token manager when neither ``--no-daemon`` nor
    ``--no-refresh`` are passed.
    """
    when(cortex_cli_module).daemonize_token_manager(ANY, ANY).thenReturn(None)
    when(cortex_cli_module).start_token_manager(ANY, ANY).thenReturn(None)
    prepare_tokens(300, 3600, **credentials)

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
            ],
        )

        assert result.exit_code == 0
        assert 'Logged in successfully' in result.output
        if platform.system().lower().startswith('win'):
            assert 'Daemonizing is not supported on Windows' in result.output
            assert 'Starting token manager in foreground' in result.output
        else:
            assert 'Starting token manager daemon' in result.output

    unstub()
