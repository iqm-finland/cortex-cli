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
Tests for Cortex CLI's init command
"""

import json
import os
from pathlib import Path

from click.testing import CliRunner
from mockito import unstub

from cortex_cli.cortex_cli import cortex_cli
from tests.conftest import expect_process_terminate, prepare_auth_server_urls


def test_init_saves_config_file(config_dict):
    """
    Tests that ``cortex init`` produces config file.
    """
    prepare_auth_server_urls(config_dict)
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
    unstub()


def test_init_overwrites_config_file(config_dict):
    """
    Tests that ``cortex init`` prompts to overwrite, and overwrites existing config file.
    """
    prepare_auth_server_urls(config_dict)
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
    unstub()


def test_init_kills_daemon_and_removes_token_file(config_dict, tokens_dict):
    """
    Tests that ``cortex init`` kills active token manager daemon and removes old token file.
    """
    prepare_auth_server_urls(config_dict)
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
    unstub()


def test_init_warns_user_if_auth_server_url_is_invalid(config_dict):
    """
    Tests that ``cortex init`` prompts user to either accept invalid auth server URL or to enter another one.
    """
    invalid_url = 'http://invalid.com'
    prepare_auth_server_urls(config_dict, invalid_url)
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
                invalid_url,
                '--realm',
                config_dict['realm'],
                '--client-id',
                config_dict['client_id'],
            ],
            input='y\ny\n',  # User accepts auth_server_url and realm (realm can not be accessed either)
        )
        assert result.exit_code == 0
        assert f'No auth server could be accessed with URL {invalid_url}' in result.output
        assert 'Do you still want to use it?' in result.output
        with open('config.json', 'r', encoding='utf-8') as config_file:
            loaded_config = json.load(config_file)
            assert loaded_config == {**config_dict, 'auth_server_url': invalid_url}
    unstub()


def test_init_warns_user_if_realm_is_invalid(config_dict):
    """
    Tests that ``cortex init`` prompts user to either accept invalid realm or to enter another one.
    """
    valid_url = config_dict['auth_server_url']
    invalid_realm = 'invalid'
    prepare_auth_server_urls(config_dict, invalid_realm=invalid_realm)
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
                valid_url,
                '--realm',
                invalid_realm,
                '--client-id',
                config_dict['client_id'],
            ],
            input='y\n',  # User accepts the realm
        )
        assert result.exit_code == 0
        assert f'No auth realm could be accessed with URL {valid_url}/realms/{invalid_realm}' in result.output
        assert 'Do you still want to use it?' in result.output
        with open('config.json', 'r', encoding='utf-8') as config_file:
            loaded_config = json.load(config_file)
            assert loaded_config == {**config_dict, 'realm': invalid_realm}
    unstub()


def test_init_lets_user_to_enter_correct_auth_server_url_if_the_original_is_invalid(config_dict):
    """
    Tests that ``cortex init`` prompts user to enter another URL if the original is invalid.
    """
    invalid_url = 'http://invalid.com'
    prepare_auth_server_urls(config_dict, invalid_url)
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
                invalid_url,
                '--realm',
                config_dict['realm'],
                '--client-id',
                config_dict['client_id'],
            ],
            input=f'\n{config_dict["auth_server_url"]}\n',  # User rejects the invalid URL and enters another one
        )
        assert result.exit_code == 0
        assert f'No auth server could be accessed with URL {invalid_url}' in result.output
        assert 'Do you still want to use it?' in result.output
        with open('config.json', 'r', encoding='utf-8') as config_file:
            loaded_config = json.load(config_file)
            assert loaded_config == config_dict
    unstub()