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

from cortex_cli.cortex_cli import cortex_cli
from tests.conftest import prepare_tokens


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

def test_auth_login(credentials):
    """
    Tests that if the client is initialized with credentials, they are used correctly
    """
    config_path = os.path.dirname(os.path.realpath(__file__)) + '/resources/config.json'
    tokens = prepare_tokens(300, 3600, **credentials)
    # expected_credentials = Credentials(
    #     access_token=tokens['access_token'],
    #     refresh_token=tokens['refresh_token'],
    #     **credentials
    # )
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cortex_cli,
            ['auth', 'login',
            '--config-path', config_path,
            '--username', credentials['username'],
            '--password', credentials['password'],
            ])
        assert result.exit_code == 0
        assert 'Cortex CLI initialized successfully' in result.output
        unstub()
        with open('tokens.json', 'r', encoding='utf-8') as tokens_file:
            loaded_tokens = json.load(tokens_file)
            assert loaded_tokens == tokens
