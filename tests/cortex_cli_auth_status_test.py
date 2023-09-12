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
Tests for Cortex CLI's auth status command
"""

import datetime
import json
import os

from click.testing import CliRunner

from iqm.cortex_cli.auth import time_left_seconds
from iqm.cortex_cli.cortex_cli import cortex_cli


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
