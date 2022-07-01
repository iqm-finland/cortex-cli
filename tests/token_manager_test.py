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

import json

from click.testing import CliRunner
from mockito import unstub
from pytest import raises
import os

from cortex_cli.cortex_cli import (DEFAULT_CLIENT_ID, DEFAULT_REALM_NAME,
                                   cortex_cli)

from cortex_cli.token_manager import check_pid, kill_by_pid, start_token_manager
from tests.conftest import (expect_check_pid, expect_kill_by_pid,
                            expect_os_kill_to_succeed, config_dict,
                            expect_refresh)

def test_token_manager(config_dict, tokens_dict):
    url = config_dict['url']
    expected_tokens = expect_refresh(url, DEFAULT_REALM_NAME, 'refresh.token.fake')
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('tokens.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_dict))
        start_token_manager(1, config_dict, single_run = True)

        saved_tokens = {}
        with open('tokens.json', 'r', encoding='utf-8') as file:
            saved_tokens = json.loads(file.read())

        assert saved_tokens['access_token'] == expected_tokens['access_token']
        assert saved_tokens['refresh_token'] == expected_tokens['refresh_token']
    unstub()

def test_test_check_pid_returns_true():
    current_pid = os.getpid()
    assert check_pid(current_pid) is True

def test_test_check_pid_returns_false():
    bad_pid = 1
    assert check_pid(bad_pid) is False

def test_kill_by_pid_fails_invalid_pid():
    bad_pid = 1
    assert kill_by_pid(bad_pid) is False

def test_kill_by_pid_succeeds():
    good_pid = 42
    expect_check_pid(good_pid)
    expect_kill_by_pid(good_pid)
    expect_os_kill_to_succeed(good_pid)
    assert kill_by_pid(good_pid) is True
    unstub()
