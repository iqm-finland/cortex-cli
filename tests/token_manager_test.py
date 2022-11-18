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

from cortex_cli.models import ConfigFile
from cortex_cli.token_manager import start_token_manager
from tests.conftest import expect_token_is_valid, prepare_tokens


def test_start_token_manager(credentials, config_dict, tokens_dict):
    """
    Tests that token manager refreshes tokens.
    """
    refresh_token = tokens_dict['refresh_token']
    expected_tokens = prepare_tokens(300, 3600, previous_refresh_token=refresh_token, **credentials)
    expect_token_is_valid(refresh_token)

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('tokens.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_dict))

        start_token_manager(cycle=1, config=ConfigFile(**config_dict), single_run=True)

        with open('tokens.json', 'r', encoding='utf-8') as file:
            saved_tokens = json.loads(file.read())
            assert saved_tokens['access_token'] == expected_tokens['access_token']
            assert saved_tokens['refresh_token'] == expected_tokens['refresh_token']
    unstub()
