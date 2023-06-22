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
Tests for Cortex CLI's auth logic
"""

import json
import os
from pathlib import Path
import platform

from click.testing import CliRunner
from mockito import ANY, unstub, when
import pytest

from cortex_cli import token_manager
from cortex_cli.models import ConfigFile
from tests.conftest import expect_token_is_valid, prepare_tokens

if not platform.system().lower().startswith('win'):
    import daemon


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

        token_manager.start_token_manager(cycle=1, config=ConfigFile(**config_dict), single_run=True)

        with open('tokens.json', 'r', encoding='utf-8') as file:
            saved_tokens = json.loads(file.read())
            assert saved_tokens['access_token'] == expected_tokens['access_token']
            assert saved_tokens['refresh_token'] == expected_tokens['refresh_token']
    unstub()


@pytest.mark.skipif(platform.system().lower().startswith('win'), reason='daemonization does not work on windows')
def test_daemonize_token_manager(config_dict):
    """
    Tests that token manager refreshes tokens.
    """
    when(daemon.DaemonContext).__enter__().thenReturn(None)  # pylint: disable=unnecessary-dunder-call
    when(daemon.DaemonContext).__exit__(ANY, ANY, ANY).thenReturn(None)
    when(token_manager).start_token_manager(1, ConfigFile(**config_dict)).thenReturn(None)

    runner = CliRunner()

    with runner.isolated_filesystem():
        token_manager.daemonize_token_manager(cycle=1, config=ConfigFile(**config_dict))
        assert os.path.isfile(f'{Path.home()}/.local/state/token_manager.log')
    unstub()
