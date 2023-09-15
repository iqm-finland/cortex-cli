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
Tests for Cortex CLI
"""

import click
from click.testing import CliRunner

from iqm.cortex_cli.cortex_cli import _validate_path, cortex_cli


def test_no_command():
    """
    Tests that calling ``cortex`` without commands or arguments shows help.
    """
    result = CliRunner().invoke(cortex_cli)
    assert result.exit_code == 0
    assert 'Usage: cortex' in result.output


def test_validate_path_handles_ctx():
    obj = {'some_param': True}
    cmd = click.Command('prompt')
    ctx = click.Context(cmd, obj=obj)

    param = type('', (), {})()  # dummy object
    param.name = 'some_param'

    path = 'some_path'
    assert _validate_path(ctx, param, path) == path
