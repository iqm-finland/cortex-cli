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
# pylint: disable=missing-function-docstring, disable=unused-argument

from click.testing import CliRunner

from cortex_cli.cortex_cli import cortex_cli


def test_no_command():
    result = CliRunner().invoke(cortex_cli)
    assert result.exit_code == 0
    assert 'Usage: cortex' in result.output
    assert 'Interact with an IQM quantum computer with Cortex CLI' in result.output
