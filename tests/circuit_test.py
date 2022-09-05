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
Tests for Cortex CLI's circuit commands
"""
import json
import os

from click.testing import CliRunner
from mockito import unstub

from cortex_cli.cortex_cli import cortex_cli
from tests.conftest import expect_jobs_requests, resources_path

valid_circuit_qasm = os.path.join(resources_path(), 'valid_circuit.qasm')
qubit_mapping_path = os.path.join(resources_path(), 'qubit_mapping.json')
qasm_qubit_mapping_path = os.path.join(resources_path(), 'qubit_mapping_qasm.json')
settings_path = os.path.join(resources_path(), 'settings.json')


def test_circuit_validate_no_argument_fails():
    """
    Tests that ``circuit validate`` fails without argument.
    """
    result = CliRunner().invoke(cortex_cli, ['circuit', 'validate'])
    assert result.exit_code != 0
    assert 'Missing' in result.output
    assert 'FILENAME' in result.output


def test_circuit_validate_no_file_fails():
    """
    Tests that ``circuit validate`` fails with non-existing file.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cortex_cli, ['circuit', 'validate', 'nope.qasm'])  # this file does not exist
        assert result.exit_code != 0
        assert 'File' in result.output
        assert 'not found' in result.output


def test_circuit_validate_obviously_invalid_fails():
    """
    Tests that ``circuit validate`` fails with obviously invalid file.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('my_circuit.qasm', 'w', encoding='utf-8') as circuit_file:
            circuit_file.write('foo baz')
        result = runner.invoke(cortex_cli, ['circuit', 'validate', 'my_circuit.qasm'])
        assert result.exit_code != 0
        assert 'Invalid quantum circuit in my_circuit.qasm' in result.output


def test_circuit_validate_slightly_invalid_fails():
    """
    Tests that ``circuit validate`` fails with slightly invalid file.
    """
    slightly_invalid_circuit = """OPENQASM 2.0;
                                  include "qelib1.inc";
                                  qreg q[2];
                                  cx q[1], q[2];
                                  """
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('my_circuit.qasm', 'w', encoding='utf-8') as circuit_file:
            circuit_file.write(slightly_invalid_circuit)
        result = runner.invoke(cortex_cli, ['circuit', 'validate', 'my_circuit.qasm'])
        assert result.exit_code != 0
        assert 'Invalid quantum circuit in my_circuit.qasm' in result.output


def test_circuit_validate_valid_circuit():
    """
    Tests that ``circuit validate`` validates a valid circuit validly.
    """
    result = CliRunner().invoke(cortex_cli, ['circuit', 'validate', valid_circuit_qasm])
    assert result.exit_code == 0
    assert f'File {valid_circuit_qasm} contains a valid quantum circuit' in result.output


def test_circuit_run_invalid_circuit(mock_environment_vars_for_backend, config_dict, tokens_dict):  # pylint: disable=unused-argument
    """
    Tests that ``circuit run`` fails with an invalid circuit.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('my_circuit.qasm', 'w', encoding='utf-8') as circuit_file:
            circuit_file.write('foo bar')
        with open('my_qubits.json', 'w', encoding='utf-8') as qubit_mapping_file:
            qubit_mapping_file.write('{}')
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens_dict))
        result = CliRunner().invoke(cortex_cli,
            ['circuit', 'run', 'my_circuit.qasm',
             '--config-file', 'config.json',
             '--qubit-mapping', 'my_qubits.json',
             '--no-auth'])

        assert result.exit_code != 0
        assert 'Invalid quantum circuit in my_circuit.qasm' in result.output


def test_circuit_run_valid_qasm_circuit(credentials, config_dict, tokens_dict):
    """
    Tests that ``circuit run`` succeeds with valid QASM circuit.
    """
    base_url = credentials['base_url']
    expect_jobs_requests(base_url)

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens_dict))
        result = CliRunner().invoke(cortex_cli,
            ['circuit', 'run', valid_circuit_qasm,
             '--config-file', 'config.json',
             '--qubit-mapping', qasm_qubit_mapping_path,
             '--settings', settings_path,
             '--url', base_url,
             '--no-auth'])
    assert 'result' in result.output
    assert result.exit_code == 0
    unstub()


def test_circuit_run_valid_json_circuit(credentials, config_dict, tokens_dict):
    """
    Tests that ``circuit run`` succeeds with valid JSON circuit.
    """
    base_url = credentials['base_url']
    expect_jobs_requests(base_url)
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens_dict))
        result = CliRunner().invoke(cortex_cli,
            ['circuit', 'run', os.path.join(resources_path(), 'valid_circuit.json'), '--iqm-json',
             '--config-file', 'config.json',
             '--qubit-mapping', qubit_mapping_path,
             '--settings', settings_path,
             '--url', base_url,
             '--no-auth'])
    assert 'result' in result.output
    assert result.exit_code == 0
    unstub()


def test_circuit_run_valid_json_circuit_custom_calibration_set_id(credentials, config_dict, tokens_dict):
    """
    Tests that ``circuit run`` succeeds with valid JSON circuit and custom calibration set ID.
    """
    base_url = credentials['base_url']
    expect_jobs_requests(base_url, calibration_set_id=24)
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens_dict))
        result = CliRunner().invoke(cortex_cli,
            ['circuit', 'run', os.path.join(resources_path(), 'valid_circuit.json'), '--iqm-json',
             '--config-file', 'config.json',
             '--qubit-mapping', qubit_mapping_path,
             '--calibration-set-id', '24',
             '--url', base_url,
             '--no-auth'])
    assert 'result' in result.output
    assert 'calibration set 24' in result.output
    assert result.exit_code == 0
    unstub()


def test_circuit_run_valid_json_circuit_default_settings_no_qubit_mapping(credentials, config_dict, tokens_dict):
    """
    Tests that ``circuit run`` succeeds with valid json circuit and no qubit mapping.
    """
    base_url = credentials['base_url']
    expect_jobs_requests(base_url, calibration_set_id=35)
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        with open('tokens.json', 'w', encoding='utf-8') as file:
            file.write(json.dumps(tokens_dict))
        result = CliRunner().invoke(cortex_cli,
            ['circuit', 'run', os.path.join(resources_path(), 'valid_circuit.json'), '--iqm-json',
             '--config-file', 'config.json',
             '--url', base_url,
             '--no-auth'])
    assert 'result' in result.output
    assert 'calibration set 35' in result.output
    assert result.exit_code == 0
    unstub()
