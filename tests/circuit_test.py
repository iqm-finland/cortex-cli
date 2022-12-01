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
from io import BytesIO, TextIOWrapper
import json
import os

from click.testing import CliRunner
from iqm_client import Instruction
from mockito import unstub

from cortex_cli.circuit import parse_qasm_circuit
from cortex_cli.cortex_cli import _human_readable_frequencies_output, cortex_cli
from cortex_cli.models import QasmQubitPlacement
from tests.conftest import expect_jobs_requests, resources_path

valid_circuit_qasm = os.path.join(resources_path(), 'valid_circuit.qasm')
valid_circuit_qasm_result = os.path.join(resources_path(), 'valid_circuit_qasm_result.json')
qasm_qubit_placement_path = os.path.join(resources_path(), 'qasm_qubit_placement.json')


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


def test_circuit_run_invalid_circuit(
    mock_environment_vars_for_backend, config_dict, tokens_dict
):  # pylint: disable=unused-argument
    """
    Tests that ``circuit run`` fails with an invalid circuit.
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('my_circuit.qasm', 'w', encoding='utf-8') as circuit_file:
            circuit_file.write('foo bar')
        with open('my_qubits.json', 'w', encoding='utf-8') as qubit_mapping_file:
            qubit_mapping_file.write('{}')
        result = CliRunner().invoke(
            cortex_cli, ['circuit', 'run', 'my_circuit.qasm', '--qasm-qubit-placement', 'my_qubits.json', '--no-auth']
        )

        assert result.exit_code != 0
        assert 'Invalid quantum circuit in my_circuit.qasm' in result.output


def test_circuit_run_valid_qasm_circuit_frequencies_output():
    """
    Tests that ``circuit run`` succeeds with valid QASM circuit and outputs human-readable frequencies table by default.
    """
    iqm_server_url = 'https://example.com'
    expect_jobs_requests(iqm_server_url, valid_circuit_qasm_result_file=valid_circuit_qasm_result)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                valid_circuit_qasm,
                '--qasm-qubit-placement',
                qasm_qubit_placement_path,
                '--iqm-server-url',
                iqm_server_url,
                '--no-auth',
            ],
        )
    assert 'q[0]' in result.output
    assert 'q[1]' in result.output
    assert result.exit_code == 0
    unstub()


def test_circuit_run_valid_qasm_circuit_shots_output():
    """
    Tests that ``circuit run`` succeeds with valid QASM circuit and outputs human-readable shots table.
    """
    iqm_server_url = 'https://example.com'
    expect_jobs_requests(iqm_server_url, valid_circuit_qasm_result_file=valid_circuit_qasm_result)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                valid_circuit_qasm,
                '--qasm-qubit-placement',
                qasm_qubit_placement_path,
                '--iqm-server-url',
                iqm_server_url,
                '--no-auth',
                '--output',
                'shots',
            ],
        )
    assert 'result' in result.output
    assert result.exit_code == 0
    unstub()


def test_circuit_run_valid_qasm_circuit_json_output():
    """
    Tests that ``circuit run`` succeeds with valid QASM circuit and outputs machine-readable ``RunResult`` json.
    """
    iqm_server_url = 'https://example.com'
    expect_jobs_requests(iqm_server_url, valid_circuit_qasm_result_file=valid_circuit_qasm_result)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                valid_circuit_qasm,
                '--qasm-qubit-placement',
                qasm_qubit_placement_path,
                '--iqm-server-url',
                iqm_server_url,
                '--no-auth',
                '--output',
                'json',
            ],
        )
    assert 'b_0' in result.output
    assert 'b_1' in result.output
    assert json.loads(result.output) is not None
    assert result.exit_code == 0
    unstub()


def test_circuit_measurements_do_not_match():
    """
    Tests that ``circuit run`` fails if measured qubits do not match the input circuit.
    """
    iqm_server_url = 'https://example.com'
    expect_jobs_requests(iqm_server_url)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                valid_circuit_qasm,
                '--qasm-qubit-placement',
                qasm_qubit_placement_path,
                '--iqm-server-url',
                iqm_server_url,
                '--no-auth',
                '--output',
                'json',
            ],
        )
    assert result.exit_code != 0
    assert 'do not match measurements in the circuit' in result.output
    unstub()


def test_circuit_run_qasm_no_qubit_placement():
    """
    Tests that ``circuit run`` fails with valid QASM circuit but missing qubit placement.
    """
    iqm_server_url = 'https://example.com'
    expect_jobs_requests(iqm_server_url)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                valid_circuit_qasm,
                '--iqm-server-url',
                iqm_server_url,
                '--no-auth',
            ],
        )
    assert '--qasm_qubit_placement is required' in result.output
    assert result.exit_code != 0
    unstub()


def test_circuit_run_invalid_qasm_qubit_placement():
    """
    Tests that ``circuit run`` fails if qubit placement is invalid.
    """
    iqm_server_url = 'https://example.com'
    expect_jobs_requests(iqm_server_url)
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('invalid_qubit_placement.json', 'w', encoding='utf8') as f:
            f.write('{"QB1": "q0"}')
        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                valid_circuit_qasm,
                '--qasm-qubit-placement',
                'invalid_qubit_placement.json',
                '--iqm-server-url',
                iqm_server_url,
                '--no-auth',
            ],
        )
    assert 'Invalid qasm_qubit_placement provided' in result.output
    assert result.exit_code != 0
    unstub()


def test_circuit_run_valid_json_circuit():
    """
    Tests that ``circuit run`` succeeds with valid JSON circuit.
    """
    iqm_server_url = 'https://example.com'
    expect_jobs_requests(iqm_server_url)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                os.path.join(resources_path(), 'valid_circuit.json'),
                '--iqm-json',
                '--iqm-server-url',
                iqm_server_url,
                '--no-auth',
            ],
        )
    assert 'result' in result.output
    assert result.exit_code == 0
    unstub()


def test_circuit_run_valid_json_circuit_custom_calibration_set_id():
    """
    Tests that ``circuit run`` succeeds with valid JSON circuit and custom calibration set ID.
    """
    iqm_server_url = 'https://example.com'
    expect_jobs_requests(iqm_server_url, calibration_set_id=24)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                os.path.join(resources_path(), 'valid_circuit.json'),
                '--iqm-json',
                '--calibration-set-id',
                '24',
                '--iqm-server-url',
                iqm_server_url,
                '--no-auth',
            ],
        )
    assert 'result' in result.output
    assert 'calibration set 24' in result.output
    assert result.exit_code == 0
    unstub()


def test_circuit_run_json_circuit_and_qasm_qubit_placement():
    """
    Tests that ``circuit run`` fails when qasm qubit placement is provided with ``--iqm-json``.
    """
    iqm_server_url = 'https://example.com'
    expect_jobs_requests(iqm_server_url, calibration_set_id=35)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                os.path.join(resources_path(), 'valid_circuit.json'),
                '--iqm-json',
                '--iqm-server-url',
                iqm_server_url,
                '--qasm-qubit-placement',
                qasm_qubit_placement_path,
                '--no-auth',
            ],
        )
    assert result.exit_code != 0
    assert '--qasm_qubit_placement is only valid if --iqm-json is not set' in result.output
    unstub()


def test_circuit_run_both_no_auth_and_config_file_provided(config_dict):
    """
    Tests that ``circuit run`` fails options validation if both ``--no-auth`` and ``--config-file`` are provided.
    """
    iqm_server_url = 'https://example.com'
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                os.path.join(resources_path(), 'valid_circuit.json'),
                '--iqm-json',
                '--config-file',
                'config.json',
                '--iqm-server-url',
                iqm_server_url,
                '--no-auth',
            ],
        )
    assert 'Cannot use both --no-auth and --config-file options' in result.output
    assert result.exit_code == 2
    unstub()


def test_circuit_run_valid_config_file_provided(config_dict, tokens_dict):
    """
    Tests that ``circuit run`` succeeds if a valid ``--config-file`` provided.
    """
    iqm_server_url = 'https://example.com'
    expect_jobs_requests(iqm_server_url)
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        with open('tokens.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_dict))
        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                os.path.join(resources_path(), 'valid_circuit.json'),
                '--iqm-json',
                '--config-file',
                'config.json',
                '--iqm-server-url',
                iqm_server_url,
            ],
        )
    assert 'result' in result.output
    assert result.exit_code == 0
    unstub()


def test_circuit_run_invalid_config_file_provided(config_dict):
    """
    Tests that ``circuit run`` fails if an invalid ``--config-file`` provided — missing tokens_file
    """
    iqm_server_url = 'https://example.com'
    expect_jobs_requests(iqm_server_url)
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                os.path.join(resources_path(), 'valid_circuit.json'),
                '--iqm-json',
                '--config-file',
                'config.json',
                '--iqm-server-url',
                iqm_server_url,
            ],
        )
    assert 'Not logged in.' in result.output
    assert result.exit_code == 2
    unstub()


def test_circuit_run_not_a_json_config_file_provided():
    """
    Tests that ``circuit run`` fails if an invalid ``--config-file`` provided — not a json
    """
    iqm_server_url = 'https://example.com'
    expect_jobs_requests(iqm_server_url)
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write('NOT A JSON')
        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                os.path.join(resources_path(), 'valid_circuit.json'),
                '--iqm-json',
                '--config-file',
                'config.json',
                '--iqm-server-url',
                iqm_server_url,
            ],
        )
    assert result.exit_code != 0
    assert 'not a valid JSON file' in result.output
    unstub()


def test_circuit_run_default_config_used_when_no_auth_provided(config_dict, tokens_dict):
    """
    Tests that ``circuit run`` takes the default config file when no auth is provided
    """
    iqm_server_url = 'https://example.com'
    expect_jobs_requests(iqm_server_url)
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open('config.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(config_dict))
        with open('tokens.json', 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_dict))

        # mock global var in cortex_cli
        cortex_cli.__class__.default_config_path = 'config.json'

        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                os.path.join(resources_path(), 'valid_circuit.json'),
                '--iqm-json',
                '--iqm-server-url',
                iqm_server_url,
            ],
        )
    assert 'result' in result.output
    assert result.exit_code == 0
    unstub()


def test_circuit_run_default_config_used_when_no_auth_provided_not_logged_in():
    """
    Tests that ``circuit run`` takes the default config file when no auth is provided
    """
    iqm_server_url = 'https://example.com'
    expect_jobs_requests(iqm_server_url)
    runner = CliRunner()
    with runner.isolated_filesystem():

        # mock global var in cortex_cli
        cortex_cli.__class__.default_config_path = 'config.json'

        result = CliRunner().invoke(
            cortex_cli,
            [
                'circuit',
                'run',
                os.path.join(resources_path(), 'valid_circuit.json'),
                '--iqm-json',
                '--iqm-server-url',
                iqm_server_url,
            ],
        )
    assert 'Not logged in.' in result.output
    assert result.exit_code == 2
    unstub()


def test_parse_qasm_circuit():
    """
    Test that parse_qasm_circuit maps QASM qubits to IQM qubits.
    """
    qasm_qubit_placement = TextIOWrapper(BytesIO(str.encode('{"QB1": ["q",0], "QB2": ["q",1]}')))

    circuit, qubit_placement = parse_qasm_circuit(valid_circuit_qasm, qasm_qubit_placement)

    assert circuit.all_qubits() == {'QB1', 'QB2'}
    assert circuit.instructions == (
        Instruction(name='phased_rx', qubits=('QB1',), args={'angle_t': 0.5, 'phase_t': 0}),
        Instruction(name='cz', qubits=('QB1', 'QB2'), args={}),
        Instruction(name='measurement', qubits=('QB1',), args={'key': 'b_0'}),
        Instruction(name='measurement', qubits=('QB2',), args={'key': 'b_1'}),
    )
    assert circuit.name == 'valid_circuit.qasm'
    assert qubit_placement == QasmQubitPlacement(qubit_placement={'QB1': ('q', 0), 'QB2': ('q', 1)})


def test_human_readable_frequencies_output_works():
    """
    Test that frequencies are calculated correctly.
    """
    per_qubit_measurements = {'QB1': [0, 0, 1, 1], 'QB2': [0, 1, 0, 1]}

    output = _human_readable_frequencies_output(4, per_qubit_measurements)
    assert '0	0	0.25' in output
    assert '0	1	0.25' in output
    assert '1	0	0.25' in output
    assert '1	1	0.25' in output
