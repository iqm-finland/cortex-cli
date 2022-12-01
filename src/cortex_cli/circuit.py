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
Submit circuit jobs to IQM quantum computers via Cortex CLI.
"""
from io import TextIOWrapper
import json
import os

import click
from pydantic import ValidationError

from cortex_cli.models import QasmQubitPlacement
from cortex_cli.utils import read_file

CIRCUIT_MISSING_DEPS_MSG = """This requires additional dependencies which are not currently installed.
To install them, run:

pip install "iqm-cortex-cli[circuit]"
"""


def validate_circuit(filename: str) -> None:
    """Validates the given OpenQASM 2.0 file.

    Args:
        filename: name of the QASM file
    Raises:
        ClickException: if circuit is invalid or not found
    """
    try:
        # pylint: disable=import-outside-toplevel
        from cirq.contrib.qasm_import.exception import QasmException
        from cirq_iqm import circuit_from_qasm
    except ModuleNotFoundError as exception:
        error_message = (
            f'{CIRCUIT_MISSING_DEPS_MSG}\nActual error which occured when attempting to load dependencies: {exception}'
        )
        raise click.ClickException(error_message) from exception
    try:
        circuit_from_qasm(read_file(filename))
    except QasmException as ex:
        message = f'Invalid quantum circuit in {filename}\n{ex.message}'
        raise click.ClickException(message) from ex


def parse_qasm_circuit(filename: str, qasm_qubit_placement: TextIOWrapper):
    """Parses the given OpenQASM 2.0 file to an IQM Circuit.

    Args:
        filename: name of the QASM file
        qasm_qubit_placement: mapping from QASM qubit register and index to physical qubit name
    Raises:
        ClickException: if circuit or qasm_qubit_placement is invalid
    Returns:
        iqm_client.Circuit: parsed circuit in IQM format,
        QasmQubitPlacement: validated QasmQubitPlacement
    """
    try:
        # pylint: disable=import-outside-toplevel
        from cirq import NamedQubit, Qid
        from cirq_iqm import circuit_from_qasm
        from cirq_iqm.iqm_sampler import serialize_circuit
    except ModuleNotFoundError as exception:
        error_message = (
            f'{CIRCUIT_MISSING_DEPS_MSG}\nActual error which occured when attempting to load dependencies: {exception}'
        )
        raise click.ClickException(error_message) from exception
    validate_circuit(filename)

    parsed_qasm_qubit_placement = json.load(qasm_qubit_placement)
    try:
        validated_qubit_placement = QasmQubitPlacement(qubit_placement=parsed_qasm_qubit_placement)
    except ValidationError as ex:
        raise click.ClickException(f'Invalid qasm_qubit_placement provided: {str(ex)}.') from ex
    circuit = circuit_from_qasm(read_file(filename))
    qubit_map: dict[Qid, Qid] = {
        NamedQubit(f'{v[0]}_{v[1]}'): NamedQubit(k) for k, v in validated_qubit_placement.qubit_placement.items()
    }
    serialized_circuit = serialize_circuit(circuit.transform_qubits(qubit_map))
    serialized_circuit.name = os.path.basename(filename)
    return (serialized_circuit, validated_qubit_placement)
