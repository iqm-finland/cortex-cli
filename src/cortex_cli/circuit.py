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
import click

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
    except ModuleNotFoundError as ex:
        message = f'{CIRCUIT_MISSING_DEPS_MSG}\nActual error which occured when attempting to load dependencies: {ex}'
        raise click.ClickException(message) from ex

    try:
        circuit_from_qasm(read_file(filename))
    except QasmException as ex:
        message = f'Invalid quantum circuit in {filename}\n{ex.message}'
        raise click.ClickException(message) from ex
