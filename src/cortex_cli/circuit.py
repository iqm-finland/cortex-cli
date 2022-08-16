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


def validate_circuit(filename: str) -> None:
    """Validates the given OpenQASM 2.0 file.

    Args:
        filename: name of the QASM file
    Raises:
        ClickException: if circuit is invalid or not found
    """
    # pylint: disable=import-outside-toplevel
    import cirq_iqm
    from cirq.contrib.qasm_import.exception import QasmException
    try:
        cirq_iqm.circuit_from_qasm(read_file(filename))
    except QasmException as ex:
        message = f'Invalid quantum circuit in {filename}\n{ex.message}'
        raise click.ClickException(message) from ex
