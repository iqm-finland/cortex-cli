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
Utility functions for Cortex CLI.
"""
import importlib.util
import json

import click


def read_file(filename: str) -> str:
    """Opens and reads the given file.

    Args:
        filename (str): name of the file to read
    Returns:
        str: contents of the file
    Raises:
        ClickException: if file is not found
    """
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            return file.read()
    except FileNotFoundError as error:
        raise click.ClickException(f'File {filename} not found') from error


def read_json(filename: str) -> dict:
    """Opens and parses the given JSON file.

    Args:
        filename (str): name of the file to read
    Returns:
        dict: object derived from JSON file
    Raises:
        JSONDecodeError: if parsing fails
    """
    try:
        json_data = json.loads(read_file(filename))
    except json.decoder.JSONDecodeError as error:
        raise click.ClickException(f'Decoding JSON has failed, {error}') from error
    return json_data


def package_installed(package_name: str) -> bool:
    """Checks whether the given package is installed.

    Args:
        package_name (str): name of the package to check
    Returns:
        bool: True if package is installed, False otherwise
    """
    if importlib.util.find_spec(package_name):
        return True
    return False


def missing_packages(required_packages: list[str]) -> list[str]:
    """Reports which of the given packages are not installed.

    Args:
        required_packages (list[str]): list of package names to check
    Returns:
        list: list of packages that are not installed; subset of required_packages
    """
    installed_packages = [pkg for pkg in required_packages if package_installed(pkg)]
    return list(set(required_packages) - set(installed_packages))
