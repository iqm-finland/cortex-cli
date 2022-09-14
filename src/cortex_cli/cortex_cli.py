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
Command line interface for interacting with IQM's quantum computers.
"""
import json
import logging
import os
import platform
import sys
from datetime import datetime, timedelta
from io import TextIOWrapper
from pathlib import Path
from typing import Optional

import click
from psutil import Process
from pydantic import AnyUrl, BaseModel, ValidationError

from cortex_cli import __version__
from cortex_cli.auth import (ClientAuthenticationError, login_request,
                             logout_request, refresh_request,
                             time_left_seconds)
from cortex_cli.circuit import validate_circuit
from cortex_cli.token_manager import (check_token_manager,
                                      daemonize_token_manager,
                                      start_token_manager)
from cortex_cli.utils import read_file, read_json

HOME_PATH = str(Path.home())
DEFAULT_CONFIG_PATH = f'{HOME_PATH}/.config/iqm-cortex-cli/config.json'
DEFAULT_TOKENS_PATH = f'{HOME_PATH}/.cache/iqm-cortex-cli/tokens.json'
REALM_NAME = 'cortex'
CLIENT_ID = 'iqm_client'
USERNAME = ''
REFRESH_PERIOD = 3*60  # in seconds

class ConfigFile(BaseModel):
    """Model of configuration file, used for validating JSON."""
    auth_server_url: AnyUrl
    realm: str
    client_id: str
    username: Optional[str]
    tokens_file: Path


class TokensFile(BaseModel):
    """Model of tokens file, used for validating JSON."""
    pid: Optional[int]
    timestamp: datetime
    access_token: str
    refresh_token: str
    auth_server_url: AnyUrl


class ClickLoggingHandler(logging.Handler):
    """Simple log handler using click's echo function."""
    def __init__(self):
        super().__init__(level=logging.NOTSET)
        self.formatter = logging.Formatter('%(message)s')

    def emit(self, record):
        click.echo(self.format(record))


logger = logging.getLogger('cortex_cli')
logger.addHandler(ClickLoggingHandler())
logger.setLevel(logging.INFO)


def _set_log_level_by_verbosity(verbose: bool) -> int:
    """Sets logger log level to DEBUG if verbose is True, to INFO otherwise.
    Args:
        verbose: whether logging should be verbose (i.e. DEBUG level)
    Returns:
        int: logging level which was set
    """
    if verbose:
        logger.setLevel(logging.DEBUG)
        return logging.DEBUG
    logger.setLevel(logging.INFO)
    return logging.INFO


def _validate_path(ctx: click.Context, param: click.Path, path: str) -> str:
    """Callback for CLI prompt. If needed, confirmation to overwrite is prompted.

    Args:
        ctx: click context
        param: click prompt param object
        path: path provided by user
    Returns:
        str: confirmed and finalized path
    """
    if ctx.obj and param.name in ctx.obj:
        return path
    ctx.obj = {param.name: True}

    # File doesn't exist, no need to confirm overwriting
    if not Path(path).is_file():
        return path

    # File exists, so user must either overwrite or enter a new path
    while True:
        msg = f"{click.style('File at given path already exists. Overwrite?', fg='red')}"
        if click.confirm(msg, default=None):
            return path

        new_path = click.prompt(
            'New file path',
            type=click.Path(dir_okay=False, writable=True))

        if new_path == path:
            continue
        return new_path


def _validate_config_file(config_file: str) -> dict:
    """Checks if provided config file is valid, i.e. it:
       - is valid JSON
       - satisfies Cortex CLI format

    Args:
        config_file (str): --config-file option value
    Raises:
        click.FileError: if config_file is not valid JSON
        click.FileError: if config_file does not satisfy Cortex CLI format
    Returns:
        dict: config dict loaded from config_file
    """

    # config_file must be a valid JSON
    try:
        config = read_json(config_file)
    except Exception as ex:
        raise click.FileError(config_file, f'Provided config is not a valid JSON file: {ex}')

    # config_file must be in correct format
    try:
        ConfigFile(**config)
    except ValidationError as ex:
        raise click.FileError(
            config_file,
            f"""Provided config file is valid JSON, but does not satisfy Cortex CLI format. Possible reasons:
- Cortex CLI was upgraded and config file format is changed. Check the changelog.
- Config file was manually edited by someone.

Re-generate a valid config file by running 'cortex init'.

Full validation error:
{ex}""")

    return config


def _validate_tokens_file(tokens_file: str) -> dict:
    """Checks if provided tokens file is valid, i.e. it:
       - is valid JSON
       - satisfies Cortex CLI format

    Args:
        tokens_file (str): path to tokens file
    Raises:
        click.FileError: if tokens file is not valid JSON
        click.FileError: if tokens file does not satisfy Cortex CLI format
    Returns:
        dict: tokens dict loaded from tokens_file
    """

    # tokens_file must be a valid JSON
    try:
        tokens = read_json(tokens_file)
    except Exception as ex:
        raise click.FileError(tokens_file, f'Provided tokens file is not a valid JSON file: {ex}')

    # tokens_file must be in correct format
    try:
        TokensFile(**tokens)
    except ValidationError as ex:
        raise click.FileError(
            tokens_file,
            f"""Provided tokens file is valid JSON, but does not satisfy Cortex CLI format. Possible reasons:
- Cortex CLI was upgraded and tokens file format is changed. Check the changelog.
- Tokens file was manually edited by someone.

Re-generate a valid tokens file by running 'cortex auth login'.

Full validation error:
{ex}""")

    return tokens


class CortexCliCommand(click.Group):
    """A custom click command group class to wrap global constants."""
    default_config_path: str = DEFAULT_CONFIG_PATH
    default_tokens_path: str = DEFAULT_TOKENS_PATH


@click.group(cls=CortexCliCommand)
@click.version_option(__version__)
def cortex_cli() -> None:
    """Interact with an IQM quantum computer with Cortex CLI."""
    return


@cortex_cli.command()
@click.option(
    '--config-file',
    prompt='Where to save config',
    callback=_validate_path,
    default=CortexCliCommand.default_config_path,
    type=click.Path(dir_okay=False, writable=True),
    help='Location where the configuration file will be saved.')
@click.option(
    '--tokens-file',
    prompt='Where to save auth tokens',
    callback=_validate_path,
    default=CortexCliCommand.default_tokens_path,
    type=click.Path(dir_okay=False, writable=True),
    help='Location where the tokens file will be saved.')
@click.option(
    '--auth-server-url',
    prompt='Base URL of IQM auth server',
    help='Base URL of IQM authentication server.')
@click.option(
    '--realm',
    prompt='Realm on IQM auth server',
    default=REALM_NAME,
    help='Name of the realm on the IQM authentication server.')
@click.option(
    '--client-id',
    prompt='Client ID',
    default=CLIENT_ID,
    help='Client ID on the IQM authentication server.')
@click.option(
    '--username',
    prompt='Username (optional)',
    required=False,
    default=USERNAME,
    help='Username. If not provided, it will be asked for at login.')
@click.option('-v', '--verbose', is_flag=True, help='Print extra information.')
def init(  #pylint: disable=too-many-arguments
         config_file: str,
         tokens_file: str,
         auth_server_url: str,
         realm: str,
         client_id: str,
         username: str,
         verbose: bool
) -> None:
    """Initialize configuration and authentication."""
    _set_log_level_by_verbosity(verbose)

    path_to_dir = Path(config_file).parent
    config_json = json.dumps(
        {
            'auth_server_url': auth_server_url,
            'realm': realm,
            'client_id': client_id,
            'username': username,
            'tokens_file': tokens_file
        },
        indent=2,
    )

    # Tokens file exist, so token manager may be running. Notify user and kill token manager.
    if Path(tokens_file).is_file():
        pid = check_token_manager(tokens_file)
        if pid:
            logger.info('Active token manager (PID %s) will be killed.', pid)
            Process(pid).terminate()

    try:
        path_to_dir.mkdir(parents=True, exist_ok=True)
        with open(Path(config_file), 'w', encoding='UTF-8') as file:
            file.write(config_json)
            logger.debug('Saved configuration file: %s', config_file)
    except OSError as error:
        raise click.ClickException(f'Error writing configuration file, {error}') from error

    logger.info("Cortex CLI initialized successfully. Login and start the token manager with 'cortex auth login'.")


@cortex_cli.group()
def auth() -> None:
    """Manage authentication."""
    return


@auth.command()
@click.option(
    '--config-file',
    default=CortexCliCommand.default_config_path,
    type=click.Path(exists=True, dir_okay=False),
    help='Location of the configuration file to be used.')
@click.option('-v', '--verbose', is_flag=True, help='Print extra information.')
def status(config_file, verbose) -> None:
    """Check status of authentication."""
    _set_log_level_by_verbosity(verbose)

    logger.debug('Using configuration file: %s', config_file)
    config = _validate_config_file(config_file)
    tokens_file = config['tokens_file']
    if not Path(tokens_file).is_file():
        click.echo('Not logged in. Use "cortex auth login" to login.')
        return

    tokens_data = _validate_tokens_file(tokens_file)

    click.echo(f'Tokens file: {tokens_file}')
    if 'pid' not in tokens_data:
        click.echo("Tokens file doesn't contain PID. Probably, 'cortex auth login' was launched with '--no-refresh'\n")

    click.echo(f"Last refresh: {tokens_data['timestamp']}")
    seconds_at = time_left_seconds(tokens_data['access_token'])
    time_left_at = str(timedelta(seconds=seconds_at))
    click.echo(f'Time left on access token (hh:mm:ss): {time_left_at}')
    seconds_rt = time_left_seconds(tokens_data['refresh_token'])
    time_left_rt = str(timedelta(seconds=seconds_rt))
    click.echo(f'Time left on refresh token (hh:mm:ss): {time_left_rt}')

    active_pid = check_token_manager(tokens_file)
    if active_pid:
        click.echo(f'Token manager: {click.style("RUNNING", fg="green")} (PID {active_pid})')
    else:
        click.echo(f'Token manager: {click.style("NOT RUNNING", fg="red")}')


def _validate_cortex_cli_auth_login(no_daemon, no_refresh, config_file) -> dict:
    """Checks if provided combination of auth login options is valid:
       - no_daemon and no_refresh are mutually exclusive
       - daemon mode should not be requested on Windows
       - config file should pass validation

    Args:
        config_file (str): --config-file option value
        no_daemon (bool): --no-daemon option value
        no_refresh (bool): --no-refresh option value
    Raises:
        click.BadOptionUsage: if both mutually exclusive --no-daemon and --no-refresh are set
        click.UsageError: if daemon is requested on Windows
        click.BadParameter: if config_file does not exist
    Returns:
        dict: config dict loaded from config_file
    """

    # --no-refresh and --no-daemon are mutually exclusive
    if no_refresh and no_daemon:
        raise click.BadOptionUsage(
            '--no-refresh',
            "Cannot request a non-daemonic (foreground) token manager when using '--no-refresh'.")

    # daemonizing is unavailable on Windows
    if platform.system().lower().startswith('win') and not no_refresh and not no_daemon:
        raise click.UsageError(
            "Daemonizing is not yet possible on Windows. Please, use '--no-daemon' or '--no-refresh' flag.")

    # config file, even the default one, should exist
    if not Path(config_file).is_file():
        raise click.BadParameter(
            f'Provided config {config_file} does not exist. ' +
            "Provide a different file or run 'cortex auth init' to create a new config file.")

    # config file should be valid JSON and satisfy Cortex CLI format
    config = _validate_config_file(config_file)

    return config


@auth.command()
@click.option(
    '--config-file',
    default=CortexCliCommand.default_config_path,
    type=click.Path(exists=True, dir_okay=False),
    help='Location of the configuration file to be used.')
@click.option('--username', help='Username for authentication.')
@click.option('--password', help='Password for authentication.')
@click.option(
    '--refresh-period',
    default=REFRESH_PERIOD,
    show_default=True,
    help='How often to refresh tokens (in seconds).')
@click.option('--no-daemon', is_flag=True, default=False, help='Start token manager in foreground, not as daemon.')
@click.option(
    '--no-refresh',
    is_flag=True,
    default=False,
    help='Login, but do not start token manager to refresh tokens.')
@click.option('-v', '--verbose', is_flag=True, help='Print extra information.')
def login(  #pylint: disable=too-many-arguments, too-many-locals
          config_file: str,
          username: str,
          password: str,
          refresh_period: int,
          no_daemon: bool,
          no_refresh: bool,
          verbose: bool
) -> None:
    """Authenticate on the IQM server, and optionally start a token manager to maintain the session."""
    _set_log_level_by_verbosity(verbose)

    # Validate whether the combination of options makes sense
    config = _validate_cortex_cli_auth_login(no_daemon, no_refresh, config_file)

    auth_server_url, realm, client_id = config['auth_server_url'], config['realm'], config['client_id']
    tokens_file = config['tokens_file']

    if Path(tokens_file).is_file():
        if check_token_manager(tokens_file):
            logger.info("Login aborted, because token manager is already running. See 'cortex auth status'.")
            return

        # Tokens file exists; Refresh tokens without username/password
        refresh_token = _validate_tokens_file(tokens_file)['refresh_token']
        logger.debug('Attempting to refresh tokens by using existing refresh token from file: %s', tokens_file)

        new_tokens = None
        try:
            new_tokens = refresh_request(auth_server_url, realm, client_id, refresh_token)
        except ClientAuthenticationError:
            logger.info('Failed to refresh tokens by using existing token. Switching to username/password.')

        if new_tokens:
            save_tokens_file(tokens_file, new_tokens, auth_server_url)
            logger.debug('Saved new tokens file: %s', tokens_file)
            if no_refresh:
                logger.info(
                    "Existing token used to refresh session. Token manager not started due to '--no-refresh' flag.")
            elif no_daemon:
                logger.info(
                    'Existing token was used to refresh the auth session. Token manager started in foreground...')
                start_token_manager(refresh_period, config)
            else:
                logger.info('Existing token was used to refresh the auth session. Token manager daemon started.')
                daemonize_token_manager(refresh_period, config)
            return

    # Login with username and password
    username = username or config['username'] or click.prompt('Username')
    if config['username']:
        click.echo(f'Username: {username}')
    password = password or click.prompt('Password', hide_input=True)

    try:
        tokens = login_request(auth_server_url, realm, client_id, username, password)
    except ClientAuthenticationError as error:
        raise click.ClickException('Invalid username and/or password') from error

    logger.info('Logged in successfully as %s', username)
    save_tokens_file(tokens_file, tokens, auth_server_url)
    click.echo(f"""
To use the tokens file with IQM Client or IQM Client-based software, set the environment variable:

export IQM_TOKENS_FILE={tokens_file}

Refer to IQM Client documentation for details: https://iqm-finland.github.io/iqm-client/
""")

    if no_refresh:
        logger.info("Token manager not started due to '--no-refresh' flag.")
    elif no_daemon:
        logger.info('Token manager started in foreground...')
        start_token_manager(refresh_period, config)
    else:
        daemonize_token_manager(refresh_period, config)
        logger.info('Token manager daemon started.')


@auth.command()
@click.option(
    '--config-file',
    type=click.Path(exists=True, dir_okay=False),
    default=CortexCliCommand.default_config_path)
@click.option(
    '--keep-tokens',
    is_flag=True, default=False,
    help="Don't delete tokens file, but kill token manager.")
@click.option('-f', '--force', is_flag=True, default=False, help="Don't ask for confirmation.")
def logout(config_file: str, keep_tokens: str, force: bool) -> None:
    """Either logout completely, or just stop token manager while keeping tokens file."""
    config = _validate_config_file(config_file)
    auth_server_url, realm, client_id = config['auth_server_url'], config['realm'], config['client_id']
    tokens_file = config['tokens_file']

    if not Path(tokens_file).is_file():
        click.echo('Not logged in.')
        return

    tokens = _validate_tokens_file(tokens_file)
    pid = tokens['pid'] if 'pid' in tokens else None
    refresh_token = tokens['refresh_token']

    extra_msg = ' and kill token manager' if check_token_manager(tokens_file) else ''

    if keep_tokens and not check_token_manager(tokens_file):
        click.echo('Token manager is not running, and you chose to keep tokens. Nothing to do, exiting.')
        return

    # 1. Keep tokens, kill daemon
    if keep_tokens and pid:
        if force or click.confirm(f'Keep tokens file{extra_msg}. OK?', default=None):
            Process(pid).terminate()
            logger.info('Token manager killed.')
            return

    # 2. Keep tokens, do nothing
    if keep_tokens and not pid:
        logger.info('No PID found in tokens file. Token manager is not running, so tokens may be stale.')

    # 3. Delete tokens, perform logout, kill daemon
    if not keep_tokens and pid:
        if force or click.confirm(f'Logout from server, delete tokens{extra_msg}. OK?', default=None):
            try:
                logout_request(auth_server_url, realm, client_id, refresh_token)
            except ClientAuthenticationError as error:
                raise click.ClickException(f'Error when logging out: {error}') from error
            Process(pid).terminate()
            os.remove(tokens_file)
            logger.info('Logged out successfully.')
            return

    # 4. Delete tokens, perform logout
    if not keep_tokens and not pid:
        logger.info('No PID found in tokens file. Token manager daemon is not running, so tokens may be stale.')
        if force or click.confirm('Logout from server and delete tokens. OK?', default=None):
            try:
                logout_request(auth_server_url, realm, client_id, refresh_token)
            except ClientAuthenticationError as error:
                raise click.ClickException(f'Error when logging out: {error}') from error

            os.remove(tokens_file)
            logger.info('Logged out successfully.')
            return

    logger.info('Logout aborted.')


@cortex_cli.group()
def circuit() -> None:
    """Execute your quantum circuits with Cortex CLI."""
    return


@circuit.command()
@click.argument('filename')
def validate(filename: str) -> None:
    """Check if a quantum circuit is valid."""
    validate_circuit(filename)
    logger.info('File %s contains a valid quantum circuit', filename)


def save_tokens_file(path: str, tokens: dict[str, str], auth_server_url: str) -> None:
    """Saves tokens as JSON file at given path.

    Args:
        path (str): path to the file to write
        tokens (dict[str, str]): authorization access and refresh tokens
        auth_server_url (str): base url of the authorization server
    Raises:
        OSError: if writing to file fails
    """
    path_to_dir = Path(path).parent
    tokens_data = {
        'timestamp': datetime.now().isoformat(),
        'access_token': tokens['access_token'],
        'refresh_token': tokens['refresh_token'],
        'auth_server_url': auth_server_url
    }

    try:
        path_to_dir.mkdir(parents=True, exist_ok=True)
        with open(Path(path), 'w', encoding='UTF-8') as file:
            file.write(json.dumps(tokens_data))
    except OSError as error:
        raise click.ClickException(f'Error writing tokens file, {error}') from error


def _validate_cortex_cli_auth(no_auth, config_file) -> Optional[str]:
    """Checks if provided auth options are correct:
       - no_auth and config_file are mutually exclusive
       - if no_auth is not set, config_file must have the CortexCliCommand.default_config_path value
       - config file must exist and contain a path to an existing tokens_file

    Args:
        no_auth (bool): --no-auth option value
        config_file (str): --config-file option value
    Raises:
        click.UsageError: if user is not logged in or provided and invalid config
        click.BadOptionUsage: if both mutually exclusive --no-auth and --config-file are set
    Returns:
        str: path to the tokens file if using cortex-cli auth and provided (or default)
             config-file exists and valid, None if --no-auth is set
    """

    # --no-auth and --config-file are mutually exclusive
    if no_auth and config_file:
        raise click.BadOptionUsage('--no-auth', 'Cannot use both --no-auth and --config-file options.')

    # no config_file to use, no tokens_file
    if no_auth:
        return None

    # --config-file was not provided, but has a default value
    if not config_file:
        logger.debug('No auth options provided, using default config file: %s', CortexCliCommand.default_config_path)
        config_file = CortexCliCommand.default_config_path

    # config file, even the default one, should exist
    if not Path(config_file).is_file():
        raise click.UsageError("Not logged in. Run 'cortex auth login' to log in.")

    # config file should exist, be valid and satisfy Cortex CLI format
    config = _validate_config_file(config_file)

    # and at least contain an existing tokens_file
    tokens_file = config['tokens_file']
    if not Path(tokens_file).is_file():
        raise click.UsageError("Not logged in. Run 'cortex auth login' to log in.")

    return tokens_file


@circuit.command()
@click.option('-v', '--verbose', is_flag=True, help='Print extra information.')
@click.option('--shots', default=1, type=int, help='Number of times to sample the circuit.')
@click.option('--settings', default=None, type=click.File(), envvar='IQM_SETTINGS_PATH',
              help='Path to the settings file containing calibration data. Must be JSON formatted. '
                   'Can also be set using the IQM_SETTINGS_PATH environment variable:\n'
                   '`export IQM_SETTINGS_PATH=\"/path/to/settings/file.json\"`\n'
                   'If not set, the latest available calibration will be used.')
@click.option('--calibration-set-id', type=int, help='ID of the calibration set to use instead of settings.')
@click.option('--qubit-mapping', default=None, type=click.File(), envvar='IQM_QUBIT_MAPPING_PATH',
              help='Path to the qubit mapping JSON file. Must consist of a single JSON object, with logical '
                   'qubit names ("Alice", "Bob", ...) as keys, and physical qubit names (appearing in '
                   'the settings file) as values. For example: {"Alice": "QB1", "Bob": "QB2"}. '
                   'Can also be set using the IQM_QUBIT_MAPPING_PATH environment variable:\n'
                   '`export IQM_QUBIT_MAPPING_PATH=\"/path/to/qubit/mapping.json\"`\n'
                   'If not set, the qubit names are assumed to be physical names.')
@click.option('--iqm-server-url', envvar='IQM_SERVER_URL', type=str, required=True,
              help='URL of the IQM server interface for running circuits. Must start with http or https. '
                   'Can also be set using the IQM_SERVER_URL environment variable:\n'
                   '`export IQM_SERVER_URL=\"https://example.com\"`')
@click.option('-i', '--iqm-json', is_flag=True,
              help='Set this flag if FILENAME is already in IQM JSON format (instead of being an OpenQASM file).')
@click.option('--config-file',
              type=click.Path(exists=True, dir_okay=False),
              help='Location of the configuration file to be used.'
              'If neither --no-auth, nor --config-file are set, the default configuration file is used.')
@click.option('--no-auth', is_flag=True, default=False,
              help="Do not use Cortex CLI's auth functionality. "
              'Mutually exclusive with --config-file option. '
              'When submitting a circuit job, Cortex CLI will use IQM Client without passing any auth tokens. '
              'Auth data can still be set using environment variables for IQM Client.')
@click.argument('filename', type=click.Path())
def run(  #pylint: disable=too-many-arguments, too-many-locals, import-outside-toplevel
        verbose: bool,
        shots: int,
        settings: Optional[TextIOWrapper],
        calibration_set_id: Optional[int],
        qubit_mapping: Optional[TextIOWrapper],
        iqm_server_url: str,
        filename: str,
        iqm_json: bool,
        config_file: str,
        no_auth: bool
) -> None:
    """Execute a quantum circuit.

    The circuit is provided in the OpenQASM 2.0 file FILENAME. The circuit must only contain operations that are
    natively supported by the quantum computer the execution happens on.

    Returns a JSON object whose keys correspond to the measurement operations in the circuit.
    The value for each key is a 2-D array of integers containing the corresponding measurement
    results. The first index of the array goes over the shots, and the second over the qubits
    included in the measurement.
    """
    import cirq_iqm
    from cirq_iqm.iqm_sampler import serialize_circuit
    from iqm_client.iqm_client import Circuit, IQMClient

    _set_log_level_by_verbosity(verbose)

    # check --no-auth and --config-file alignment
    tokens_file = _validate_cortex_cli_auth(no_auth, config_file)

    raw_input = read_file(filename)

    try:
        # serialize the circuit and the qubit mapping
        if iqm_json:
            input_circuit = Circuit.parse_raw(raw_input)
        else:
            validate_circuit(filename)
            input_circuit = cirq_iqm.circuit_from_qasm(raw_input)
            input_circuit = serialize_circuit(input_circuit)

        logger.debug('\nInput circuit:\n%s', input_circuit)

        parsed_qubit_mapping = None
        if qubit_mapping is not None:
            parsed_qubit_mapping = json.load(qubit_mapping)

        parsed_settings = None
        if settings is not None:
            parsed_settings = json.load(settings)

        # run the circuit on the backend
        iqm_client = IQMClient(iqm_server_url, tokens_file=tokens_file)
        job_id = iqm_client.submit_circuits(
            [input_circuit],
            qubit_mapping=parsed_qubit_mapping,
            shots=shots,
            settings=parsed_settings,
            calibration_set_id=calibration_set_id
        )
        results = iqm_client.wait_for_results(job_id)
    except Exception as ex:
        # just show the error message, not a stack trace
        raise click.ClickException(str(ex)) from ex

    if results.measurements is None:
        raise click.ClickException(
            f'No measurements obtained from backend. Job status is ${results.status}'
        )

    logger.debug('\nResults:')
    if results.metadata.calibration_set_id is not None:
        logger.info('Using calibration set %d', results.metadata.calibration_set_id)
    logger.info(json.dumps(results.measurements[0]))  # pylint: disable=unsubscriptable-object


if __name__ == '__main__':
    cortex_cli(sys.argv[1:])  # pylint: disable=too-many-function-args
