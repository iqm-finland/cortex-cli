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
Command line interface for executing quantum circuits on IQM's quantum computers.
"""
import json
import logging
import os
import sys
import time
from pathlib import Path
import click

from cortex_cli import __version__
from cortex_cli.auth import login_request, logout_request, refresh_request
from cortex_cli.token_manager import (check_pid, daemonize_token_manager,
                                      kill_by_pid)

HOME_PATH = str(Path.home())
DEFAULT_CONFIG_PATH = f'{HOME_PATH}/.config/iqm-cortex-cli/config.json'
DEFAULT_TOKENS_PATH = f'{HOME_PATH}/.cache/iqm-cortex-cli/tokens.json'
DEFAULT_BASE_URL = 'https://auth.demo.qc.iqm.fi'
DEFAULT_REALM_NAME = 'cortex'
DEFAULT_CLIENT_ID = 'iqm_client'
DEFAULT_USERNAME = ''
DEFAULT_REFRESH_PERIOD = 20 # in seconds

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


def _validate_path(ctx, param, path) -> str:
    """Validate whether entered file path already exists"""
    if ctx.obj and param.name in ctx.obj:
        return path
    ctx.obj = { param.name: True }

    # File doesn't exist, no need to confirm overwriting
    if not Path(path).is_file():
        return path

    # File exists, so user must either overwrite or enter a new path
    while True:
        msg = f"{click.style('File at that path already exists. Overwrite?', fg='red')}"
        if click.confirm(msg, default=None):
            return path

        new_path = click.prompt('New file path')
        if new_path == path:
            continue
        return new_path


@click.group()
@click.version_option(__version__)
def cortex_cli():
    """Interact with an IQM quantum computer with Cortex CLI."""
    return

@cortex_cli.command()
@click.option(
    '--config-path',
    prompt='Where to save config',
    callback=_validate_path,
    default=DEFAULT_CONFIG_PATH,
    help='Location where the configuration file will be saved.')
@click.option(
    '--tokens-path',
    prompt='Where to save auth tokens',
    callback=_validate_path,
    default=DEFAULT_TOKENS_PATH,
    help='Location where the tokens file will be saved.')
@click.option(
    '--url',
    prompt='Base URL of IQM auth server',
    default=DEFAULT_BASE_URL,
    help='Base URL of IQM authentication server.')
@click.option(
    '--realm',
    prompt='Realm on IQM auth server',
    default=DEFAULT_REALM_NAME,
    help='Name of the realm on the IQM authentication server.')
@click.option(
    '--client-id',
    prompt='Client ID',
    default=DEFAULT_CLIENT_ID,
    help='Client ID on the IQM authentication server.')
@click.option(
    '--username',
    prompt='Username (optional)',
    required=False,
    default=DEFAULT_USERNAME,
    help='Username. If not provided, it will be asked at login.')
def init(config_path, tokens_path, url, realm, client_id, username) -> None: #pylint: disable=too-many-arguments
    """Initialize configuration and authentication."""
    path_to_dir = Path(config_path).parent
    config_json = json.dumps({
        'url': url,
        'realm': realm,
        'client_id': client_id,
        'username': username,
        'tokens_path': tokens_path
    })
    try:
        path_to_dir.mkdir(parents=True, exist_ok=True)
        with open(Path(config_path), 'w', encoding='UTF-8') as file:
            file.write(config_json)
    except OSError as error:
        print('Error writing configuration file', error)
    click.echo("Cortex CLI initialized successfully. You can login with 'cortex auth login'.")


@cortex_cli.group()
def auth() -> None:
    """Manage authentication."""
    return

@auth.command()
@click.option(
    '--config-path',
    default=DEFAULT_CONFIG_PATH,
    type=click.Path(),
    help='Location of the configuration file to be used.')
@click.option('-v', '--verbose', is_flag=True, help='Print extra information.')
def status(config_path, verbose):
    """Check status of authorization."""
    if not Path(config_path).is_file():
        click.echo(f'Config file not found at: {config_path}')
        return

    if verbose:
        click.echo(f'Using configuration file: {config_path}')
    config = json.loads(_read(config_path))
    tokens_path = config['tokens_path']
    if not Path(tokens_path).is_file():
        click.echo(f'Tokens file not found at: {tokens_path}')
        return

    if verbose:
        click.echo(f'Using tokens file {tokens_path}')
    tokens_data = json.loads(_read(tokens_path))
    if 'pid' not in tokens_data:
        click.echo(f'Token manager: {click.style("NOT RUNNING", fg="red")}')
        return

    pid = int(tokens_data['pid'])
    if check_pid(pid):
        click.echo(f'Token manager: {click.style("RUNNING", fg="green")} (PID {pid})')
    else:
        click.echo(f'Token manager: {click.style("NOT RUNNING", fg="red")}')

@auth.command()
@click.option(
    '--config-path',
    default=DEFAULT_CONFIG_PATH,
    help='Location of the configuration file to be used.')
@click.option('--username', help='Username for authentication.')
@click.option('--password', help='Password for authentication.')
@click.option('--refresh-period', default=DEFAULT_REFRESH_PERIOD, help='How often to reresh tokens (in seconds).')
@click.option('--no-refresh', is_flag=True, default=False, help='Do not start token manager to refresh tokens.')
def login(config_path, username, password, refresh_period, no_refresh):
    """Authorize"""
    config = json.loads(_read(config_path))
    url = config['url']
    realm = config['realm']
    tokens_path = config['tokens_path']
    if Path(tokens_path).is_file():
        tokens_data = json.loads(_read(tokens_path))
        tokens = refresh_request(config['url'], config['realm'], config['client_id'], tokens_data['refresh_token'])
        save_tokens_file(tokens_path, tokens['access_token'], tokens['refresh_token'])
        return

    if not username:
        if not config['username']:
            username = click.prompt('Username')
        else:
            username = config['username']
            click.echo(f'Username: {username}')

    if not password:
        password = click.prompt('Password', hide_input=True)


    tokens = login_request(url, realm, DEFAULT_CLIENT_ID, username, password)
    if tokens:
        logger.info('Logged in successfully as %s', username)
    save_tokens_file(tokens_path, tokens['access_token'], tokens['refresh_token'])
    if not no_refresh:
        daemonize_token_manager(refresh_period, config)


@auth.command()
@click.option('--config-path', default=DEFAULT_CONFIG_PATH)
@click.option(
    '--keep-tokens',
    is_flag=True, default=False,
    help="Don't delete tokens file, but kill token manager daemon.")
@click.option('-f', '--force', is_flag=True, default=False, help="Don't ask for confirmation.")
def logout(config_path, keep_tokens, force):
    """Either logout completely, or only stop token manager process and keep tokens file."""
    config = json.loads(_read(config_path))
    url = config['url']
    realm = config['realm']
    client_id = config['client_id']
    tokens_path = config['tokens_path']

    tokens = json.loads(_read(tokens_path))
    pid = None
    if 'pid' in tokens:
        pid = int(tokens['pid'])
    refresh_token = tokens['refresh_token']

    if keep_tokens:
        if pid:
            if force or click.confirm('Kill token manager and keep tokens file. OK?', default=None):
                kill_by_pid(pid)
                return
            logger.info('Logout aborted.')
            return
        else:
            logger.info('No PID found in tokens file. Token manager is not running, so tokens may be stale.')
            return

    # Don't keep tokens, kill by PID
    if pid:
        if force or click.confirm('Logout from server, kill token manager, and delete tokens. OK?', default=None):
            if logout_request(url, realm, client_id, refresh_token):
                kill_by_pid(pid)
                os.remove(tokens_path)
                logger.info('Logged out successfully.')
                return
            logger.info('Error when logging out.')
            return
        logger.info('Logout aborted.')
        return

    # Don't keep tokens, PID doesn't exist
    click.echo('No PID found in tokens file. Token manager daemon is not running, so tokens may be stale.')
    click.echo('Attempting to logout from server...')
    if force or click.confirm('Logout from server and delete tokens. OK?', default=None):
        if logout_request(url, realm, client_id, refresh_token):
            os.remove(tokens_path)
            logger.info('Logged out successfully.')
            return
        logger.info('Error when logging out.')
        return
    logger.info('Logout aborted.')
    return


@auth.command()
@click.option('--config-path', default=DEFAULT_CONFIG_PATH, help='Location of the configuration file to be used.')
def refresh(config_path):
    """Refresh tokens manually"""
    config = json.loads(_read(config_path))
    tokens_path = config['tokens_path']
    tokens_data = json.loads(_read(tokens_path))
    tokens = refresh_request(config['url'], config['realm'], config['client_id'], tokens_data['refresh_token'])
    save_tokens_file(tokens_path, tokens['access_token'], tokens['refresh_token'])
    logger.info('Logout aborted.')


def _read(filename: str) -> str:
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
    except FileNotFoundError as ex:
        raise click.ClickException(f'File {filename} not found') from ex

def get_pid_from_tokens_file(path: str) -> int:
    """Reads PID from tokens file.

    Args:
        filename (str): name of the file to read
    Returns:
        int: pid
    Raises:
        ClickException: if file is not found
    """
    tokens_file = _read(path)
    try:
        tokens_data = json.loads(tokens_file)
    except json.decoder.JSONDecodeError as e:
        print('Decoding JSON has failed', e)
    if 'pid' in tokens_data:
        return int(tokens_data['pid'])
    return None

def get_refresh_token_from_tokens_file(path: str) -> int:
    """Reads PID from tokens file.

    Args:
        filename (str): name of the file to read
    Returns:
        int: pid
    Raises:
        ClickException: if file is not found
    """
    tokens_file = _read(path)
    try:
        tokens_data = json.loads(tokens_file)
    except json.decoder.JSONDecodeError as e:
        print('Decoding JSON has failed', e)
    if 'pid' in tokens_data:
        return tokens_data['refresh_token']
    return None

def save_tokens_file(path: str, access_token: str, refresh_token: str):
    """Saves tokens as JSON file at given path.

    Args:
        path (str): path to the file to write
        access_token(str): authorization access token
        refresh_token(str): authorization refresh token
    Raises:
        OSError: if writing to file fails
    """
    path_to_dir = Path(path).parent
    tokens_json = json.dumps({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'timestmamp': time.time()
    })
    try:
        path_to_dir.mkdir(parents=True, exist_ok=True)
        with open(Path(path), 'w', encoding='UTF-8') as file:
            file.write(tokens_json)
    except OSError as error:
        print('Error writing tokens file', error)

if __name__ == '__main__':
    cortex_cli(sys.argv[1:])  # pylint: disable=too-many-function-args



# CONFIG_FILE_SCHEMA = {
#     "type" : "object",
#     "properties" : {
#         "base_url" : {"type" : "string"},
#         "realm" : {"type" : "string"},
#         "tokens_path" : {"type" : "string"},
#         "username" : {"type" : "string"},
#     },
#     "required": ["base_url", "realm", "tokens_path"],
#     "additionalProperties": False
# }

# TOKENS_FILE_SCHEMA = {
#     "type" : "object",
#     "properties" : {
#         "pid" : {"type" : "number"},
#         "timestmamp" : {"type" : "string"},
#         "access_token" : {"type" : "string"},
#         "refresh_token" : {"type" : "string"},
#     },
#     "required": ["pid", "timestmamp", "access_token", "refresh_token"],
#     "additionalProperties": False
# }
