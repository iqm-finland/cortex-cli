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
from cortex_cli.auth import login_request, logout_request, refresh_tokens
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


def _validate_config_path(ctx, param, path) -> str: # pylint: disable=unused-argument
    """Validate whether entered config file path already exists"""
    if ctx.obj and 'validated_config_path' in ctx.obj:
        return path
    ctx.obj = { 'validated_config_path': True }

    # File doesn't exist, no need to confirm overwriting
    if not Path(path).is_file():
        return path

    # File exists, so user must either overwrite or enter a new path
    while True:
        msg = f"{click.style('Config file at that path already exists. Overwrite?', fg='red')}"
        overwrite = click.confirm(msg, default=None)
        if overwrite:
            return path

        new_path = click.prompt('New config path')
        if new_path == path:
            continue
        return new_path


def _validate_tokens_path(ctx, _, path):
    """Validate whether entered tokens file path already exists"""
    if ctx.obj and 'validated_tokens_path' in ctx.obj:
        return path
    ctx.obj = { 'validated_tokens_path': True }

    # File doesn't exist, no need to confirm overwriting
    if not Path(path).is_file():
        return path

    # User must either agree to overwrite or enter a truly new path
    while True:
        msg = f"{click.style('Tokens file already exists. Overwrite it and kill its token manager?', fg='red')}"
        overwrite = click.confirm(msg, default=None)
        if overwrite:
            pid = get_pid_from_tokens_file(path)
            if pid:
                kill_by_pid(pid)
            return path
        new_path = click.prompt('New configuration path')
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
    callback=_validate_config_path,
    default=DEFAULT_CONFIG_PATH)
@click.option(
    '--tokens-path',
    prompt='Where to save auth tokens',
    callback=_validate_tokens_path,
    default=DEFAULT_TOKENS_PATH)
@click.option('--url', prompt='Base URL of IQM auth server', default=DEFAULT_BASE_URL)
@click.option('--realm', prompt='Realm on IQM auth server', default=DEFAULT_REALM_NAME)
@click.option('--client-id', prompt='Client ID', default=DEFAULT_CLIENT_ID)
@click.option('--username', prompt='Username (optional)', required=False, default=DEFAULT_USERNAME)
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
@click.option('--config-path', default=DEFAULT_CONFIG_PATH, type=click.Path())
@click.option('-v', '--verbose', is_flag=True, help='Print extra information.')
def status(config_path, verbose):
    """Check status of authorization."""
    if not Path(config_path).is_file():
        click.echo(f'Config file not found: {config_path}')
        return

    if verbose:
        click.echo(f'Using configuration file {config_path}')
    config = json.loads(_read(config_path))
    tokens_path = config['tokens_path']
    if not Path(tokens_path).is_file():
        click.echo(f'Tokens file not found: {tokens_path}')
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
@click.option('--config-path', default=DEFAULT_CONFIG_PATH)
@click.option('--username')
@click.option('--password')
@click.option('--refresh-period', default=DEFAULT_REFRESH_PERIOD)
@click.option('--no-refresh', is_flag=True, default=False)
def login(config_path, username, password, refresh_period, no_refresh):
    """Authorize"""
    config = json.loads(_read(config_path))
    url = config['url']
    realm = config['realm']
    tokens_path = config['tokens_path']

    if not username:
        if not config['username']:
            username = click.prompt('Username')
        else:
            username = config['username']
            click.echo(f'Username: {username}')

    if not password:
        password = click.prompt('Password')


    tokens = login_request(url, realm, DEFAULT_CLIENT_ID, username, password)
    save_tokens_file(tokens_path, tokens['access_token'], tokens['refresh_token'])
    if not no_refresh:
        daemonize_token_manager(refresh_period, config)


@auth.command()
@click.option('--config-path', default=DEFAULT_CONFIG_PATH)
@click.option(
    '--keep-tokens',
    is_flag=True,
    default=False,
    help="Don't delete tokens file, but kill token manager daemon.")
@click.option('-f', '--force', is_flag=True, default=False, help="Don't ask for confirmation.")
def logout(config_path, keep_tokens, force):
    """Logout completely, or just stop token manager process and keep tokens file"""
    config = json.loads(_read(config_path))
    tokens_path = config['tokens_path']
    pid = get_pid_from_tokens_file(tokens_path)
    if not pid:
        click.echo('No PID found in tokens file.')
        return
    if keep_tokens:
        if force or click.confirm('Kill token manager daemon and keep tokens file. OK?', default=None):
            kill_by_pid(pid)
            return

    tokens_data = json.loads(_read(tokens_path))
    refresh_token = tokens_data['refresh_token']
    config = json.loads(_read(config_path))
    url = config['url']
    realm = config['realm']

    if force:
        logged_out = logout_request(url, realm, 'iqm_client', refresh_token)
        os.remove(tokens_path)
        if logged_out:
            click.echo('Logged out successfully.')
        return
    confirmed = click.confirm('Logout from server, stop token manager and delete tokens file. OK?', default=None)
    if confirmed:
        if logout_request(url, realm, 'iqm_client', refresh_token):
            os.remove(tokens_path)


@auth.command()
@click.option('--config-path', default=DEFAULT_CONFIG_PATH)
def refresh(config_path):
    """Refresh tokens manually"""
    config = json.loads(_read(config_path))
    tokens_path = config['tokens_path']
    tokens_data = json.loads(_read(tokens_path))

    refresh_tokens(config['url'], config['realm'], config['client_id'], tokens_data['refresh_token'])


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
