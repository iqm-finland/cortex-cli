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
Token manager for authentication and authorization to IQM's quantum computers. Part of Cortex CLI.
"""
import json
import os
import platform
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from psutil import pid_exists
from requests.exceptions import Timeout

from cortex_cli.auth import ClientAuthenticationError, refresh_request

if not platform.system().lower().startswith('win'):
    import daemon


def daemonize_token_manager(cycle: int, config: dict, errfile: str = '/tmp/stderr.txt') -> None:
    """Start a daemon process.
    Args:
        cycle: refresh cycle in seconds
        config: Cortex CLI configuration dict
        errfile: path to file for writing errors
    """
    with daemon.DaemonContext(stderr=open(errfile, 'w', encoding='UTF-8')):
        start_token_manager(cycle, config)


def start_token_manager(cycle: int, config: dict, single_run: bool = False) -> None:
    """Refresh tokens periodically.

    For each refresh cycle new tokens are requested from auth server.
    - If refresh is successful next refresh is attempted in the next cycle.
    - If auth server does not respond within the timeout period, refresh is attempted again immediately until
      it succeeds or the existing refresh token expires.
    - If auth server responds but returns an error code a ClientAuthenticationError is raised.

    Args:
        cycle: refresh cycle in seconds
        config: Cortex CLI configuration dict
        single_run: if True, refresh tokens only once and exit; otherwise repeat refreshing indefinitely

    Raises:
        ClientAuthenticationError: auth server was connected but no valid tokens were obtained
    """
    path_to_tokens_file = config['tokens_file']
    auth_server_url = config['auth_server_url']

    while True:
        with open(path_to_tokens_file, 'r', encoding='utf-8') as file:
            tokens = json.load(file)
            access_token = tokens['access_token']
            refresh_token = tokens['refresh_token']

        try:
            tokens = refresh_request(auth_server_url, config['realm'], config['client_id'], refresh_token)
            refresh_request_timed_out = False
        except Timeout:
            tokens = {'access_token': access_token, 'refresh_token': refresh_token}
            refresh_request_timed_out = True
        if not tokens:
            raise ClientAuthenticationError('Failed to update tokens. Probably, they were expired.')

        timestamp = datetime.now()
        tokens_json = json.dumps({
            'pid': os.getpid(),
            'timestamp': timestamp.isoformat(),
            'refresh_status': 'FAILED' if tokens is None or refresh_request_timed_out else 'SUCCESS',
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token'],
            'auth_server_url': auth_server_url
        })

        try:
            Path(config['tokens_file']).parent.mkdir(parents=True, exist_ok=True)
            with open(Path(path_to_tokens_file), 'w', encoding='UTF-8') as file:
                file.write(tokens_json)
        except OSError as error:
            print('Error writing tokens file', error)

        if single_run:
            break

        human_timestamp = timestamp.strftime('%m/%d/%Y %H:%M:%S')
        if refresh_request_timed_out:
            print(f'{human_timestamp}: No response from auth server.')
        else:
            print(f'{human_timestamp}: Tokens refreshed successfully.')
            time.sleep(cycle)


def check_token_manager(tokens_file: str) -> Optional[int]:
    """Check whether a token manager related to the given tokens_file is running.
    Args:
        tokens_file: Path to a tokens JSON file.
    Returns:
        Optional[int]: PID of the process if process is running, None otherwise.
    """
    with open(tokens_file, 'r', encoding='utf-8') as file:
        tokens_data = json.load(file)
    pid = tokens_data['pid'] if 'pid' in tokens_data else None

    if pid and pid_exists(pid):
        return pid
    return None
