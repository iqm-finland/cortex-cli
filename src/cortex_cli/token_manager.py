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
import signal
import time
from pathlib import Path
from typing import Optional

import daemon

from cortex_cli.auth import ClientAuthenticationError, refresh_request


def daemonize_token_manager(timeout: int, config: dict, errfile: str = '/tmp/stderr.txt') -> None:
    """Start a daemon process.
    Args:
        timeout: refresh timeout (period) in seconds
        config: Cortex CLI configuration dict
        errfile: path to file for writing errors
    """
    with daemon.DaemonContext(stderr=open(errfile, 'w', encoding='UTF-8')):
        start_token_manager(timeout, config)

def start_token_manager(timeout: int, config: dict, single_run: bool = False) -> None:
    """Refresh tokens periodically.
    Args:
        timeout: refresh timeout (period) in seconds
        config: Cortex CLI configuration dict
        single_run: if True, refresh tokens only once and exit; otherwise repeat refreshing indefinitely
    """
    path_to_tokens_dir = Path(config['tokens_file']).parent
    path_to_tokens_file = config['tokens_file']
    base_url = config['base_url']
    realm = config['realm']
    client_id = config['client_id']

    while True:
        with open(path_to_tokens_file, 'r', encoding='utf-8') as file:
            refresh_token = json.load(file)['refresh_token']

        tokens = refresh_request(base_url, realm, client_id, refresh_token)
        if not tokens:
            raise ClientAuthenticationError('Failed to update tokens. Proabably, they were expired.')

        tokens_json = json.dumps({
            'pid': os.getpid(),
            'timestamp': time.ctime(),
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token'],
            'auth_server_url': base_url
        })

        try:
            path_to_tokens_dir.mkdir(parents=True, exist_ok=True)
            with open(Path(path_to_tokens_file), 'w', encoding='UTF-8') as file:
                file.write(tokens_json)
        except OSError as error:
            print('Error writing tokens file', error)

        if single_run:
            break

        time.sleep(timeout)

def check_daemon(tokens_file: str) -> Optional[int]:
    """Check whether a daemon related to the given tokens_file is running.
    Args:
        tokens_file: Path to a tokens JSON file.
    Returns:
        Optional[int]: PID of the process if process is running, None otherwise.
    """
    with open(tokens_file, 'r', encoding='utf-8') as file:
        tokens_data = json.load(file)
    pid = tokens_data['pid'] if 'pid' in tokens_data else None

    if pid and check_pid(pid):
        return pid
    return None

def check_pid(pid: int) -> bool:
    """Check for the existence of a unix PID.
    Args:
        pid: PID in question
    Returns:
        bool: True if process with given PID is running, False otherwise.
    """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True

def kill_by_pid(pid: int) -> bool:
    """Kill process with given PID.
    Args:
        pid: PID in question
    Returns:
        bool: True if process with given PID is has been killed, False otherwise.
    """
    if check_pid(pid):
        os.kill(int(pid), signal.SIGTERM)
        return True
    return False
