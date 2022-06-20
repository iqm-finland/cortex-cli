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
Token manager for authorization to IQM's quantum computers. Part of Cortex CLI.
"""
import daemon
import json
import os
import signal
import time
from cortex_cli.auth import refresh_tokens
from pathlib import Path


def start_tm_daemon(timeout, cfg):
    with daemon.DaemonContext(stderr=open('/tmp/stderr.txt', 'w')) as context:
        _token_manager(timeout, cfg)


def _token_manager(timeout, cfg):
    path_to_tokens_dir = Path(cfg['tokens_path']).parent
    path_to_tokens_file = cfg['tokens_path']
    url = cfg['url']
    realm = cfg['realm']
    client_id = cfg['client_id']

    while True:
        with open(path_to_tokens_file, 'r', encoding='utf-8') as file:
            rft = json.load(file)['refresh_token']


        n = refresh_tokens(url, realm, client_id, rft)
        tokens_json = json.dumps({
            "pid": os.getpid(),
            "timestmamp": time.ctime(),
            "access_token": n['access_token'],
            "refresh_token": n['refresh_token']
        })
        try:
            path_to_tokens_dir.mkdir(parents=True, exist_ok=True)
            with open(Path(path_to_tokens_file), 'w', encoding='UTF-8') as file:
                file.write(tokens_json)
        except OSError as error:
            print('Error writing configuration file', error)

        time.sleep(timeout)

def check_pid(pid):        
    """ Check for the existence of a unix pid."""
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True

def kill_by_pid(pid: int) -> bool:
    if check_pid(pid):
        os.kill(int(pid), signal.SIGTERM)
        print(f"Killed token manager process with PID {pid}")
        return True
    return False
