# Copyright 2021-2023 IQM client developers
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
from datetime import datetime
import json
import os
from pathlib import Path
import platform
import time
from typing import Optional, Tuple

from psutil import pid_exists
from requests.exceptions import ConnectionError, Timeout  # pylint: disable=redefined-builtin

from cortex_cli.auth import AUTH_REQUESTS_TIMEOUT, ClientAuthenticationError, refresh_request
from cortex_cli.models import ConfigFile

if not platform.system().lower().startswith('win'):
    import daemon

import tempfile
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT = b'\x05\xd58Y\xfa\x8e\xe1o\xb74=:\x9c\xe9\x82e'


def daemonize_token_manager(cycle: int, config: ConfigFile, password: str, logfile: Optional[str] = None) -> None:
    """Start a daemon process.
    Args:
        cycle: refresh cycle in seconds
        config: Cortex CLI configuration
        logfile: path to file for writing errors
        password: decryption key for tokens file
    """
    logfile = (
        logfile
        if logfile is not None
        else f'{os.environ.get("XDG_STATE_HOME", f"{Path.home()}/.local/state")}/iqm-cortex-cli/token_manager.log'
    )
    os.makedirs(os.path.dirname(logfile), exist_ok=True)

    with open(logfile, 'w', encoding='UTF-8') as output:
        with daemon.DaemonContext(stdout=output, stderr=output):
            start_token_manager(cycle, config, password)


def start_token_manager(cycle: int, config: ConfigFile, password: str, single_run: bool = False) -> None:
    """Refresh tokens periodically.

    For each refresh cycle new tokens are requested from auth server.
    - If refresh is successful next refresh is attempted in the next cycle.
    - If auth server does not respond refresh is attempted repeatedly until it succeeds or
      the existing refresh token expires.
    - If auth server responds but returns an error code or invalid tokens token manager is stopped.

    Args:
        cycle: refresh cycle in seconds
        config: Cortex CLI configuration
        password: decryption key for tokens file
        single_run: if True, refresh tokens only once and exit; otherwise repeat refreshing indefinitely
    """

    temp = tempfile.NamedTemporaryFile(prefix='iqm_auth_token_')
    with open(Path(config.proxy_tmp_file), 'w', encoding='UTF-8') as file:
        file.write(temp.name)

    print(
        f"""
To use the tokens file with IQM Client or IQM Client-based software, set the environment variable:

export IQM_TOKENS_FILE={temp.name}

Refer to IQM Client documentation for details: https://iqm-finland.github.io/iqm-client/
"""
    )

    while True:
        tokens_file = str(config.tokens_file)
        tokens = read_tokens(tokens_file, password)

        new_tokens, status, sleep_time = refresh_tokens(config, tokens, cycle)
        if new_tokens is None:
            break

        write_tokens(tokens_file, config.auth_server_url, status, password, **new_tokens)

        temp.write(json.dumps(tokens).encode())
        temp.seek(0)

        if single_run:
            break

        time.sleep(sleep_time)

    print(f'{datetime.now().strftime("%m/%d/%Y %H:%M:%S")}: Token manager stopped')
    os.remove(config.proxy_tmp_file)  # NOTE: these will not run if process is
    temp.close()  # terminated e.g. via keyboard interrupt


def read_tokens(path_to_tokens_file: str, password: str) -> dict:
    """
    Read current tokens from the tokens file.

    Args:
        path_to_tokens_file: path to the encrypted tokens file
        password: decryption key

    Returns:
        dict containing the tokens
    """
    with open(path_to_tokens_file, 'r', encoding='utf-8') as file:
        try:
            tokens_data = _decrypt_text(file.read(), password, SALT)
        except InvalidToken:
            print(f'Invalid password for decrypting file {path_to_tokens_file}')
            exit()
        tokens = json.loads(tokens_data)
    return tokens


def refresh_tokens(config: ConfigFile, current_tokens: dict, cycle: int) -> Tuple[Optional[dict], bool, int]:
    """
    Request new tokens from auth server.

    Args:
        config: Cortex CLI configuration
        current_tokens: dict containing the current tokens from the tokens file
        cycle: refresh cycle length in seconds

    Returns:
        Tuple[Optional[dict], bool, int] = (tokens, status, sleep_time)
        tokens: dict containing new tokens or current tokens if auth server could not be connected or
                None if auth server refused to provide new tokens.
        status: bool, True if tokens were refreshed successfully, False otherwise
        sleep_time: time to sleep before next refresh attempt
    """
    access_token = current_tokens.get('access_token', '')
    refresh_token = current_tokens.get('refresh_token', '')
    try:
        tokens = refresh_request(config.auth_server_url, config.realm, config.client_id, refresh_token)
        status = True
        sleep_time = cycle
        log_timestamp = datetime.now().strftime('%m/%d/%Y %H:%M:%S')
        print(f'{log_timestamp}: Tokens refreshed successfully.')
    except (Timeout, ConnectionError) as ex:
        # No connection to auth server or auth server did not respond, keep current tokens
        tokens = {'access_token': access_token, 'refresh_token': refresh_token}
        status = False
        if isinstance(ex, ConnectionError):
            sleep_time = AUTH_REQUESTS_TIMEOUT
        else:
            sleep_time = 1
        log_timestamp = datetime.now().strftime('%m/%d/%Y %H:%M:%S')
        print(f'{log_timestamp}: No response from auth server: {ex}')
    except ClientAuthenticationError as ex:
        # Auth server responded but no valid tokens were received
        tokens = None
        status = False
        sleep_time = cycle
        log_timestamp = datetime.now().strftime('%m/%d/%Y %H:%M:%S')
        print(f'{log_timestamp}: Failed to authenticate with auth server: {ex}')

    return tokens, status, sleep_time


def write_tokens(
    path_to_tokens_file: str,
    auth_server_url: str,
    status: bool,
    password: str,
    *,
    access_token: str = '',
    refresh_token: str = '',
) -> None:
    """
    Write new tokens into the tokens file.

    Args:
        path_to_tokens_file: path to the tokens file
        auth_server_url: base URL of the auth server
        status: refresh status, True when successful, False otherwise
        password: decryption key for tokens file
        access_token: new access token
        refresh_token: new refresh token
    """
    tokens_json = json.dumps(
        {
            'pid': os.getpid(),
            'timestamp': datetime.now().isoformat(),
            'refresh_status': 'SUCCESS' if status else 'FAILED',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'auth_server_url': auth_server_url,
        }
    )

    tokens_data_content = _encrypt_text(tokens_json, password, SALT)

    try:
        Path(path_to_tokens_file).parent.mkdir(parents=True, exist_ok=True)
        with open(Path(path_to_tokens_file), 'w', encoding='UTF-8') as file:
            file.write(tokens_data_content)
    except OSError as error:
        print('Error writing tokens file', error)


def check_token_manager(tokens_file: str, password: str) -> Optional[int]:
    """Check whether a token manager related to the given tokens_file is running.
    Args:
        tokens_file: Path to a tokens JSON file.
        password: decryption key for tokens file
    Returns:
        Optional[int]: PID of the process if process is running, None otherwise.
    """
    with open(tokens_file, 'r', encoding='utf-8') as file:
        try:
            tokens_data = json.loads(_decrypt_text(file.read(), password, SALT))
        except InvalidToken:
            print(f'Invalid password for decrypting file {tokens_file}')
            exit()

    pid = tokens_data['pid'] if 'pid' in tokens_data else None

    if pid and pid_exists(pid):
        return pid
    return None


def _get_kdf(salt: bytes) -> PBKDF2HMAC:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf


def _encrypt_text(text: str, password: str, salt: bytes) -> str:
    encryption_key = password.encode()
    kdf = _get_kdf(salt)
    key = base64.urlsafe_b64encode(kdf.derive(encryption_key))
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()


def _decrypt_text(text: str, password: str, salt: bytes) -> str:
    encryption_key = password.encode()
    kdf = _get_kdf(salt)
    key = base64.urlsafe_b64encode(kdf.derive(encryption_key))
    f = Fernet(key)
    return f.decrypt(text).decode()
