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
"""Command-line interface (CLI) for managing user authentication when using IQM quantum computers.
"""
from importlib.metadata import PackageNotFoundError, version  # type: ignore
import warnings

try:
    DIST_NAME = 'iqm-cortex-cli'
    __version__ = version(DIST_NAME)
except PackageNotFoundError:
    __version__ = 'unknown'
finally:
    del version, PackageNotFoundError

warnings.warn(
    DeprecationWarning(
        'The iqm-cortex-cli package is deprecated and new versions of Cortex CLI will be published as part of '
        'iqm-client. Please uninstall iqm-cortex-cli and install iqm-client[cli] to get the newest version.'
    )
)
