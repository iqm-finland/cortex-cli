#!/usr/bin/env bash
check_imports() {
  OUTPUT=$(isort cortex_cli/**.py --diff)
  echo "$OUTPUT"
  [ -z "$OUTPUT" ] || exit 1
}

set -e
pycodestyle cortex_cli/
pylint -s no cortex_cli/
check_imports
