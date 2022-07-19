|CI badge| |Release badge|

.. |CI badge| image:: https://github.com/iqm-finland/cortex-cli/actions/workflows/ci.yml/badge.svg
.. |Release badge| image:: https://img.shields.io/github/release/iqm-finland/cortex-cli.svg

==========
Cortex CLI
==========

Command-line tool (CLI) for interacting with IQM quantum computers.

Installing Cortex CLI
---------------------

Requirements for installing:

- Python 3.9
- `Pip <https://pypi.org/project/pip/>`_

.. code-block:: bash

  $ pip install iqm-cortex-cli

Using Cortex CLI
----------------

For general usage instructions, run

.. code-block:: bash

  $ cortex --help

Initialization
^^^^^^^^^^^^^^

First, Cortex CLI needs initialization, which produces a configuration file. Run:

.. code-block:: bash

  $ cortex init

Cortex CLI will ask a few questions. You can also pass the values via command line to avoid having an interactive prompt. See ``cortex init --help`` for details.

Login
^^^^^

To login, use:

.. code-block:: bash

  $ cortex auth login

This will ask you to enter your login and password. After a successful authentication, tokens will be saved into a tokens file (path specified in the configuration file), and a token manager daemon will start in the background. Token manager will periodically refresh the session and re-write the tokens file. To login and get tokens once, without starting a token manager daemon, run ``cortex auth login --no-daemon``.

If the tokens file already exists, then running ``cortex auth login`` will first attempt to refresh the session without asking you for a login and password. If that fails (because existing tokens may've already expired), then you'll be asked to enter login and password.

See ``cortex auth login --help`` for more details.

Status
^^^^^^

To see the current status of the token manager daemon, use:

.. code-block:: bash

  $ cortex auth status

If tokens file exists, ``cortex auth status`` will report whether the corresponding token manager daemon is running. It will also print the time of the last successful refresh request, and how much time is left until current tokens are expired.

See ``cortex auth status --help`` for more details.

Logout
^^^^^^

To logout, run:

.. code-block:: bash

  $ cortex auth logout

This will send a logout request to the authentication server, kill the token manager daemon (if any), and delete the tokens file.

You may want to stop the token manager, but maintain the session on the server and keep the tokens file intact. To do so, run:

.. code-block:: bash

  $ cortex auth logout --keep-tokens

See ``cortex auth logout --help`` for more details.

Multiple configuration files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, all Cortex CLI commands read the configuration file from the default location ``~/.config/iqm-cortex-cli/config.json``. You can specify a different filepath by providing ``--config-file`` value, for example:

.. code-block:: bash

  $ cortex auth status --config-file /home/joe/config.json
  $ cortex auth login --config-file /home/joe/config.json
  $ cortex auth logout --config-file /home/joe/config.json

Circuit validation
^^^^^^^^^^^^^^^^^^

.. code-block:: bash

  $ cortex circuit validate my_circuit.qasm

validates the quantum circuit in file `my_circuit.qasm`, and reports errors if the circuit is not valid OpenQASM 2.0. The exit code is 0 if and only if the circuit is valid.

Executing circuits on a quantum computer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can execute a quantum circuit on an IQM quantum computer with

.. code-block:: bash

  $ export IQM_SERVER_URL="https://example.com/iqm-server"
  $ cortex circuit run --settings "path/to/settings.json" --shots 100 --qubit-mapping my_qubit_mapping.json my_circuit.qasm

The server URL and settings path can be set either with command-line options or as environment variables.

By default, authentication is handled the same way as with other Cortex CLI commands. You can override this and provide your own server url, username and password by setting environment variables IQM_AUTH_SERVER, IQM_AUTH_USERNAME and IQM_AUTH_PASSWORD.

Note that the circuit needs to be transpiled so that it only contains operations natively supported by the IQM quantum
computer you are using.

Run the following command:

.. code-block:: bash

  $ cortex circuit run --help

for information on all the parameters and their usage.

The results of the measurements in the circuit are returned in JSON format:

.. code-block:: json

  {"measurement_0":
    [
      [1, 0, 1, 1],
      [1, 0, 1, 1],
      [1, 0, 1, 1]
    ]
  }

The dictionary keys are measurement keys from the circuit. The value for each measurement is a 2-D array of binary
integers. The first index goes over the shots, and the second over the qubits in the measurement. For example, in the
example above, "measurement_0" is a 4-qubit measurement, and the number of shots is three.
