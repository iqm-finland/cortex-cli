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
