=========
Changelog
=========

Version 2.2
===========

* Tokens file gets deleted and logout succeeds even if the authentication server is not available `#32 <https://github.com/iqm-finland/cortex-cli/pull/32>`_

Version 2.1
===========

* The user can now specify the output format for ``cortex circuit run``: human-readable ``--output frequencies``, ``--output shots`` or machine-readable raw ``RunResult`` ``--output json``. `#31 <https://github.com/iqm-finland/cortex-cli/pull/31>`_

Version 2.0
===========

* Replace qubit mapping with QASM qubit placement. `#30 <https://github.com/iqm-finland/cortex-cli/pull/30>`_

Version 1.6
===========

* Gracefully handle token files with outdated format. `#28 <https://github.com/iqm-finland/cortex-cli/pull/28>`_

Version 1.5
===========

* Make circuit execution an optional functionality, which requires to install additional dependencies. `#27 <https://github.com/iqm-finland/cortex-cli/pull/27>`_

Version 1.4
===========

* Fix typing issue related to upgrading to cirq-on-iqm 7.7. `#25 <https://github.com/iqm-finland/cortex-cli/pull/25>`_

Version 1.3
===========

* Remove settings from circuit run command. `#24 <https://github.com/iqm-finland/cortex-cli/pull/24>`_
* Upgrade to iqm-client 8.0. `#24 <https://github.com/iqm-finland/cortex-cli/pull/24>`_

Version 1.2
===========

* Fix a bug in handling tokens received from auth server. `#23 <https://github.com/iqm-finland/cortex-cli/pull/23>`_

Version 1.1
===========

* Token manager will keep trying indefinitely to re-connect to auth server. `#22 <https://github.com/iqm-finland/cortex-cli/pull/22>`_

Version 1.0
===========

* Enable foreground mode for token manager. `#20 <https://github.com/iqm-finland/cortex-cli/pull/20>`_
* Flag ``--no-daemon`` of the ``cortex auth login`` command is renamed to ``--no-refresh``. `#20 <https://github.com/iqm-finland/cortex-cli/pull/20>`_
* Flag ``--no-daemon`` now starts the token manager in foreground mode. `#20 <https://github.com/iqm-finland/cortex-cli/pull/20>`_
* Breaking change. The format of the configuration file is changed: ``base_url`` renamed to ``auth_server_url``. `#20 <https://github.com/iqm-finland/cortex-cli/pull/20>`_
* Breaking change. The format of the tokens file is changed: ``timestamp`` format is changed to ISO. `#20 <https://github.com/iqm-finland/cortex-cli/pull/20>`_
* Configuration and tokens files' formats are now validated by Cortex CLI. `#20 <https://github.com/iqm-finland/cortex-cli/pull/20>`_

Version 0.11
============

* ``--no-auth`` and ``--config-file`` are now mutually exclusive `#19 <https://github.com/iqm-finland/cortex-cli/pull/19>`_

Version 0.10
============

* Upgrade to iqm-client 7.0 `#18 <https://github.com/iqm-finland/cortex-cli/pull/18>`_
* Report the ID of the calibration set that was used in circuit run when no settings were specified. `#18 <https://github.com/iqm-finland/cortex-cli/pull/18>`_

Version 0.9
===========

* Enable mypy checks. `#17 <https://github.com/iqm-finland/cortex-cli/pull/17>`_
* Update source code according to new checks in pylint v2.15.0. `#17 <https://github.com/iqm-finland/cortex-cli/pull/17>`_

Version 0.8
===========

* Upgrade ``cirq-iqm`` to 7.3. `#15 <https://github.com/iqm-finland/cortex-cli/pull/15>`_

Version 0.7
===========

* iqm-client 6.1 support. `#13 <https://github.com/iqm-finland/cortex-cli/pull/13>`_
* Allow user to provide a custom ``calibration_set_id`` when using ``cortex circuit run``. `#13 <https://github.com/iqm-finland/cortex-cli/pull/13>`_
* Update documentation regarding the use of Cortex CLI. `#13 <https://github.com/iqm-finland/cortex-cli/pull/13>`_

Version 0.6
===========

* iqm-client 6.0 support. `#14 <https://github.com/iqm-finland/cortex-cli/pull/14>`_

Version 0.5
===========

* Partial Windows support (no token manager daemon)
* Performance improvements for faster loading time

Version 0.4
===========

* Bump iqm-client dependency to 5.0
* Remind the user to login before using operations requiring authentication

Version 0.3
===========

* Fix tests for iqm-client 4.3

Version 0.2
===========

* Added circuit commands ``cortex circuit validate`` and ``cortex circuit run``

Version 0.1
===========

* Authentication token manager daemon
* Multiple configurations support
