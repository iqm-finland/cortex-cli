=========
Changelog
=========

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
