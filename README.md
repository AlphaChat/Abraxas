# Abraxas
AlphaChat's DroneBL Reporting Bot for SSH Server Abuse 

---

This is a Python asyncio script (using the [Pydle IRC Client Framework](https://pydle.readthedocs.io/en/stable/)) to
take SSH server messages from your system log (via an IRC channel) and parse them for abuse. It then tallies the
abuse event counts for each IP address it has seen and submits them to [DroneBL](https://dronebl.org/docs/what) when
the event count for that address crosses a predefined threshold.

You will need to have your system log in an IRC channel because this script expects that. We have our system logs in
an IRC channel so that we actually pay attention to the log messages. You may also need to adjust the "startswith"
line in the source code depending upon the nicknames of your system logging bots.

---

GitHub Issues is disabled for this repository. There is no support provided for this software.
