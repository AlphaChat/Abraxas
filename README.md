# Abraxas
AlphaChat's DroneBL Reporting Bot for SSH Server Abuse 

---

This is a Python asyncio script (using the [Pydle IRC Client Framework](https://pydle.readthedocs.io/en/stable/)) to
take SSH server messages from your system log (via an IRC channel) and parse them for abuse. It then tallies the
abuse event counts for each IP address it has seen and submits them to [DroneBL](https://dronebl.org/docs/what) when
the event count for that address crosses a predefined threshold.

Because of the way that the AlphaChat IRC Network's SSH servers are configured, bots cannot actually make it far
enough into the SSH negotiation to attempt a username, let alone a password. Specifically, we force a host key
algorithm that includes an [SSH certificate](https://medium.com/@berndbausch/ssh-certificates-a45bdcdfac39), not a
public key, and we limit our key exchange algorithms to [NTRU](https://en.wikipedia.org/wiki/NTRU) and
[Curve25519](https://en.wikipedia.org/wiki/Curve25519). In our experience, not a single abusive SSH bot/worm is
currently (as of writing) capable of negotiating an SSH session with these parameters.

You will need to have your system log in an IRC channel because this script expects that. We have our system logs in
an IRC channel so that we actually pay attention to the log messages. You may also need to adjust the "startswith"
line in the source code depending upon the nicknames of your system logging bots.

---

GitHub Issues is disabled for this repository. There is no support provided for this software.
