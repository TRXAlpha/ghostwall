# Security

Please report vulnerabilities privately through GitHub:
[Security → Report a vulnerability](https://github.com/TRXAlpha/ghostwall/security/advisories/new).
Do not open a public issue for them. I aim to reply within a week.

In scope: anything that lets someone on the network, a website in your browser, or a
crafted DNS name or log line change Ghostwall's state, read data they shouldn't, run
code, or break DNS. The dashboard (`agents/web_ui`) and the query-log parsers
(`agents/ghost_dns/shadow.py`) are the most exposed parts.

Out of scope: the control API on `127.0.0.1:5380` having no authentication (by design,
loopback only), and anything that needs root on the box already.
