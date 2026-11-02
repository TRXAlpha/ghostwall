# Security

Please report vulnerabilities privately through GitHub:
[Security → Report a vulnerability](https://github.com/TRXAlpha/ghostwall/security/advisories/new).
Do not open a public issue for them. I aim to reply within a week.

In scope: anything that lets someone on the network, a website in your browser, or a
crafted DNS name or log line change Ghostwall's state, read data they shouldn't, run
code, or break DNS. The dashboard (`agents/web_ui`) and the query-log parsers
(`agents/ghost_dns/shadow.py`) are the most exposed parts.

Out of scope: anything that needs root or the `ghostwall` user on the box already. The
control API on `127.0.0.1:5380` takes actions only with the token in
`/var/lib/ghostwall/control_token`; getting past that, or past its loopback-`Host` and
JSON-only checks from a browser, is in scope. So is the capture API on `127.0.0.1:5381`,
which has the same browser checks but no token (it can only start a bounded number of
pcap freezes for known devices).

The services run as the unprivileged `ghostwall` user; ghost-dns holds only
`CAP_DAC_READ_SEARCH` (to read the DNS server's query log) and `CAP_NET_BIND_SERVICE`.
