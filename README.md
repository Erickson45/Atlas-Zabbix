# Atlas — Zabbix / AIOps Module (portfolio excerpt)

This is a **sanitized excerpt** of the monitoring/alerting engine from **Atlas**, an internal AIOps platform I built at my current job to centralize Zabbix alerts, automate triage, and speed up incident response. The full platform (Flask app, auth, Teams/email notifications, chat assistant, etc.) is internal company software and is being discontinued — this module is shared here purely as a portfolio/code-sample piece, with my employer's permission.

**This is not a runnable standalone app.** It imports from sibling modules (`models`, `extensions`, `azure_auth`, etc.) that aren't included here, and some values have been replaced with placeholders — see **What was changed** below. Treat it as a reading sample of the Zabbix integration and dashboard logic, not something you `pip install` and run.

## What's here

- `zabbix_logic.py` — Zabbix API client, alert ingestion/caching (Redis-backed), executive-report grouping logic, auto-assignment ("round robin") of incidents to team members, and the Flask blueprint exposing this to the rest of the app.
- `templates/zabbix_dashboard.html` — the real-time dashboard template (Socket.IO-driven) that renders the alert feed, filters, and stats shown to the NOC team.

## What was changed before publishing

Every change is also flagged inline with a `NOTE (public/portfolio version)` comment at the exact spot it was made, so nothing is hidden:

1. **Internal hostnames → placeholders.** `ZABBIX_FRONT_URL` and the HTML `dnsBase`/`ipBase` constants pointed at this company's real Zabbix front-end URL and an internal fallback IP. Replaced with `https://zabbix.example.com` / `http://10.0.0.10`, now also overridable via env vars (`ZABBIX_FRONT_URL`, `ZABBIX_FRONT_URL_FALLBACK`).
2. **Real client list → generic placeholders.** `DEFAULT_PJ_GROUPS` originally listed real Zabbix host-group names that map to real client organizations. Replaced 1:1 with generic `CLIENTE_01`, `CLIENTE_02`, ... placeholders, keeping only the genuinely generic infra entries (`_Zabbix Proxy`, `_Zabbix Server`, `VPN`, `GITLAB`). The filtering logic itself is untouched.
3. A duplicated hardcoded URL (the "V4 fallback" link builder) now reuses the `ZABBIX_FRONT_URL` constant instead of repeating the literal string — a small cleanup that also removes the second copy of the real hostname.

Nothing else (variable names, logic, comments, structure) was altered — this is the real code I wrote, minus the data that identifies the company or its clients.

## Why this exists

Most of what I do day to day is reactive — responding to alerts as they come in. Atlas (and this module specifically) came from asking a more proactive question: instead of a human reading every alert, could the system itself correlate alerts, suppress noise, auto-assign work fairly across the team, and hand back a clean executive summary? This file is the part of that answer that talks to Zabbix directly.

## Stack

Python, Flask (Blueprint), Redis (caching + distributed locks), SQLAlchemy, Zabbix API (JSON-RPC), Socket.IO (real-time push to the dashboard). The full platform runs in production containerized with **Docker**, behind **Nginx** as reverse proxy, with **PostgreSQL** as the primary datastore.

## License

MIT — this excerpt is shared for portfolio/learning purposes. See [LICENSE](LICENSE).
