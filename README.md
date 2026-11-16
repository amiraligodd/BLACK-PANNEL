# KING_PANNEL

Single-admin panel for Xray (VMess, VLESS, Trojan and VLESS-HU over WebSocket/HTTPUpgrade) behind Caddy.

Deploy: push this repository to the branch connected to your host. The `Dockerfile` builds everything.

## Variables

| Name | Purpose |
|---|---|
| `ADMIN_PASSWORD` | Optional. If set, the panel owner is `ADMIN_USER` with this password and no setup page is shown. |
| `ADMIN_USER` | Username used together with `ADMIN_PASSWORD` (default `admin`). |
| `SETUP_KEY` | Optional. If set, the first-run setup page is only reachable at `/login?key=<SETUP_KEY>`. |
| `PORT` | HTTP port. Set automatically by the host. |
| `DOMAIN` | Optional. By default config links use the host the panel was opened with. |
| `PANEL_TITLE` | Optional. Defaults to `KING_PANNEL`. |

## First run

Without `ADMIN_PASSWORD`, the first visit to the site shows a setup page where the new owner chooses a username and password. After that the page is closed for good. Open the link right after deploying, or set `SETUP_KEY` so only people who know the key can reach the setup page. To reset a forgotten password, set `ADMIN_PASSWORD` and redeploy.

## Persistence

Mount a volume at `/data`, otherwise users and the password reset on every deploy.

## Endpoints

`/admin` panel, `/login`, `/sub/<token>` subscription, `/healthz` health check.
