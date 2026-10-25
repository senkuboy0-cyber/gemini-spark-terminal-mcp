# Spark Terminal MCP

Minimal terminal MCP server built to connect to **Gemini Spark** as a custom app.

- Transport: Streamable HTTP at `/mcp` (JSON responses)
- Auth: OAuth 2.1 — RFC 9728 protected-resource metadata, RFC 8414 AS metadata, RFC 7591 dynamic client registration, PKCE S256, 302 redirect from `/authorize`
- Tools (test build): `execute_command`
- Zero npm dependencies, runs on Ubuntu 24.04 (Docker)

## Env vars
- `JWT_SECRET` – HMAC key for tokens (keep stable across deploys)
- `CONSENT_PASSWORD` – password typed on the consent page when connecting
- `PUBLIC_URL` – optional; defaults to `RENDER_EXTERNAL_URL`

## Connect to Spark
gemini.google.com → Settings & help → Connected Apps → Custom apps for Spark → Add a custom app → `https://<your-service>.onrender.com/mcp` → Next → enter consent password → Approve.

> Warning: this exposes a shell. Keep the consent password secret.
