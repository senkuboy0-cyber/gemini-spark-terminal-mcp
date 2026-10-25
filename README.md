<div align="center">

<img src="assets/icon.svg" width="128" height="128" alt="Terminal MCP logo">

# Terminal MCP for Gemini Spark

**A full Ubuntu terminal inside Gemini Spark.**
Run commands, edit files, zip things up, and get direct download links — all from chat.

![Node](https://img.shields.io/badge/node-26-3ddc84?style=flat-square&logo=node.js&logoColor=white)
![Python](https://img.shields.io/badge/python-3.15-4f8cff?style=flat-square&logo=python&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-Streamable%20HTTP-4f8cff?style=flat-square)
![OAuth](https://img.shields.io/badge/OAuth%202.1-DCR%20%2B%20PKCE-a66bff?style=flat-square)
![Dependencies](https://img.shields.io/badge/dependencies-0-ff6fb1?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)

</div>

---

## ✨ Highlights

- 🧰 **11 tools** covering shell, processes, files, archives, downloads, code, packages, HTTP, env and system info
- 🔗 **Direct download links** for *any* file — `.py`, `.kt`, `.zip`, `.apk`, images… open the link and the download starts
- 🗜️ **Archives** — create and extract `zip`, `tar.gz`, `tar`, `7z`, `rar`
- ⏱️ **Flexible timeouts** — 60 s by default, no fixed upper limit
- 🔐 **OAuth 2.1** with Dynamic Client Registration, PKCE `S256` and a consent password
- 🎨 **Logo** served everywhere a client might look (MCP `serverInfo.icons`, favicon, OAuth `logo_uri`)
- 📦 **Zero npm dependencies** — a single `server.js`

---

## 🛠️ Tools

| # | Tool | Actions | What it does | Safety |
|:-:|------|---------|--------------|:------:|
| 1 | `run_shell_command` | — | Run any bash command. `cwd`, `env`, `timeout`, `background` | ⚡ |
| 2 | `manage_background_process` | `list` · `output` · `wait` · `kill` | Manage background jobs | 🟡 |
| 3 | `read_files` | `read` · `info` · `list` · `find` · `grep` | Read-only file access | 🟢 |
| 4 | `write_files` | `write` · `append` · `edit` · `mkdir` · `copy` · `move` · `delete` | Change files and folders | 🔴 |
| 5 | `manage_archives` | `create` · `extract` · `list` | zip / tar.gz / tar / 7z / rar, optional share link | 🔴 |
| 6 | `create_download_link` | `create` · `list` · `revoke` | Direct download link for any file (folders auto-zipped) | 🟡 |
| 7 | `run_code_snippet` | — | Run Python, Node.js or Bash snippets, with `stdin`. `cloudscraper` preinstalled | ⚡ |
| 8 | `manage_packages` | `install` · `uninstall` · `list` · `search` | apt, pip, npm | 🔴 |
| 9 | `http_request` | modes `raw` · `text` · `download` | Call APIs, read pages, download to server | 🟡 |
| 10 | `manage_env_variables` | `get` · `set` · `unset` · `list` | Environment variables, secrets masked | 🟡 |
| 11 | `get_system_info` | — | OS, CPU, RAM, disk, uptime, versions | 🟢 |

🟢 read-only · ⚡ runs without a confirmation prompt · 🟡 moderate · 🔴 destructive (Spark asks before running)

---

## 🔗 Download links

Any file on the server can become a link:

```text
https://<your-service>.onrender.com/dl/<signed-token>/main.kt
```

- Opening it **starts the download immediately** (`Content-Disposition: attachment`)
- Supports **resume** (HTTP `Range`)
- Default lifetime **24 hours** (`expires_hours`, up to 30 days), optional `max_downloads`
- Tokens are **HMAC-signed** — they cannot be guessed, and no login is needed to download
- Revoke any time with `create_download_link` → `revoke`

Shortcuts: `manage_archives` → `create` with `share: true`, or `http_request` → `download` with `share: true`, return a link in the same step.

> ⚠️ On Render's free tier the disk is temporary. When the service sleeps or redeploys, files and their links disappear — download soon after creating a link.

---

## 🚀 Connect to Gemini Spark

1. Open **gemini.google.com** → **Settings & help** → **Connected Apps**
2. Under **Custom apps for Spark**, click **Add a custom app**
3. Paste your MCP URL:
   ```text
   https://<your-service>.onrender.com/mcp
   ```
4. Click **Next** — Spark registers itself automatically (no client ID needed)
5. Enter your **consent password** on the approval page

> Requirements: a personal Google account with Spark access, 18+, in a supported country, English, Keep Activity on. Custom apps work in interactive Spark chats.

---

## ☁️ Deploy on Render

1. Fork or push this repo to GitHub
2. Create a **Web Service** → **Docker** runtime
3. Set environment variables:

| Variable | Required | Purpose |
|----------|:--------:|---------|
| `JWT_SECRET` | ✅ | Signs OAuth tokens and download links. Keep it fixed. |
| `CONSENT_PASSWORD` | ✅ | Typed on the approval page when connecting |
| `PUBLIC_URL` | — | Override the public base URL (Render sets `RENDER_EXTERNAL_URL` automatically) |
| `SHARE_DIR` | — | Where folder zips for links are stored (default `/tmp/spark-mcp-share`) |

4. Deploy. Health check: `GET /health`

### Run locally

```bash
JWT_SECRET=dev CONSENT_PASSWORD=dev node server.js
# MCP endpoint: http://localhost:10000/mcp
```

---

## 🧪 Runtime

| Tool | Version |
|------|---------|
| Ubuntu | 24.04 LTS |
| Node.js | 26.x (latest, LTS from Oct 28 2026) + latest npm |
| Python | 3.15 (latest stable, via uv) + latest pip |
| git | latest (git-core PPA) |
| Python packages | `cloudscraper`, `requests` |
| Archives | zip, unzip, 7z, tar, gzip, xz, unrar |

---

> Old v1.0 tool names (`run_command`, `fs_read`, `share_file`, …) are still accepted for compatibility.

## 🔐 Security

- `run_shell_command` gives **full shell access** — treat the consent password like a root password
- `run_shell_command` and `run_code_snippet` are marked so Spark runs them **without asking each time**
- `JWT_SECRET` and `CONSENT_PASSWORD` are **stripped from every child process**, hidden from `manage_env_variables`, and cannot be changed through tools
- `manage_env_variables list` masks anything that looks like a key, token, secret or password, and credentials inside URLs
- `write_files delete` refuses protected paths (`/`, `/etc`, `/usr`, `/bin`, `/var`, …) and needs `recursive: true` for folders
- Access tokens last **1 hour**, refresh tokens **30 days**
- Tool output is capped at **~100 KB** per call

---

## 🎨 Logo

Drawn in code (`assets/icon.svg`, rendered to PNG/ICO). Served at:

| Path | Format |
|------|--------|
| `/icon.png` | PNG 512×512 |
| `/icon-192.png` | PNG 192×192 |
| `/apple-touch-icon.png` | PNG 180×180 |
| `/icon.svg` | SVG |
| `/favicon.ico` | ICO 16–64 |

Also advertised in the MCP `initialize` response (`serverInfo.icons`) and the OAuth registration (`logo_uri`). Whether a client shows it is up to the client.

---

## 📁 Project structure

```text
.
├── server.js      # MCP server, OAuth, tools, download links
├── assets/
│   ├── icon.svg   # logo source
│   ├── icon.png   # 512×512 render
│   └── …          # 192px, apple-touch, favicon.ico
├── Dockerfile     # Ubuntu 24.04 + Node 26 + Python 3.15 + archive tools
└── package.json
```

---

<div align="center">
<sub>MIT License · Built for Gemini Spark custom apps</sub>
</div>
