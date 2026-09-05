---
name: vnt-operations
description: "Operate VNT 2 clients and self-hosted VNTS servers: run packaged programs, author client TOML configuration, call authenticated client or server Web APIs, and deploy VNTS with Linux systemd. Use for VNT runtime, configuration, API automation, troubleshooting, or server deployment tasks; do not use for unrelated Rust development."
---

# VNT Operations

Use the packaged VNT programs and their supported APIs. Treat the checked-in source as the authority when a local build differs from this skill.

## Route the task

- For `vnt2_cli`, `vnt2_ctrl`, `vnt2_web`, the desktop client, or client TOML/CLI parameters, read [references/client-usage.md](references/client-usage.md).
- For the `vnt2_web` or desktop Web-access API, read [references/client-web-api.md](references/client-web-api.md).
- For building, installing, configuring, upgrading, or troubleshooting the self-hosted server in `D:\rust\vnts`, read [references/server-deployment.md](references/server-deployment.md).
- For the VNTS administrative API, read [references/server-web-api.md](references/server-web-api.md).
- For repeatable HTTP calls, use [scripts/vnt_api.py](scripts/vnt_api.py). Run `python scripts/vnt_api.py --help` and the relevant subcommand help before first use.

Read only the references required by the current request. If behavior appears version-dependent, check the current binary's `--help`/`--conf-example` or the source paths named in the relevant reference before acting.

## Acquire API access

Client and server authentication are separate and their tokens are not interchangeable.

For a client Web API task, if access data is missing, ask for either:

- the complete access URL printed by `vnt2_web`, such as `http://host:19099/?token=...`; or
- the API base URL and Web access token separately.

Parse the `token` query parameter, remove it from subsequent request URLs, and send it only as `Authorization: Bearer <token>`. Probe `/api/version` and `/api/runtime` before relying on the rest of the API.

For a VNTS administrative API task, if access data is missing, ask for the management base URL, username, and password. Log in at `/api/login`, then use the returned JWT as the Bearer token. A client Web token does not authenticate to VNTS.

Never echo secrets, include them in summaries, commit them, or persist them in the skill/repository. Prefer the helper's stdin or environment-variable inputs over command-line secret arguments. Redact credentials from errors. On `401`, refresh or request credentials once; if the retry also fails, stop and report the authentication failure.

## Respect operation scope

Read-only inspection may proceed when it is relevant. Start, stop, restart, save, or update only when the user's request authorizes that mutation. Before a delete that was not already explicit, identify the exact instance, configuration, network, device, or peer server and obtain confirmation.

After a mutation, read back the affected resource or status. For asynchronous client startup, poll `/api/start/status` until `Running` or `Stopped`, report the terminal state, and include useful logs without credentials.

For remote deployment, establish the target host, architecture, SSH access method, public name/address, and intended open ports before changing the host. Do not assume access to a production server merely because the local `D:\rust\vnts` source is available.
