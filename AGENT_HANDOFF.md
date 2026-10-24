# doorman — agent handoff

As of 2026-10-24. The browser-profile work is committed; see `git log` for
the current commit. This document is for another agent picking up the project.

## Purpose

`doorman` restricts network access for one Linux user (Arch) with two independent
policies:

1. **Browser** — block images, videos, and downloads unless explicitly allowed.
2. **Apps** — block an application's internet access unless its host is allowed.

The project deliberately avoids MITM for apps, keeps `wheel` until the user asks
for `--remove-wheel`, and uses nftables plus two local proxies.

## Architecture

Two listeners, two policies, one UID-scoped firewall:

| Listener | Process | Policy |
|---|---|---|
| `127.0.0.1:8080` | `mitmdump -s addon.py` | MITM; media/download blocking; browser host allowlist |
| `127.0.0.1:8081` | `strict_proxy.py` | No decryption; hostname allow/deny via SNI, Host, or CONNECT |

nftables (drop mode) matches the daily UID:

- allow DNS to the configured resolvers
- allow all loopback (local IPC and both proxies)
- drop all other TCP/UDP

The proxies run as a separate `doorman` system user, so their upstream
connections are not caught by the daily UID rule.

Root is exempt. That is intentional: it is both the recovery path and the
remaining bypass until `--remove-wheel`.

## Repo layout

| Path | Purpose |
|---|---|
| `addon.py` | Browser MITM policy on `:8080` |
| `strict_proxy.py` | Host allowlist proxy on `:8081` |
| `rules.py` | Shared host matching for the strict proxy |
| `allowlist.txt` | Default browser-exempt hosts |
| `downloads.conf` | Default browser download allow rules |
| `strict_allowlist.txt` | Default strict allowlist |
| `steam_allowlist.txt` | Steam hosts, merged into the strict allowlist |
| `scripts/install.sh` | One-shot Arch installer |
| `scripts/doorman-browser.sh` | Installed as `doorman-browser`; normal or configured Helium profile through `:8080` |
| `scripts/doorman-migrate-profile.sh` | Installed as `doorman-migrate-profile`; explicit profile migration |
| `scripts/doorman-firewall.sh` | `print`, `apply`, `status`, `revert`; `apply` validates and swaps atomically |
| `scripts/doorman-run.sh` | Dev launcher for the strict proxy |
| `wrap-chromium.sh` | Dev browser launcher with its own test profile |
| `wrap-helium.sh` | Dev browser launcher; normal Helium profile, optional dev proxy |
| `policy/internet-blocker.json` | Chromium policy (incognito/guest disabled) |
| `test_rules.py`, `test_addon.py`, `test_launcher.py`, `test_migrate.py` | Unit tests |
| `v0.5brainstorm.md` | Per-app policy design note |

## Installed layout

| Path | Contents |
|---|---|
| `/opt/doorman` | code, `.venv`, `Helium.AppImage` |
| `/etc/doorman` | **live rules**: `allowlist.txt`, `downloads.conf`, `strict_allowlist.txt`, `doorman.conf` |
| `/var/lib/doorman/mitmproxy` | mitmproxy CA certificate and key |
| `/var/log/doorman` | directory only; services log to journald |
| `/etc/systemd/system/doorman-{browser,strict,firewall}.service` | units |
| `/usr/local/bin/doorman-browser`, `doorman-run`, `doorman-migrate-profile` | launchers and migration helper |

`/etc/doorman` is generated on first install and preserved across reinstalls.
`--force` regenerates it. Do not edit the copies under `/opt/doorman` or the
repo and expect the running service to change.

## Live configuration

### `/etc/doorman/doorman.conf`

Written by the installer: daily user and UID, ports, strict default, Helium
path, NSS mode, CA path, and `BROWSER_PROFILE`. An empty `BROWSER_PROFILE`
means Helium's normal profile. The value is preserved across reinstalls unless
`--browser-profile` is passed.

### `/etc/doorman/allowlist.txt`

Browser-exempt hosts. A host also covers its subdomains. Scheme and port are
ignored. Current defaults: `wikipedia.org`, `192.168.0.250` (dashboard and
Jellyfin), `freetubeapp.io`, `chromewebstore.google.com`, `cdn.jsdelivr.net`,
`hcaptcha.com`, `youtube.com`.

### `/etc/doorman/downloads.conf`

Allowed browser downloads. Format:

```conf
type application/pdf
ext .iso
ext .tar.zst
```

Anything not listed is blocked. An empty file blocks all downloads. Current
defaults allow `.iso`, `.tar.zst`, `.appimage`, `.crx`.

### `/etc/doorman/strict_allowlist.txt`

Host allowlist for non-browser apps. The installer merges
`strict_allowlist.txt` + `steam_allowlist.txt` into this file on first install.
Current seed: `api.deepseek.com`, `example.com`, `wikipedia.org`,
`wikimedia.org`, plus the Steam hosts.

### `steam_allowlist.txt`

Covers login, APIs, community, avatars, game downloads, chat, and hCaptcha:

```
steamconnecttest.com
steamserver.net
steampowered.com
steamcommunity.com
steamusercontent.com
steamcommunity-a.akamaihd.net
steamuserimages-a.akamaihd.net
steamstatic.com
steamcontent.com
steamcdn-a.akamaihd.net
steampipe.akamaized.net
steam-chat.com
hcaptcha.com
```

There is **no blocklist** anymore. `steam_blocklist.txt` was removed. The store
and trailers are therefore reachable; only login/API separation would allow
blocking the store, and hostname filtering cannot do that.

**Steam Cloud is not covered.** Regional buckets such as
`steamcloud-eu-ams.storage.googleapis.com`,
`steamcloudfrankfurt.blob.core.windows.net`, and
`steamcloud-frf.s3.dualstack.eu-central-1.amazonaws.com` are added manually to
the live allowlist. Glob support (`steamcloud-*.storage.googleapis.com`) was
discussed but **not implemented**; `rules.matches()` only does exact and suffix
matching.

## Installer and modes

```bash
sudo scripts/install.sh --daily-user stan --no-upgrade \
    --default deny --enforce --trust-ca
```

- `--default deny` — strict proxy is allowlist-only.
- `--default allow` — strict proxy allows every host. Diagnostic only; it does
  not enforce "apps are blocked unless allowed".
- `--enforce` — applies nftables for the daily UID.
- `--no-enforce` — does not touch the firewall; it does **not** remove active
  rules. Use `systemctl stop doorman-firewall` or
  `nft delete table inet doorman`.
- `--ttl 15m` — schedules a root-owned revert; intended for first tests.
- `--trust-ca` — installs the CA system-wide and in NSS. Needed for
  `doorman-browser`; irrelevant to `doorman-strict`.
- `--browser-profile PATH` — use this Helium profile instead of the normal
  one, and preserve it in `doorman.conf` across reinstalls.
- `--remove-wheel` — final lockdown step. Requires an admin in `wheel` with a
  password. Run it only after verification.
- `--vm` — implies `--yes`, `--trust-ca`, and `pacman -Syu`.
- `--force` — regenerates live config, overwriting edits.

The installer now:

- rebuilds a venv that has `python` but no `pip`;
- refuses to finish if `:8080` or `:8081` is not listening after restart;
- stops a crash-looping strict proxy after 3 failures.

## Current state

Verified on the host:

- `doorman-browser` and `wrap-helium.sh` use Helium's normal profile by
  default, or the `BROWSER_PROFILE` from `doorman.conf`; Helium must be closed
  first. `doorman-migrate-profile` moves an older profile with a backup.
  `test_launcher.py` and `test_migrate.py` cover the paths and guards.
- `doorman-browser` blocks images, videos, and non-allowed downloads.
- `.iso` and `.tar.zst` downloads work; `.exe`, `.pdf`, `.iso.sig`,
  `.tar.zst.sig` are blocked.
- An app launched without a proxy has no internet under `--enforce`.
- Steam logs in and shows the library under `--default deny`.
- The Steam store is reachable (known limitation).
- The in-game overlay browser does not work in practice; it likely bypasses the
  proxy and is dropped by nftables. It is not selectively blocked by policy.
- The strict proxy crash loop caused by `--default "$STRICT_DEFAULT"` was fixed
  by unquoting the unit heredoc.
- 33 unit tests pass (including launcher, profile migration, SNI fuzz,
  CONNECT parsing, and reload); `py_compile`, `bash -n`, and `git diff --check`
  pass.
- The firewall validates a complete ruleset and swaps it in one nft
  transaction; a failed apply leaves the previous table in place.
- Malformed CONNECT or TLS input is logged (`BAD CONNECT`, `ERROR`) instead of
  killing the handler.
- `systemctl reload doorman-strict` reloads the strict allowlist; the browser
  allowlist is re-read when the file changes.

## Current limitations

- **One global app allowlist.** Every app that reaches `:8081` shares the same
  hosts. No per-app policy yet.
- **Loopback bypass.** An app can point itself at `:8080` and use the browser
  proxy, bypassing the strict allowlist for non-media traffic, or forge a
  `Referer` from an allowlisted site. Closing this needs per-process/cgroup
  rules or a separate browser UID.
- **Store cannot be blocked independently.** Login, checkout, and APIs share
  `steampowered.com`. The store tab and trailers remain reachable.
- **Overlay browser.** `steamwebhelper` inherits Steam's process tree. Under a
  future per-app cgroup it would inherit Steam's profile. Fully blocking it
  needs a separate cgroup or MITM/URL filtering.
- **Apps that ignore proxy env.** They are dropped in drop mode. Redirect mode
  exists but is IPv4-only and covers only TCP 80/443.
- **No glob matching.** Steam Cloud regional hosts need exact entries.
- **Header/extension-based browser checks.** `blob:`/`data:` downloads and
  mislabeled content bypass them.
- **Browser cache.** Cached responses do not hit the proxy; hard-reload or
  clear the site's cache. Clearing the whole profile would sign the user out.
- **CA trust.** With the normal profile and `--nss auto`, the CA is in the
  shared NSS store (`~/.pki/nssdb`) and system trust. `--nss own` makes
  `doorman-browser` point Helium at the doorman store instead, hiding client
  certificates from the shared store.
- **Custom browser profiles are explicit.** The installer cannot detect a
  wrapper or desktop file that passes `--user-data-dir`. Use
  `--browser-profile` or edit `BROWSER_PROFILE`; moving an old profile is an
  explicit `doorman-migrate-profile` step.
- **Steam network errors are misleading.** A full disk and other failures are
  reported as "needs to be online". Check `df -h /` and `ss -ltn | grep 8081`.
- **Root bypass.** `sudo`, `pacman`, and root network traffic are not filtered.
  `--remove-wheel` closes the ordinary sudo path, not root itself.
- **IPv6.** Transparent redirect is IPv4-only; drop mode drops IPv6 TCP/UDP.
- **Allowlist reload.** `strict_proxy` reloads on `SIGHUP`; the packaged unit
  has `ExecReload`, so use `systemctl reload doorman-strict`. Browser
  `allowlist.txt` is picked up on the next request; `downloads.conf` needs a
  `doorman-browser` restart.
- **Installer requires a Helium AppImage**, even for a strict-only host install.
  A missing AppImage aborts before the firewall step.
- **Git push is blocked by the project's own firewall.** The remote is SSH;
  port 22 is dropped. Use a temporary firewall stop or an SSH `ProxyCommand`
  through `:8081`.
- **No per-app attribution in logs.** The proxy logs host decisions, not which
  process made the request.

## Future ideas

### Per-app policies (v0.5)

Design note: `v0.5brainstorm.md`. Summary:

- Profiles under `/etc/doorman/apps/<name>.allow` and `.pending`.
- `doorman-run <app>` selects a proxy profile, e.g. via
  `http://steam:<token>@127.0.0.1:8081`.
- The proxy maps `Proxy-Authorization` to a profile.
- nftables places the app in a cgroup and allows only its proxy port plus DNS.
- `doorman-run --learn <app>` collects `DENY` hosts into `.pending`.
- `doorman-allow <app> --pending` appends and reloads.
- Overlay caveat: `steamwebhelper` inherits Steam's cgroup; fully blocking it
  needs a separate cgroup or MITM/URL rules.
- Recommended order: profiles + proxy auth, learn/allow commands, cgroup
  nftables, separate UID/netns only if hard isolation is needed.

### Modes

Two ports map naturally to two products:

- `doorman-mode browser` / lite: `:8080` only, no strict proxy, no firewall.
  Bypassable by design.
- `doorman-mode strict`: `:8080` + `:8081` + nftables.

Persist the mode in `/etc/doorman/doorman.conf`, make switching idempotent, and
check `nft list` rather than `systemctl status`.

### Other ideas

- Glob support in `rules.matches()` for regional Steam Cloud hosts.
- `doorman-shell`: a subshell with proxy env set, for interactive work.
- Structured JSON logs and per-app pending profiles.
- Browser extension/policy as an alternative to MITM for media/download rules.
- MITM with URL/path filtering for the Steam store and overlay (CA and pinning
  costs).
- Better redirect mode, including IPv6.
- Tests for known bypasses: loopback, forged `Referer`, blob downloads, cache.
- Password-delay / time-window feature for package installation (future).

## Testing and diagnostics

```bash
.venv/bin/python -m unittest -v test_rules test_addon test_launcher test_migrate

journalctl -u doorman-strict -f
journalctl -u doorman-browser -f

systemctl reload doorman-strict   # re-read /etc/doorman/strict_allowlist.txt

ss -ltn | grep -E '8080|8081'
sudo nft list table inet doorman
systemctl status doorman-browser doorman-strict doorman-firewall --no-pager
```

Strict proxy log lines:

- `ALLOW host`
- `DENY host`
- `DRYRUN host`
- `UPSTREAM host:port failed: ...`

## Important gotchas

- Edit **`/etc/doorman`**, not the repo copies, after install. The browser
  profile is `BROWSER_PROFILE` in `doorman.conf`.
- Use `doorman-migrate-profile` (with Helium closed) to move an old profile;
  do not copy profile directories by hand.
- Start `doorman-browser` or `wrap-helium.sh` only when Helium is closed. A
  second launch joins the running instance, which has no proxy, so both
  launchers refuse.
- Reload or restart the matching service after editing:
  `systemctl reload doorman-strict` for the strict allowlist (restart also
  works), `systemctl restart doorman-browser` for `downloads.conf` (browser
  allowlist edits are picked up automatically).
- `--default allow` means "allow every host", not "use the allowlist for the
  rest". It is not an enforcement mode.
- `--no-enforce` does not undo active nftables rules.
- `--ttl` reverts nftables but leaves the unit enabled; check `nft list`.
- The daily UID can reach both proxies; this is a known bypass.
- `doorman-run` only exports proxy env and execs. It does not filter anything.
- The strict proxy logs to journald, not `/var/log/doorman`.
- `git push` over SSH is dropped while enforcement is on. Workarounds:
  temporarily stop `doorman-firewall`, or use an SSH `ProxyCommand` through
  `:8081` after allowlisting `github.com`.

## Security model

- Policy is enforced per UID, not per binary.
- The strict proxy decides by hostname; it does not decrypt TLS.
- Root is exempt; `--remove-wheel` is the normal lockdown step.
- The browser proxy MITMs; the app proxy does not.
- Proxy environment variables are routing, not enforcement. A process can clear
  them; the firewall is what blocks direct traffic.
- `Referer` is spoofable and is a browser convenience, not a security boundary.

## Git state

The browser-profile work is committed; see `git log` for the current commit.
The working tree should be clean.

- `doorman-browser` and `wrap-helium.sh` use Helium's normal profile, or the
  `BROWSER_PROFILE` from `doorman.conf`, and refuse while Helium is running.
- `--browser-profile` selects an existing profile and is preserved across
  reinstalls; `doorman-migrate-profile` moves an older profile with a backup.
- `test_launcher.py` and `test_migrate.py` cover the launch, config, guard, and
  migration paths; README and this document updated.

Verify with `git status` before assuming. Do not commit or rewrite the user's
changes without being asked.
