# doorman

Block downloads (browser) and unwanted outbound traffic (everything else)
unless explicitly allowed.

Two independent policies, two listeners:

| Listener | Runs | Policy |
|---|---|---|
| `127.0.0.1:8080` | `mitmdump -s addon.py` | Browser: MITM, download/media blocking, site allowlist |
| `127.0.0.1:8081` | `strict_proxy.py` | Everything else: host allowlist, no decryption |

## Installer (Arch VM)

One script does packages, venv, Helium, CA, service user, both proxies,
launchers, desktop entries, optional admin, optional firewall:

```bash
sudo scripts/install.sh --vm --daily-user stan \
    --helium /path/Helium.AppImage --create-admin --enforce --ttl 15m
```

This uses the default `--default deny` policy. `steam_allowlist.txt` is merged
into `/etc/doorman/strict_allowlist.txt` so Steam can log in without switching
the whole proxy to allow-all.

`--vm` implies `--yes`, `--trust-ca`, and `pacman -Syu` (use `--no-upgrade`
to skip the upgrade). `--enforce` is optional; `--ttl` schedules a root-owned
auto-revert. `--remove-wheel` is **not** implied and refuses to run unless the
admin account has working sudo.

`--browser-profile PATH` makes `doorman-browser` use an existing Helium
profile; without it, Helium's normal profile is used. The setting is kept in
`/etc/doorman/doorman.conf` and survives reinstalls.

After install:

```bash
doorman-browser        # Helium through the MITM proxy on :8080
doorman-run steam      # Steam through the strict proxy on :8081
```

`/etc/doorman` holds the live rules. `strict_allowlist.txt` controls the
strict proxy; `allowlist.txt` and `downloads.conf` control the browser. They
are created from the project files on first install and preserved afterwards,
so edits survive a reinstall; use `--force` to regenerate them. Edit a file and
reload or restart the matching service:

```bash
sudo systemctl reload doorman-strict     # strict_allowlist.txt (or restart)
sudo systemctl restart doorman-browser   # downloads.conf
```

Browser `allowlist.txt` changes are picked up on the next request; only
`downloads.conf` needs the browser restart.

Uninstall:

```bash
sudo scripts/install.sh --uninstall --daily-user stan
```

## Browser

Installed:

```bash
doorman-browser
```

That launches Helium with your normal profile and
`--proxy-server=http://127.0.0.1:8080`, so your existing cookies and logins
stay. Close Helium completely before starting it: a second launch would
otherwise join the running instance, which has no proxy, so the launcher
refuses to start. The `helium` shortcut installed by `wrap-helium.sh` uses
the same normal profile; it still starts a development proxy when `:8080` is
not already listening.

If your profile lives somewhere else, set `BROWSER_PROFILE=/path/to/profile`
in `/etc/doorman/doorman.conf` (empty means Helium's normal profile), or
reinstall with `--browser-profile /path/to/profile`. The old dedicated
profile at `~/.config/doorman-helium` is no longer used. To move an older
profile into the normal default, close Helium and run:

```bash
doorman-migrate-profile --from ~/.config/doorman-helium
```

It keeps a timestamped backup and refuses while Helium is running. A custom
profile selected with `--browser-profile` does not need migration.

Development/manual Chromium:

```bash
./wrap-chromium.sh
```

Uses `/etc/doorman/allowlist.txt` (fully exempt hosts) and
`/etc/doorman/downloads.conf` (allowed download types and extensions). The
repo copies are defaults; the installer copies them to `/etc/doorman` on first
install and preserves edits. Entries are hostnames; a scheme or port in an
entry is ignored, so the host is exempt on every port. An empty
`downloads.conf` blocks every download. Restart `doorman-browser` after
editing `downloads.conf` (allowlist edits apply on the next request).

## Everything else

Installed:

```bash
doorman-run steam
```

`doorman-run` uses the systemd strict proxy on `:8081` and exports the proxy
environment. The first run creates `/etc/doorman/apps/<app>.txt`, owned by
your user, and tells you where it is. Add hosts there to extend the global
allowlist for that app only:

```conf
# /etc/doorman/apps/steam.txt
steamcloud-eu-ams.storage.googleapis.com
```

The global allowlist still applies. The file is used only after it contains at
least one host, so the empty auto-created file does not change anything. Add
the hosts, then restart the app; the proxy re-reads the file for new
connections. The file name comes from the command name (`steam.txt`,
`firefox.txt`); set `DOORMAN_APP_NAME` when a wrapper needs a different name.

The proxy identifies the app from the username in the proxy URL. That is a
label, not a security boundary: another program running as you can use the
same name. Apps that do not send proxy credentials fall back to the global
list, so their per-app entries are ignored.

For Git, `doorman-run git` sets `http.proxy` for that invocation, overriding a
plain global `http.proxy`. Add the hosts Git needs to `git.txt`.

Some clients cannot send the proxy username at all. Electron apps such as
Obsidian reject credentials in `--proxy-server` and ignore `http_proxy`. Give
them a dedicated loopback port:

```conf
# /etc/doorman/apps/ports.conf — one "PORT APP" per line
8082 obsidian
```

```bash
sudo systemctl restart doorman-strict
printf -- '--proxy-server=http://127.0.0.1:8082\n' \
  > ~/.config/obsidian/user-flags.conf
```

Restart Obsidian. Every connection on 8082 is treated as `obsidian`, so
`obsidian.txt` applies without proxy auth. Add every host the app needs,
including `github.com` and the release-asset hosts, to `obsidian.txt`. The
proxy reads `ports.conf` at startup, so restart the strict service after
changing it. The port is a label, not a secret.

Development/manual:

```bash
scripts/doorman-run.sh --allowlist steam_allowlist.txt --default deny -- steam
```

`doorman-run.sh` starts `strict_proxy.py`, exports `http_proxy`/`https_proxy`,
runs the command, and stops the proxy on exit.

The strict proxy reads the TLS SNI or HTTP `Host` and allows or denies by
hostname. It also reads the optional proxy username to add a per-app
allowlist. TLS is never decrypted, so there is no CA to install and
certificate pinning is not a problem.

Discovery loop:

```bash
.venv/bin/python strict_proxy.py --dry-run
# use the app, watch the log, add what it needs
.venv/bin/python strict_proxy.py --allowlist my_allowlist.txt
```

`DRYRUN` means "not on the list, but allowed because of --dry-run".
`ALLOW` means on the list. `DENY` means blocked.

## Firewall

The installer uses drop mode for the daily UID: direct TCP/UDP is dropped, DNS
and loopback (local IPC and the proxies) are allowed. Apps must use a proxy.
The lower-level test script supports both modes:

```bash
scripts/doorman-test-user.sh
sudo scripts/doorman-firewall.sh apply --user doorman-test --mode redirect
sudo scripts/doorman-firewall.sh apply --user doorman-test --mode drop
sudo scripts/doorman-firewall.sh status
sudo scripts/doorman-firewall.sh revert
```

`print` shows the generated rules without root. `apply` validates the ruleset
and replaces the table in one nft transaction, so a failed apply leaves the
existing firewall untouched.

## Tests

```bash
.venv/bin/python -m unittest -v test_rules test_addon test_launcher test_migrate test_apps test_doorman_run
```

## Files

| File | Purpose |
|---|---|
| `addon.py` | Browser policy (MITM) |
| `strict_proxy.py` | Host allowlist proxy (no MITM) |
| `rules.py` | Shared host matching |
| `allowlist.txt` | Browser-exempt hosts (default for `/etc/doorman/allowlist.txt`) |
| `downloads.conf` | Allowed browser download types/extensions (default for `/etc/doorman/downloads.conf`) |
| `strict_allowlist.txt` | Default strict allowlist; Steam hosts are merged in at install |
| `steam_allowlist.txt` | Hosts Steam needs under `--default deny` |
| `scripts/install.sh` | One-shot Arch installer |
| `scripts/doorman-browser.sh` | Installed as `doorman-browser`; launches Helium with the normal or configured profile |
| `scripts/doorman-migrate-profile.sh` | Installed as `doorman-migrate-profile`; move an old profile into the default |
| `wrap-chromium.sh` | Launch Chromium through the browser proxy |
| `wrap-helium.sh` | Dev Helium launcher; normal profile, optional dev proxy |
| `scripts/doorman-run-app.sh` | Installed as `doorman-run`; per-app allowlist launcher |
| `scripts/doorman-run.sh` | Development launcher for the strict proxy |
| `scripts/doorman-firewall.sh` | Reversible per-UID nftables test policy |
| `scripts/doorman-test-user.sh` | Create the throwaway test user |
| `test_rules.py` | Matcher and SNI parser tests |
| `test_addon.py` | Browser config parser tests |
| `test_launcher.py` | Browser launcher tests |
| `test_migrate.py` | Profile migration helper tests |
| `test_apps.py` | Proxy auth and per-app allowlist tests |
| `test_doorman_run.py` | Per-app launcher tests |
| `policy/` | Chromium enterprise policy |

## Known gaps

- Apps that ignore proxy settings bypass `strict_proxy.py` until the firewall
  is applied; with `--enforce`, they are dropped instead.
- Per-app allowlists are additive and advisory. Proxy-aware clients use
  `Proxy-Authorization`; clients that cannot send it can use a dedicated port
  from `ports.conf`. Any process running as the daily user can use either
  label. Real isolation needs cgroups.
- The installer has one strict proxy for all non-browser apps.
- The daily UID can reach both loopback proxies, so a non-browser app can use
  the browser proxy (`:8080`) and bypass the strict allowlist for non-media
  traffic, or forge a `Referer` from an allowlisted site. Closing this needs
  per-process/cgroup rules or a separate browser UID.
- `--enforce` drops outbound TCP/UDP except DNS and loopback. Steam
  multiplayer/voice, WebRTC, and LAN or Tailscale destinations are blocked
  unless you add exceptions.
- Steam login and downloads work under `--default deny` because the installer
  merges `steam_allowlist.txt` into the strict allowlist. Add any host Steam
  logs as `DENY` while it runs.
- The Steam store cannot be blocked independently of the login/API hosts on
  `steampowered.com`, so the store tab and its trailers remain reachable.
- `--default allow` makes the strict proxy allow every host. It does not
  enforce "apps are blocked unless allowed"; use `--default deny` with a
  populated allowlist for that.
- Media and download decisions use headers and URL extensions. A server that
  mislabels a file, or a page that generates a `blob:`/`data:` download, can
  bypass them; inspecting bytes or using browser download policy would be
  needed.
- Responses already in the browser cache are served without hitting the proxy;
  hard-reload or clear the site's cache. Clearing the whole profile would sign
  you out of everything.
- Steam reports most update failures as "needs to be online", including a full
  disk. If login fails, check `df -h /` and the proxy port before changing the
  allowlist: `ss -ltn | grep 8081`.
- The strict proxy is IPv4-only for transparent redirects; IPv6 is dropped.
- The installer cannot detect a profile selected by a third-party wrapper or
  desktop file. Pass `--browser-profile` or set `BROWSER_PROFILE`.
- Profile migration is explicit; the installer warns about the old doorman
  and dev profiles but never moves them.
- CA trust for Helium is installed system-wide and in `~/.pki/nssdb`, but a
  Chromium build with its own root store may still reject the MITM certificate.
- Package managers run as root and are not covered by any of the above.
- `--uninstall` removes `/opt/doorman`, including the Helium AppImage, and does
  not remove `/etc/chromium/policies/managed/internet-blocker.json`.
- Removing `wheel` is explicit (`--remove-wheel`); the admin account can still
  bypass any local policy.
