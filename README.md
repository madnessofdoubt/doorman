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

After install:

```bash
doorman-browser        # Helium through the MITM proxy on :8080
doorman-run steam      # Steam through the strict proxy on :8081
```

`/etc/doorman` holds the live rules. `strict_allowlist.txt` controls the
strict proxy; `allowlist.txt` and `downloads.conf` control the browser. They
are created from the project files on first install and preserved afterwards,
so edits survive a reinstall; use `--force` to regenerate them. Edit a file and
restart the matching service:

```bash
sudo systemctl restart doorman-browser   # allowlist.txt, downloads.conf
sudo systemctl restart doorman-strict    # strict_allowlist.txt
```

Uninstall:

```bash
sudo scripts/install.sh --uninstall --daily-user stan
```

## Browser

Installed:

```bash
doorman-browser
```

That launches Helium with the dedicated profile and `--proxy-server=http://127.0.0.1:8080`.

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
editing either file.

## Everything else

Installed:

```bash
doorman-run steam
```

`doorman-run` uses the systemd strict proxy on `:8081` and exports the proxy
environment.

Development/manual:

```bash
scripts/doorman-run.sh --allowlist steam_allowlist.txt --default deny -- steam
```

`doorman-run.sh` starts `strict_proxy.py`, exports `http_proxy`/`https_proxy`,
runs the command, and stops the proxy on exit.

The strict proxy reads the TLS SNI or HTTP `Host` and allows or denies by
hostname. TLS is never decrypted, so there is no CA to install and certificate
pinning is not a problem.

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

`--print` shows the generated rules without root.

## Tests

```bash
.venv/bin/python -m unittest -v test_rules test_addon
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
| `wrap-chromium.sh` | Launch Chromium through the browser proxy |
| `scripts/doorman-run.sh` | Launch any app through the strict proxy |
| `scripts/doorman-firewall.sh` | Reversible per-UID nftables test policy |
| `scripts/doorman-test-user.sh` | Create the throwaway test user |
| `test_rules.py` | Matcher and SNI parser tests |
| `test_addon.py` | Browser config parser tests |
| `policy/` | Chromium enterprise policy |

## Known gaps

- Apps that ignore proxy settings bypass `strict_proxy.py` until the firewall
  is applied; with `--enforce`, they are dropped instead.
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
  clear the doorman browser profile after changing policy.
- Steam reports most update failures as "needs to be online", including a full
  disk. If login fails, check `df -h /` and the proxy port before changing the
  allowlist: `ss -ltn | grep 8081`.
- The strict proxy is IPv4-only for transparent redirects; IPv6 is dropped.
- CA trust for Helium is installed system-wide and in `~/.pki/nssdb`, but a
  Chromium build with its own root store may still reject the MITM certificate.
- Package managers run as root and are not covered by any of the above.
- `--uninstall` removes `/opt/doorman`, including the Helium AppImage, and does
  not remove `/etc/chromium/policies/managed/internet-blocker.json`.
- Removing `wheel` is explicit (`--remove-wheel`); the admin account can still
  bypass any local policy.
