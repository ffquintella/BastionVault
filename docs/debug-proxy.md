# Debug proxy — reading the GUI's vault traffic in Charles

A development-only escape hatch that routes **every outbound vault
HTTP(S) request the desktop GUI makes** through an intercepting proxy,
so the API stream can be read and replayed while diagnosing a problem.
Compatible with Charles Proxy, mitmproxy, Fiddler and Burp — anything
that speaks an HTTP/HTTPS or SOCKS5 proxy.

```bash
make run-dev-gui-proxy
```

## Read this first

The proxy terminates TLS. That means it sees, in cleartext:

* the session token in `X-Vault-Token` on every request,
* every secret, private key and certificate in every response body,
* unseal shares, if you unseal through a proxied GUI.

This is inherent to what an intercepting proxy is, not a defect of this
integration. **Use it against scratch and development vaults only.**
Never against a vault holding real operator secrets.

Two gates keep it out of everything else, mirroring the local Tauri MCP
bridge (AGENTS.md §7):

1. **Cargo feature `debug_proxy`.** Off in every default build, every
   release build and every packaged installer. With the feature off the
   code is not compiled at all — `crates/bv-client/src/debug_proxy.rs`
   is behind `#[cfg(feature = "debug_proxy")]`, as is each of the three
   call sites.
2. **Environment variable `BASTION_DEBUG_PROXY`.** Even a build that
   *has* the feature does nothing until this is set, so a feature-on
   binary cannot be steered by a stray `HTTPS_PROXY`.

Nothing about it is silent. Resolution logs once per process at WARN,
naming the proxy URI and the TLS posture:

```
WARN DEBUG PROXY ACTIVE: routing all outbound vault HTTP(S) through
     'http://127.0.0.1:8888' (trusting only the CA from
     $BASTION_DEBUG_PROXY_CA). Tokens and secrets are visible to that
     proxy — never use this against a real vault.
```

## What is covered

The GUI drives three separate HTTP clients. All three honour the
override, or only part of the traffic would appear in the proxy:

| Client | Where | Carries |
|---|---|---|
| `bastion_vault::api::Client` (legacy) | `src/api/client.rs` | `sys/health`, seal/unseal fan-out, login |
| `bv_client::RemoteBackend` | `crates/bv-client/src/remote.rs` | the logical data plane (`v2/...`) |
| cluster-discovery health probes | `crates/bv-client/src/health.rs` | SRV candidate `/v1/sys/health` scoring |

The probes are included on purpose: if discovery took a different route
from the data plane it could select a node the proxied requests cannot
then reach.

Not covered, because they are not HTTP: the SSH and RDP session
transports, and the embedded (in-process) vault mode — an embedded
vault never leaves the process, so there is no traffic to intercept.
Switch the GUI to a remote profile (Connect page) to see anything.

## Environment

| Variable | Meaning |
|---|---|
| `BASTION_DEBUG_PROXY` | Proxy URI. `http://127.0.0.1:8888` is Charles' default; `socks5://…` works too. Unset ⇒ inert. |
| `BASTION_DEBUG_PROXY_CA` | Path to the proxy's root CA, PEM. Becomes the **only** trusted root, so the MITM certificate validates normally. |
| `BASTION_DEBUG_PROXY_INSECURE` | `1`/`true`/`yes`/`on` ⇒ disable TLS verification outright. Overrides `_CA` (with a warning). |

With neither `_CA` nor `_INSECURE` set, the caller's own TLS settings
are left alone: an HTTPS target then fails the handshake against the
proxy's certificate. That failure is deliberate — a loud error rather
than a silent downgrade. Plain-HTTP targets still work.

A bad CA path is fatal to the override, not ignored: the proxy is
disabled and an error is logged, so you never think you are proxying
when you are not.

## Makefile

`make run-dev-gui-proxy` is `make run-dev-gui` plus the `debug_proxy`
feature and the environment above. Knobs:

```bash
make run-dev-gui-proxy                                  # Charles on 127.0.0.1:8888
make run-dev-gui-proxy PROXY=http://127.0.0.1:8080      # mitmproxy
make run-dev-gui-proxy PROXY=socks5://127.0.0.1:1080    # SOCKS
make run-dev-gui-proxy PROXY_CA=/path/to/root.pem       # a CA elsewhere
make run-dev-gui-proxy PROXY_INSECURE=1                 # no TLS verification
```

`PROXY_CA` defaults to `~/.charles/charles-ssl-proxying-certificate.pem`
and is passed through only if the file exists; when it is missing the
recipe says so and explains the two ways forward rather than failing
late inside the app.

## Charles setup

1. **Export the root certificate.** Help → SSL Proxying → Save Charles
   Root Certificate, choose the `.pem` format, save it to
   `~/.charles/charles-ssl-proxying-certificate.pem` (or pass
   `PROXY_CA=`). Installing it into the macOS login keychain is *not*
   enough on its own — `ureq` uses its own root store, which is exactly
   why this variable exists.
2. **Enable SSL proxying for the vault.** Proxy → SSL Proxying Settings
   → Add, with the vault's host and port (e.g. `vault.example.com:8200`,
   or `*:8200`). Without this Charles only tunnels the `CONNECT` and you
   see encrypted bytes, not requests.
3. Check the listening port under Proxy → Proxy Settings (8888 by
   default) and match `PROXY=` to it.
4. Run `make run-dev-gui-proxy`, then connect the GUI to a remote vault
   from the Connect page.

For mitmproxy the equivalents are `mitmproxy --listen-port 8080` and
`~/.mitmproxy/mitmproxy-ca-cert.pem`.

## Relationship to the "Use system proxy" toggle

The per-profile **Use system-configured proxy** setting
(`RemoteProfile::use_system_proxy`, resolved by
`bv_client::sysproxy`) is an operator-facing production feature: it
honours the OS proxy or `HTTPS_PROXY` when the operator asks for it,
and bypasses any proxy when they do not.

`BASTION_DEBUG_PROXY` is not that. It is applied *after* that decision
and overrides it either way, including the deliberate "clear the proxy"
branch. That is the point — the debugger's proxy should apply whatever
the profile says — and it is the reason it is feature-gated instead of
being just another environment variable the release build reads.
