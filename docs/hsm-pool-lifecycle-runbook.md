# Runbook: HSM pool lifecycle (bootstrap, init, verify, troubleshoot, re-initialize)

Operational procedure for a two-node cluster whose seal is a **pool of two YubiHSM 2 devices**
(`topology = "pool"`), with and without a Shamir recovery key. It covers the whole life of a
fresh cluster: provision, bootstrap, `init`, enrolling the second node, verification, restart
tests, troubleshooting, and re-initialization from scratch.

It complements, and does not replace:

- [hsm-runbook-two-node-pool.md](hsm-runbook-two-node-pool.md): the short happy path.
- [hsm.md](hsm.md): the reference (recovery ceremony, device audit log, replacing a device).
- [configuration.md](configuration.md#hsm-pool-topology-topology--pool): every `hsm` key.
- [cli-reference.md](cli-reference.md): the `operator hsm` commands.

Placeholders used below: `<node-1>` / `<node-2>` (hosts), `NODE1` / `NODE2` (their HSM
`node_id`, e.g. `prd-0001`), `<SERIAL_A>` / `<SERIAL_B>` (device serials).

> **Read this first.** Three things cannot be undone after `init`:
> the recovery mode (`none` vs `shamir-ceremony`), the recovery share split (N and M), and
> the physical state of each device (`provision` deletes the factory auth key; only a
> physical reset brings it back). Decide all three before you start.

---

## 1. Choose the recovery mode

| | `recovery = "shamir-ceremony"` | `recovery = "none"` |
|---|---|---|
| Both HSMs lost | Recoverable with M shares (`operator hsm recover`) | **The vault is unrecoverable** |
| `init` output | Root token **and** the recovery shares, shown once | Root token only |
| `init` flags | `--recovery-shares N --recovery-threshold M` | none (the flags are refused) |
| Break-glass | A quorum of share holders plus a copy of storage can decrypt everything | None: nothing outside the devices can |
| Extra config | none | `acknowledge_single_member_without_recovery = true` only when the pool has, or will drop to, **one** member |

- A valid split needs `2 <= M <= N <= 254`. The default is 5 of 3.
  Trade-off: with 3 of 2 any two holders can recover the vault, and losing two of the three shares
  makes recovery impossible; 5 of 3 tolerates two lost or unavailable holders, and needs three
  colluding ones to abuse it.
- The recovery mode is chosen **at `init`** and cannot be enabled later. The server compares it
  with the config and refuses an `init` whose flags do not match
  (see [troubleshooting](#7-troubleshooting)).
- Unseal **never** uses the recovery copy. It exists only for the ceremony in
  [section 9.4](#94-both-hsms-lost-recovery-ceremony).

---

## 2. Prerequisites

Do not start until every line is true.

- [ ] A `bvault` build with the `hsm_yubihsm2` backend (the official image ships it).
- [ ] `hiqlite` storage (a pool refuses anything else in a cluster) on both nodes.
- [ ] Each YubiHSM is attached to **one** host, with `yubihsm-connector` listening on
      `127.0.0.1:12345` there. The connector must listen on loopback only.
- [ ] The Yubico attestation trust file (root plus intermediates) on both nodes
      ([how to build it](hsm.md#yubico-attestation-trust-file)). Without it every attestation is refused.
- [ ] A CA for the HSM link, and per host: a **gateway server certificate** (SAN = the hostname
      other nodes use in `gateway = "https://…"`), and per node a **client certificate** whose DNS
      SAN equals that node's HSM `node_id`.
- [ ] An `hsm-gateway` config on each host with `allowed_clients = ["NODE1", "NODE2"]`.
- [ ] The `bv-admin` password of each device generated in the team's password manager: strong and
      **different per device**. It is typed at a hidden prompt or read from `env:VAR`; a literal
      value on the command line is refused. It cannot be recovered.
- [ ] If recovery is on: the **N custodians** and a separate delivery channel for each share are
      agreed. Nobody records all shares in one place, and the terminal that runs `init` keeps no
      screen or session recording.
- [ ] A backup (BVBK or `.bvx` export) of anything worth keeping, if the cluster is not new.

### Naming that must agree

| Thing | Where | Must match |
|---|---|---|
| hiqlite `node_id` (`1`, `2`) | `storage "hiqlite"` | its entry in `nodes = [...]` |
| HSM `node_id` (`NODE1`, `NODE2`) | `hsm "yubihsm2"` | the SAN of that node's client certificate, and `allowed_clients` on both gateways |
| `serial` of each `member` | `hsm "yubihsm2"` | the device actually reachable at that `connector` / `gateway` |

The two `node_id` namespaces are independent. Pick one numbering and keep it: changing it later
means reissuing node certificates.

---

## 3. Procedure A: with a recovery key (`shamir-ceremony`)

The init node is the node on which you run `operator hsm bootstrap` and `operator init`, once.
Pick the node whose local device is simplest to reach; the other node is enrolled afterwards.

### A1. Reset both devices to factory state (new cluster, or re-initialization)

Skip this step for a device that has never been provisioned. For a device that was, **this erases
its keys and cannot be undone.** BastionVault never resets a device.

On the host of each device, one device at a time:

1. Stop everything that holds a session on it (`yubihsm-connector`, the `hsm-gateway`, any
   `yubihsm-shell`).
2. Unplug the device. Touch the metal rim, plug it in **without releasing the rim**, keep touching it
   for at least 10 seconds, release.
3. Start `yubihsm-connector`, then verify the factory state:

   ```bash
   yubihsm-shell -C http://127.0.0.1:12345 -a get-device-info          # serial must be the device you meant
   yubihsm-shell -C http://127.0.0.1:12345 --authkey 1 -a list-objects # prompts for the password
   ```

   The factory password is the published Yubico default, `password`. A device in factory state
   shows **exactly one object**: the authentication key `0x0001`, labelled
   `DEFAULT AUTHKEY CHANGE THIS ASAP`.

   | Result of `list-objects --authkey 1` | Meaning |
   |---|---|
   | one object, `0x0001`, session opens | factory state, go on |
   | `Failed to create session: Object not found` | key `0x0001` is gone: the device is **provisioned**, the reset did not take; repeat step 2 |
   | `Authentication failed` | key `0x0001` exists with another password: not factory state |

   The log counter in `get-device-info` (`Log used`) is **not** evidence of a reset; do not rely on it.

### A2. Provision each device

On the host of each device (the CLI talks to the connector; the vault server is not involved):

```bash
bvault operator hsm provision --connector http://127.0.0.1:12345 --out <dir>/a.json   # on the hsm-a host
bvault operator hsm provision --connector http://127.0.0.1:12345 --out <dir>/b.json   # on the hsm-b host
```

- It prompts `the new bv-admin password`. Use that device's password from the password manager.
- On success: `provisioned <SERIAL>; attestation bundle written to <path>`.
- The bundle holds no secrets. Copy **both** bundles to the init node (verify with `sha256sum` on
  both ends).
- Provisioning deletes the factory auth key `0x0001`. **Check that `--out` is writable before you
  run it** (see [troubleshooting](#7-troubleshooting), "Permission denied writing the bundle"):
  a failure to write the bundle can happen *after* the device was already provisioned, which leaves
  a provisioned device with no bundle, and only a physical reset fixes that. `--adopt` does not:
  a pool device's `bv-admin` cannot read the attestation certificate.

### A3. Start the gateways

On each host, start `bvault hsm-gateway --config <gateway.hcl>` and confirm it listens (`ss -ltn | grep 8250`).
Each node reaches the *other* host's device through it, over mTLS.

### A4. Configure both nodes

```hcl
storage "hiqlite" {
  data_dir = "/var/lib/bvault/data"
  node_id  = 1                       # 2 on the other node
  nodes    = [ "1:<node-1>:8210:<node-1>:8220", "2:<node-2>:8210:<node-2>:8220" ]
  # plus the secrets / TLS keys your deployment uses (see configuration.md)
}

hsm "yubihsm2" {
  topology               = "pool"
  node_id                = "NODE1"                       # NODE2 on the other node
  credential_dir         = "/var/lib/bvault/data/hsm-credentials"
  attestation_roots_file = "/path/to/yubico-attestation.pem"
  recovery               = "shamir-ceremony"
  min_wrap_copies        = 2                             # see below

  link {                                                  # every node that uses a gateway
    ca_file   = "/path/to/hsm-link/ca.pem"
    cert_file = "/path/to/hsm-link/NODE1.pem"             # SAN = node_id
    key_file  = "/path/to/hsm-link/NODE1.key"
  }

  member "hsm-a" { connector = "http://127.0.0.1:12345"  serial = "<SERIAL_A>" }   # local on node 1
  member "hsm-b" { gateway   = "https://<node-2>:8250"   serial = "<SERIAL_B>" }   # remote on node 1
}
```

- On node 2 the two `member` blocks swap: `hsm-a` by `gateway`, `hsm-b` by local `connector`.
- Do **not** set `acknowledge_single_member_without_recovery`: with recovery on and two members it
  is not needed.
- `min_wrap_copies = 2` makes key creation fail while a member is down (unseal is unaffected).
  Leave it at the default `1` if you prefer creation to keep working with one member, at the cost of
  under-replicated sets that `repair` later fills.
- The host in each `gateway` URL must be in that gateway certificate's SAN.

### A5. Start the init node and bootstrap

1. Start the server on the init node. It is expected to stay **sealed and uninitialized**
   (`bvault status`: `Initialized false`, `Sealed true`).
2. Bootstrap attests both devices and enrolls this node. It runs on loopback, before `init`:

   ```bash
   bvault operator hsm bootstrap \
     --bundle hsm-a=<a.json> --bundle hsm-b=<b.json> \
     --admin hsm-a --admin hsm-b
   ```

   Each `--admin <member>` prompts for that member's `bv-admin` password (no echo), in the order named.
   Use `--admin <member>=env:VAR` for unattended runs. Success returns the member list and this node's
   `auth_key_id`.

### A6. Initialize

```bash
bvault operator init --recovery-shares <N> --recovery-threshold <M>      # e.g. 5 and 3
```

- The output carries the **root token** and the **N recovery shares**, shown **once**.
- Give each share to a different custodian by a separate channel. Do not paste the output into a
  ticket or chat, and do not store the shares together.
- There are no unseal shares: the vault auto-unseals through the HSMs.
- If `init` fails, **do not repeat it blindly**; see [troubleshooting](#7-troubleshooting).

### A7. Restart the init node: confirm the auto-unseal

Restart the service, wait for it, and run `bvault status`: `Initialized true`, `Sealed false`, with no
share entered.

### A8. Enroll the second node

1. Start the server on node 2. It stays sealed and logs its transport key fingerprint:

   ```
   HSM pool node NODE2 transport key fingerprint: <FP> (confirm it before `node add`)
   ```

2. Confirm `<FP>` **out of band**: from a different session than the one that printed it, ideally by
   a second person. It is what stops you enrolling an impostor.
3. On the init node, with the root token in `VAULT_TOKEN` (read it with `read -rs`, never on the
   command line):

   ```bash
   bvault operator hsm node add NODE2 --fingerprint <FP> --admin hsm-a --admin hsm-b
   bvault operator hsm node list
   ```

   The new node shows `credentials_waiting: true` until it fetches its credentials.
4. **Restart node 2.** It attempts the auto-unseal only at start, so it stays sealed until then. After
   the restart it unseals by itself.

### A9. Install the device-log auditor and verify

On the init node:

```bash
bvault operator hsm repair --run --admin hsm-a --admin hsm-b
bvault operator hsm members
bvault operator hsm status
```

Expected, on this build:

| Check | Expected |
|---|---|
| `repair`: `failures` | `[]` |
| `repair`: `can_install_auditor` / `can_set_forced_audit` | `true` for both members |
| `repair`: `auditors_installed` | both members |
| `repair`: `under_replicated` / `status`: `under_replicated_sets` | `0` |
| `members`: `state`, `incarnation` | `active`, `1` |
| `members`: `holds_kek_copy` / `up` / `faulted` | `true` / `true` / `false` |
| `status`: `redundancy` | `"full"`, `redundancy_warning` `null` |
| `status`: `recovery_configured` | `true`, with `recovery_shares` / `recovery_threshold` as chosen |
| `status`: `kek_recovery_copy` | `true` |
| `status`: `device_audit.members[]` | `enrolled: true`, `last_error: null`, `gaps: 0` |

A device provisioned by a build older than 2026-11-09 reports `can_install_auditor: false`; see
[hsm.md](hsm.md#give-an-existing-pool-the-drains-bv-admin).

### A10. Restart and resilience tests

Hiqlite with **two** nodes has no quorum tolerance: while one node is down the other cannot commit
writes, and logs `Cluster lost quorum` until the peer is back. That is expected. Restart **one node at
a time** and wait for it to unseal before touching the next.

1. Restart node 2, then node 1. Each must reach `Sealed false` by itself.
2. Single-HSM test, one node at a time: stop the gateway that serves the device that node reaches
   *remotely*, restart the node, and confirm it still unseals through its **local** device. Restore
   the gateway afterwards, and repeat for the other node.

### A11. Close out

1. Revoke the root token if it was generated only for this task, and create an operations token and
   policy with access to `sys/hsm/*`.
2. Record, **without the values**: which custodian holds which share, the date, and the `M of N` split.
3. Keep the `bv-admin` passwords in the password manager. `repair --admin`, `node add --admin`,
   `rotate-epoch` and `recover` all need them.

---

## 4. Procedure B: without a recovery key (`none`)

Identical to Procedure A except for:

| Step | Change |
|---|---|
| A4 config | `recovery = "none"`. Add `acknowledge_single_member_without_recovery = true` **only** if the pool has, or will drop to, a single member; omit it with two members |
| A6 init | `bvault operator init` **without** `--recovery-shares` / `--recovery-threshold` (they are refused) |
| A9 verify | `status`: `recovery_configured: false`, `kek_recovery_copy: false` |
| A11 | Nothing to distribute, and nothing to recover with |

**Consequence:** if both HSMs are lost, or a device is reset while it is the only member, the vault
is gone. Make sure a current backup exists and that the second device is enrolled quickly.
`status` reports `redundancy: "none"` and raises `hsm.pool_not_redundant` while only one member is
active.

### B1. Starting with one HSM, adding the second later

A pool may start with one device and gain the second with `member add`
([hsm.md](hsm.md#starting-with-one-hsm-a-pool-of-one)). In that case `min_wrap_copies` must stay `1`,
and `none` requires the acknowledgement above. Once the second device is in, raise `min_wrap_copies`
to `2` if you want it, and remove the acknowledgement.

---

## 5. Rootless Podman / Quadlet deployments

Observed on a Puppet-managed deployment (one container for the server, one for the gateway, each
under a rootless service user, with a system-level wrapper unit). Names differ in your environment;
the mechanisms apply to any rootless-container deployment.

- **The CLI wrapper runs inside the server container.** `bvault` on the host is a script that does
  `podman exec` into the running server container and injects `--address`, the CA and the SNI name.
  Consequently: paths you pass (`--bundle`, `--out`) are **container paths**; the server container
  must be running for any command that talks to the server (`bootstrap`, `init`, `node …`,
  `repair`, `status`); and `VAULT_TOKEN` is read by the wrapper from the environment or its token file.
- **Provisioning without starting the server.** `provision` is a local command, but the wrapper
  needs the container. Run the CLI from the same image in a throw-away container that shares the
  host network (to reach the connector on loopback) and mounts the output directory:

  ```bash
  cd / && sudo -u <svc-user> XDG_RUNTIME_DIR=/run/user/<uid> podman run --rm -it --network=host \
    --user 0:0 --entrypoint /usr/local/bin/bvault \
    -v <host-hsm-out-dir>:/hsm-out:z <image>:<tag> \
    operator hsm provision --connector http://127.0.0.1:12345 --out /hsm-out/a.json
  ```

  `--user 0:0` matters: rootless Podman maps the image's default user to a sub-uid that cannot write
  to a directory owned by the service user, and the bundle write then fails with `Permission denied`.
  Test the write first, without touching a device:

  ```bash
  podman run --rm --network=host --user 0:0 --entrypoint /bin/sh -v <host-hsm-out-dir>:/hsm-out:z \
    <image>:<tag> -c 'touch /hsm-out/t && rm /hsm-out/t && echo write-ok'
  ```

- **Single-file bind mounts go stale.** The server config is bind-mounted as a single file. Editing it
  with `sed -i` (or any editor that writes a new file and renames it) creates a new inode; a container
  that is already running keeps reading the **old** one. **Always restart the server container after
  editing the config**, and confirm what the process sees:

  ```bash
  podman exec <server-container> grep -nE 'recovery|min_wrap_copies' /etc/bvault/config.hcl
  ```

- **Stop the service through its wrapper unit**, then confirm the process is gone with a pattern that
  cannot match itself (`pgrep -af '[b]vault server'`). A plain `pgrep -f "bvault server"` matches the
  shell that runs it.
- **Directories on the host** (the server container's data and the HSM output directory): they belong
  to the service user and are mode `0750`/`0700`. Reading them needs `sudo` or a deliberate ACL.
  The backup destination for scheduled exports is a path **inside the container**: use a mounted path
  (for example `/backups`), never a path that is not a volume, or the files vanish with the container.

### Cluster-transport settings to review

On the deployment this runbook was written from, hiqlite ran with `tls_raft_no_verify = true` and
`tls_api_no_verify = true`: node-to-node traffic is encrypted but the peer certificate is not
verified. That is a deployment decision outside the HSM pool, but it weakens the guarantee that only
your nodes join the cluster. Review it.

---

## 6. Day-two checks

```bash
bvault status                       # Initialized, Sealed, Is Leader, Node Id
bvault operator hsm status          # redundancy, members, recovery, device_audit
bvault operator hsm members
bvault operator hsm node list       # enrolled, revoked, credentials_waiting, signatures_valid
bvault operator hsm repair          # last repair run; add --run to run it now
```

Signals worth alerting on: `bv_hsm_pool_redundancy{level="none"}`, `bv_hsm_member_up`,
`bv_hsm_under_replicated_sets`, `bv_hsm_device_log_gap_total`, and the log events
`hsm.pool_not_redundant`, `hsm.member_down`, `hsm.crypto_failure`, `hsm.device_log_gap`.

---

## 7. Troubleshooting

Always start with `bvault status`, `bvault operator hsm status`, and the **server container's log**
filtered for `hsm|unseal|security`. The `security` log target carries the HSM events.

### 7.1 Bring-up and provisioning

| Symptom | Cause | Fix |
|---|---|---|
| `init`: `HSM seal configuration is invalid: recovery_shares and recovery_threshold need recovery = "shamir-ceremony" … this node's config says recovery = "none"` | The **running** server holds a different config than the file on disk. In containers: stale single-file bind mount (section 5), or the file was never edited | Fix the file, **restart the server**, confirm what the process sees, then retry `init`. Nothing was initialized |
| `init` refused with two members configured and one unreachable | `init` never turns a two-member pool into a pool of one | Make both members reachable (gateway up, certs valid, serial matches) |
| `provision`: `Error: writing <path>: Permission denied`, **after** the password prompt | The output path is not writable. The device may **already be provisioned** | Do **not** repeat blindly. Run `list-objects --authkey 1`: `Object not found` means it was provisioned and the bundle is lost; physically reset the device (A1) and provision again, writing to a path you tested |
| `provision`: `authentication failed: auth key not found: 0x0001` | The device is not in factory state | Physical reset (A1), verify, retry |
| `list-objects --authkey 1` → `Object not found` **before** provisioning | Reset did not take | Repeat the reset: connector stopped, rim touched **before** and **while** plugging in, 10 s or more |
| `list-objects --authkey 1` → `Object not found` **after** provisioning | Expected: provisioning deletes `0x0001` | Nothing. Do not reset a device you just provisioned |
| `bootstrap` refused | Single member with `recovery = "none"` and no acknowledgement; or a bundle truncated by an old build; or attestation failed | Set the acknowledgement (one member only), re-provision with this build, or fix the Yubico trust file |
| `bootstrap` cannot reach a member | Gateway down, mTLS mismatch, SAN does not include the host in the URL, `allowed_clients` lacks this node | Test the gateway port, the certificate SAN and `allowed_clients` |
| `bootstrap` answers only on loopback | By design | Run it on the init node itself |

### 7.2 Enrollment and unseal

| Symptom | Cause | Fix |
|---|---|---|
| `this node holds no credential for HSM pool member …; enroll it` | The node is not enrolled yet | `operator hsm node add <NODE> --fingerprint <FP> --admin …` on a node that can reach both devices |
| Node still sealed after `node add` | Auto-unseal is attempted at start only; the credentials arrived later (`installed HSM pool credentials` in the log) | Restart the node |
| `node add` refused: `the confirmed fingerprint does not match` | The fingerprint is not the one this node logged | Re-read it on the node; if it still differs, stop: something is impersonating or the node's `credential_dir` changed |
| `node list`: `credentials_waiting: true` | The node has not fetched its credentials yet | Start or restart that node |
| Node stays sealed, every member `unavailable` | Neither device reachable | Check the connector (`/connector/status`), the gateway, certificates, and `members` |
| Sealed with `hsm.crypto_failure` | Tampering or an AAD/authorization/MAC mismatch. **Not retried** on the other member | Treat as a security incident; do not force |
| A member `faulted` | The device reports another serial than the record | Wrong or swapped device: put the right one back; do not edit the record |
| `no bv-auditor credential, so its device log is not drained` | `repair --run --admin …` has not run since `init` | Run it with each member's `bv-admin` |
| `bv-admin cannot create bv-auditor` | Device provisioned before the build that delegates `get-log-entries` | [hsm.md](hsm.md#give-an-existing-pool-the-drains-bv-admin) |

### 7.3 Transient noise vs real faults

| Log line | Reading |
|---|---|
| `Cluster lost quorum`, `timeout while confirming leadership … AppendEntries`, many `WebSocket read … failed` | Seen for tens of seconds while the peer node restarts and unseals, on a two-node hiqlite cluster. **Transient** if it stops once both nodes are up. If it persists, check latency and the Raft ports (`8210`/`8220` in the examples) between the nodes |
| `hsm pool member … failed probe: … bad response from connector: error reading response`, with `libusb: interrupted` in the connector journal | A connector or USB hiccup on the **locally attached** device. Not fatal while `status` shows the member `up` and `faulted: false`. If it repeats every probe interval and a member goes down, look at the connector (`journalctl -u yubihsm-connector`), the USB port and cable, and stray sessions (the device holds 16) |
| `SESSIONS_FULL` | The device's 16 sessions are used; the node backs off and uses the other member. Close stray `yubihsm-shell` sessions; mind the drain's sessions (about 7 per device) in large clusters |
| `hsm.pool_not_redundant`, `redundancy: "none"` | Only one member active. Intended for a pool of one; otherwise restore the second member |

### 7.4 What to collect before asking for help

`bvault status`, `bvault operator hsm status`, `… members`, `… node list`, the last 100 `security`
log lines from both nodes, `yubihsm-connector` journal lines around the failure, and the output of
`yubihsm-shell … get-device-info`. **Never** include `init` output, root tokens, recovery shares, or
`bv-admin` passwords.

---

## 8. Safety rules

- Passwords: only through the hidden prompt or `env:VAR`. A literal value is refused; do not put them in
  shell history, files, tickets or chat.
- Never run two destructive steps in parallel. Reset and provision **one device at a time**, and verify
  each before the next.
- A physical reset erases the device's keys. Confirm the serial **before** you touch the rim.
- Do not unseal by hand, edit the seal record, or delete `hsm-credentials` on a running node.
- The BastionVault server never resets a device and never uses the recovery copy to unseal.
- Revoke the root token when the task that needed it is done.

---

## 9. Re-initialization

Pick the smallest case that fits.

### 9.1 One node is broken, the cluster is fine

Do not re-initialize. Revoke the node (`operator hsm node revoke <NODE> --admin …`), rebuild it with a
fresh `credential_dir`, and enroll it again (A8).

### 9.2 One HSM failed or must be replaced

Follow the device-replacement procedure in [hsm.md](hsm.md): `member retire`, `repair --run`,
factory-reset and `provision` the device, `member add` or `member reenter`, `repair --run --admin …`,
then restart the nodes one at a time. With `min_wrap_copies = 2` lower it to `1` first. With
`recovery = "none"` the acknowledgement is needed while only one member is active.

### 9.3 Rebuild the whole cluster from scratch

This discards **everything** in the vault. Confirm there is nothing to keep, or restore from a backup
afterwards if your build supports restoring a BVBK into a new vault.

1. Agree the recovery mode and, if on, the custodians and split (section 1).
2. Stop the service on **every** node. Confirm no `bvault server` process remains.
3. Wipe on every node, after listing the exact paths and having them confirmed:
   the hiqlite state (`state_machine`, `state_machine_cache`, and the hiqlite `logs` / `logs_cache`
   directories under `data_dir`) **and** `credential_dir`. Keep the binary, the config, the TLS and
   link certificates, and any backup directory.
4. Physically reset **both** devices, one at a time, and verify factory state (A1).
5. Provision both (A2), start the gateways (A3), confirm or update the config (A4) and restart so the
   process reads it, then bootstrap, init, restart, enroll the other node, repair and verify
   (A5 to A10 for recovery, or Procedure B).
6. Revoke the root token and record the custody (A11).

Re-using already-provisioned devices after wiping storage is **not documented or validated**: the
devices still hold the previous node and wrap keys. Reset them.

### 9.4 Both HSMs lost: recovery ceremony

Only possible if the pool was initialized with `recovery = "shamir-ceremony"`; with `none` the vault is
unrecoverable and you rebuild from scratch (9.3).

1. Provision two new devices (bundles `c.json`, `d.json`) after a physical reset if they were used.
2. Point the node's `member` blocks at the new devices and restart it. It stays sealed.
3. Collect M share holders. The node accepts the ceremony only while sealed and while **every** non-retired
   member is unreachable; any device that answers makes it refuse (repair or `member add` instead).
4. Run it on the sealed node. Each share is a hidden prompt, or `--share env:VAR`:

   ```bash
   bvault operator hsm recover --member hsm-a2=c.json --member hsm-b2=d.json --admin hsm-a2 --admin hsm-b2
   ```

   Shares stay in that node's memory until the ceremony completes or you run
   `bvault operator hsm recover --reset`. Wrong, tampered or too few shares are refused and every
   attempt consumes the shares submitted.
5. On success the old members are `retired`, the epoch is bumped and the node auto-unseals through the
   new devices. Other nodes pick up their new credentials on their next refresh; restart them if they do
   not. Reset or destroy the lost devices if they reappear.

---

## 10. Command quick reference

```bash
# on each device host
bvault operator hsm provision --connector http://127.0.0.1:12345 --out <bundle.json>
bvault hsm-gateway --config <gateway.hcl>

# on the init node, before init (loopback)
bvault operator hsm bootstrap --bundle hsm-a=<a.json> --bundle hsm-b=<b.json> --admin hsm-a --admin hsm-b
bvault operator init --recovery-shares <N> --recovery-threshold <M>   # omit both flags for recovery = "none"

# enroll another node, then restart it
bvault operator hsm node add <NODE> --fingerprint <FP> --admin hsm-a --admin hsm-b
bvault operator hsm node list | revoke <NODE> --admin …

# operate
bvault operator hsm status | members
bvault operator hsm repair [--run --admin hsm-a --admin hsm-b]
bvault operator hsm member retire|add|reenter …           # see hsm.md
bvault operator hsm rotate-epoch --admin hsm-a --admin hsm-b
bvault operator hsm recover --member <n>=<bundle> … --admin <n> …   # both devices lost; recovery only
```
