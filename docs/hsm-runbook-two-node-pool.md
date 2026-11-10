# Runbook: two-node pool of two YubiHSM 2 devices

Initializes one YubiHSM 2 on each of two servers, then the vault, and confirms the unseal.
References: [hsm.md](hsm.md), [configuration.md](configuration.md#hsm-pool-topology-topology--pool), [cli-reference.md](cli-reference.md#hsm-gateway).
For the full lifecycle (with and without a recovery key, rootless-container notes, troubleshooting and
re-initialization) see [hsm-pool-lifecycle-runbook.md](hsm-pool-lifecycle-runbook.md).

| Server | Node (`node_id`) | Pool member | YubiHSM serial |
|---|---|---|---|
| `server1` | `vault-1` (init node) | `hsm-a` | `<SERIAL_A>` |
| `server2` | `vault-2` | `hsm-b` | `<SERIAL_B>` |

Each server hosts one HSM (local access through `yubihsm-connector`) and runs one vault node.
Each node reaches the other server's HSM through an `hsm-gateway` protected by mTLS.

## Before you start

- A `bvault` binary built with `--features hsm_yubihsm2` on both servers.
- `yubihsm-connector` running on `127.0.0.1:12345` on both, with the YubiHSM in factory state.
- The Yubico trust file (root plus intermediates) at `/etc/bastionvault/yubico-attestation.pem`
  on both, owned by root and read-only ([how to build it](hsm.md#yubico-attestation-trust-file)).
  Without it every attestation is refused.
- A CA for the HSM link and, per server, a gateway server certificate and a node client certificate
  (DNS SAN = `node_id`): `ca.pem`, `hsm-a.pem/.key`, `hsm-b.pem/.key`, `vault-1.pem/.key`,
  `vault-2.pem/.key` in `/etc/bastionvault/hsm-link/`.
- `hiqlite` storage (a pool refuses other storage in a cluster).
- Decide the recovery mode **before init**; it cannot be enabled later:
  - `recovery = "shamir-ceremony"` (recommended): init returns Shamir recovery shares exactly once.
  - `recovery = "none"`: losing both HSMs loses the vault.
- Keep each device's `bv-admin` password in the team's password manager. It is never passed as a command-line argument.

## 1. Provision each YubiHSM

On **server1**:

```bash
export HSM_ADMIN_PW_A='<strong bv-admin password for hsm-a>'
bvault operator hsm provision --connector http://127.0.0.1:12345 \
  --admin-password env:HSM_ADMIN_PW_A --out /root/hsm-a.json
```

On **server2**:

```bash
export HSM_ADMIN_PW_B='<strong bv-admin password for hsm-b>'
bvault operator hsm provision --connector http://127.0.0.1:12345 \
  --admin-password env:HSM_ADMIN_PW_B --out /root/hsm-b.json
```

Without `--admin-password` the password is prompted on the terminal. The bundle (`*.json`) holds no secrets.

Copy `hsm-b.json` from server2 to server1: the init node needs both bundles.
Note each device's serial (it is in the bundle).

## 2. HSM gateways (both servers)

`/etc/bastionvault/hsm-gateway.hcl` on server1:

```hcl
hsm_gateway {
  listen          = "0.0.0.0:8250"
  connector       = "http://127.0.0.1:12345"
  tls_cert_file   = "/etc/bastionvault/hsm-link/hsm-a.pem"
  tls_key_file    = "/etc/bastionvault/hsm-link/hsm-a.key"
  client_ca_file  = "/etc/bastionvault/hsm-link/ca.pem"
  allowed_clients = ["vault-1", "vault-2"]
}
```

Server2 is the same with `hsm-b.pem/.key`. Start it on both:

```bash
bvault hsm-gateway --config /etc/bastionvault/hsm-gateway.hcl
```

## 3. Vault configuration

Server1 (`/etc/bastionvault/config.hcl`, storage and HSM sections):

```hcl
storage "hiqlite" {
  data_dir    = "/var/lib/bvault/data"
  node_id     = 1
  secret_raft = "<raft-secret>"
  secret_api  = "<api-secret-16+-chars>"
  nodes = [
    "1:server1:8210:server1:8220",
    "2:server2:8210:server2:8220",
  ]
}

hsm "yubihsm2" {
  topology               = "pool"
  node_id                = "vault-1"
  credential_dir         = "/var/lib/bastionvault/hsm"
  attestation_roots_file = "/etc/bastionvault/yubico-attestation.pem"
  recovery               = "shamir-ceremony"

  link {
    ca_file   = "/etc/bastionvault/hsm-link/ca.pem"
    cert_file = "/etc/bastionvault/hsm-link/vault-1.pem"
    key_file  = "/etc/bastionvault/hsm-link/vault-1.key"
  }

  member "hsm-a" {
    connector = "http://127.0.0.1:12345"
    serial    = "<SERIAL_A>"
  }
  member "hsm-b" {
    gateway = "https://server2:8250"
    serial  = "<SERIAL_B>"
  }
}
```

Server2: `storage` with `node_id = 2`, and in the `hsm` block use
`node_id = "vault-2"`, a `link` block with `vault-2.pem/.key`,
`member "hsm-a"` with `gateway = "https://server1:8250"` and
`member "hsm-b"` with `connector = "http://127.0.0.1:12345"`.

The host in each gateway URL must be in the gateway certificate's SAN.

Note: hiqlite with two nodes has no quorum tolerance, so losing either node stops writes. If that matters, add a
third storage node; it needs no HSM of its own, only the `hsm` block with both members through `gateway`.

## 4. Start the servers

```bash
export BVAULT_ENV=production
bvault server --config /etc/bastionvault/config.hcl
```

On both. Before init they are expected to stay sealed. On **server2** the log shows:

```
HSM pool node vault-2 transport key fingerprint: <FP> (confirm it before `node add`)
```

Note `<FP>` and confirm out of band (another session or another person) that it belongs to `vault-2`.

## 5. Bootstrap and init (on server1, node `vault-1`)

Bootstrap answers only loopback callers and only before init. It attests both HSMs and enrolls `vault-1`.

```bash
export HSM_ADMIN_PW_A='...' HSM_ADMIN_PW_B='...'
bvault operator hsm bootstrap \
  --bundle hsm-a=/root/hsm-a.json --bundle hsm-b=/root/hsm-b.json \
  --admin hsm-a=env:HSM_ADMIN_PW_A --admin hsm-b=env:HSM_ADMIN_PW_B

bvault operator init --recovery-shares 5 --recovery-threshold 3
```

`init` prints the root token and the 5 recovery shares **once**. Give each share to a different custodian and
store the root token safely. With `recovery = "none"` there are no shares (omit both flags).
There are no unseal shares: the HSM seal opens by itself.

## 6. Enroll `vault-2`

On server1, with the `<FP>` confirmed in step 4:

```bash
export VAULT_TOKEN='<root token>'
bvault operator hsm node add vault-2 --fingerprint <FP> \
  --admin hsm-a=env:HSM_ADMIN_PW_A --admin hsm-b=env:HSM_ADMIN_PW_B
bvault operator hsm node list
```

## 7. Unseal and verify

With an HSM there is no manual `operator unseal`: each node unseals on start. If `vault-2` is still sealed after
`node add`, restart its process and it opens.

```bash
bvault operator hsm status      # on each server
bvault operator hsm members
```

Expected on each node: `sealed: false`, `redundancy: "full"`, `members_active: 2`, both members `up`.
If a member stays `joining`, run
`bvault operator hsm repair --run --admin hsm-a=env:HSM_ADMIN_PW_A --admin hsm-b=env:HSM_ADMIN_PW_B`.

Optional resilience check (in a maintenance window): stop one HSM's gateway/connector and confirm the other
node still unseals through the remaining member.

## Notes

- The YubiHSM 2 pool path has been validated on hardware with **one** device only; the two-device run is still
  pending (`hsm.md`, "Phase 7"). Rehearse in a staging environment first.
- At most two HSMs per pool and 12 nodes. To replace a failed HSM: `member retire`, `repair --run`,
  `member add` for the replacement, then `repair --run --admin ...` (see `hsm.md`).
- Total loss recovery (both HSMs lost): `bvault operator hsm recover` with the shares from step 5.
