# BastionVault 3-node cluster (compose reference)

This directory hosts the supporting files for `deploy/compose/cluster.yml`:
the per-node Hiqlite configurations and (operator-supplied) TLS material.

## Layout

```
deploy/compose/cluster/
├── README.md          (this file)
├── node1.hcl          # node_id = 1, advertises bv-1
├── node2.hcl          # node_id = 2, advertises bv-2
├── node3.hcl          # node_id = 3, advertises bv-3
└── tls/               # operator-supplied; mounted read-only
    ├── server.crt     # API listener cert
    ├── server.key     # API listener key
    ├── raft.crt       # (optional) Hiqlite Raft cert if you don't want
    ├── raft.key       #            the auto-generated self-signed pair
    ├── api.crt        # (optional) Hiqlite internal-API cert
    └── api.key        #            ditto
```

The image runs as UID 65532 inside the container. Make sure the host-side
files are readable by that UID (`chmod 0644 *.hcl tls/*.crt`,
`chmod 0640 tls/*.key`, then `chown 65532:65532 ...`).

## Operator quickstart

```sh
# 1. Generate / drop in real TLS material under ./tls/.
#    Self-signed test material. The extensions matter: rustls/webpki
#    (used by the `bvault` CLI) rejects certs with `CA:TRUE` as a TLS
#    leaf (`CaUsedAsEndEntity`) and requires a SAN — CN alone is not
#    accepted. Replace the SAN entries with the hostnames/IPs your
#    clients will actually connect to.
mkdir -p tls
openssl req -x509 -newkey ed25519 -nodes -days 90 \
    -subj "/CN=bastionvault-cluster" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "subjectAltName=DNS:bv-1,DNS:bv-2,DNS:bv-3,DNS:localhost,IP:127.0.0.1" \
    -keyout tls/server.key -out tls/server.crt
chmod 0640 tls/server.key
chmod 0644 tls/server.crt

# 2. Replace the `change_me_*` secrets in node{1,2,3}.hcl with values
#    that fail the placeholder check. Both `secret_raft` and `secret_api`
#    must match across all three nodes.

# 3. Bring the cluster up.
podman compose -f deploy/compose/cluster.yml up -d

# 4. Watch leader election converge (one node logs "became leader").
podman compose -f deploy/compose/cluster.yml logs -f bv-1 | grep -E "leader|raft"

# 5. Initialise + unseal against any node (convention: bv-1).
podman compose -f deploy/compose/cluster.yml exec bv-1 bvault operator init
podman compose -f deploy/compose/cluster.yml exec bv-1 bvault operator unseal <key-1>
podman compose -f deploy/compose/cluster.yml exec bv-1 bvault operator unseal <key-2>
podman compose -f deploy/compose/cluster.yml exec bv-1 bvault operator unseal <key-3>

# 6. Each follower then needs its own unseal:
for n in bv-2 bv-3; do
  podman compose -f deploy/compose/cluster.yml exec $n bvault operator unseal <key-1>
  podman compose -f deploy/compose/cluster.yml exec $n bvault operator unseal <key-2>
  podman compose -f deploy/compose/cluster.yml exec $n bvault operator unseal <key-3>
done
```

Auto-init and auto-unseal are deliberately not provided. See
[features/packaging-podman-server.md](../../../features/packaging-podman-server.md)
for the rationale.
