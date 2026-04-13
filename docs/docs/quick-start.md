---
sidebar_position: 1
title: Quick Start
---

# BastionVault Quick Start

This guide covers the minimum steps to start a BastionVault server and use it to store secrets.

## Build from Source

Read [install.md](./install.md) for more detailed information on installation.

Clone BastionVault from GitHub:

~~~bash
git clone https://github.com/ffquintella/BastionVault.git
cd BastionVault
~~~

Build BastionVault:

~~~bash
make build
~~~

After a successful build, the `rvault` executable will be in `target/release/`.

## Configure the Server

BastionVault requires a configuration file. Create a file called `config.hcl`:

~~~conf
storage "file" {
    path = "./vault/data"
}

listener "tcp" {
    address     = "127.0.0.1:8200"
    tls_disable = true
}

api_addr  = "http://127.0.0.1:8200"
log_level = "debug"
pid_file  = "bastion_vault.pid"
~~~

For production use, you should enable TLS by providing `tls_cert_file` and `tls_key_file` instead of setting `tls_disable = true`.

## Run the Server

Launch the server:

~~~bash
target/release/rvault server --config config.hcl
~~~

Or for development using the included config:

~~~bash
make run-dev
~~~

The server will listen on TCP port 8200 and is ready for incoming HTTP requests.

## Initialize BastionVault

Before it's fully usable, a BastionVault server needs to be initialized. During initialization, a master key is generated and used to seal and unseal BastionVault, ensuring that stored data is properly encrypted.

We use `curl` to interact with the server and `jq` to parse JSON responses. Install `jq` from [here](https://jqlang.github.io/jq/download/) if you don't have it.

Initialize BastionVault:

~~~bash
curl --request PUT \
  --data '{"secret_shares": 1, "secret_threshold": 1}' \
  http://127.0.0.1:8200/v1/sys/init | jq
~~~

The response should look like:

~~~json
{
  "keys": [
    "7df5ff90cd9417e04cbb9f6db65e0b16ce265d5108fd07e45bdae1a35bf5da6a"
  ],
  "root_token": "bc9e904b-acff-db3d-4cfd-f575cb36428a"
}
~~~

Save the key and root token. You can verify initialization:

~~~bash
curl http://127.0.0.1:8200/v1/sys/init | jq
~~~

## Unseal the Server

After initialization, BastionVault is in a *sealed* state. Everything is encrypted and inaccessible. You need to *unseal* it to make it functional.

Use the key from the initialization step:

~~~bash
curl --request PUT \
  --data '{"key": "7df5ff90cd9417e04cbb9f6db65e0b16ce265d5108fd07e45bdae1a35bf5da6a"}' \
  http://127.0.0.1:8200/v1/sys/unseal | jq
~~~

A response with `"sealed": false` confirms the server is unsealed:

~~~json
{
  "sealed": false,
  "t": 1,
  "n": 1,
  "progress": 0
}
~~~

## Write Secrets

BastionVault provides a secure key-value storage for sensitive data such as passwords, credentials, tokens, and keys.

Use the `root_token` from initialization for authentication:

Write a secret:

~~~bash
curl -H "Cookie: token=bc9e904b-acff-db3d-4cfd-f575cb36428a" \
  --request POST \
  --data '{ "foo": "bar" }' \
  http://127.0.0.1:8200/v1/secret/test | jq
~~~

Read it back:

~~~bash
curl -H "Cookie: token=bc9e904b-acff-db3d-4cfd-f575cb36428a" \
  http://127.0.0.1:8200/v1/secret/test | jq
~~~

~~~json
{
  "renewable": false,
  "lease_id": "",
  "lease_duration": 3600,
  "auth": null,
  "data": {
    "foo": "bar"
  }
}
~~~

## Next Steps

The examples above are for demonstration only. For production deployments, consider:

* **TLS**: Enable TLS with proper certificates instead of `tls_disable = true`.
* **Authentication methods**: Configure AppRole, userpass, or certificate authentication instead of relying on the root token.
* **Storage backends**: Use MySQL or PostgreSQL for durable production storage instead of the local file backend.
* **Shamir's Secret Sharing**: Use multiple key shares (`secret_shares > 1`) so that no single person can unseal the vault alone.
* **Compatibility with HashiCorp Vault**: BastionVault is API-compatible with HashiCorp Vault, so most Vault documentation and tooling applies.
