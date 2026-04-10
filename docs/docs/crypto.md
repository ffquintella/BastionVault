---
sidebar_position: 3
title: Crypto Adaptor
---
# BastionVault Crypto Adaptor

In BastionVault, older runtime crypto paths still use a "crypto adaptor" mechanism to connect to the underlying cryptography library.

The supported legacy adaptor is:

* OpenSSL crypto adaptor

## The OpenSSL Crypto Adaptor

The following steps require a properly installed OpenSSL library. There are many ways of installing an OpenSSL on various platforms, so in this docuemnt we don't discuss that part.

The OpenSSL crypto adaptor is configured by default in BastionVault, so you can simply build BastionVault to enable it:

~~~
cargo build
~~~

Otherwise if you want to explicitly configure it, you can still use something like:

~~~
cargo build --features crypto_adaptor_openssl
~~~

But this is not necessary.

## Migration Direction

New post-quantum work is not being added to the legacy adaptor layer.

The current migration direction is:

* `ChaCha20-Poly1305` for payload encryption
* `ML-KEM-768` for key wrapping and key establishment
* smaller crypto modules and crates such as [crates/bv_crypto](/Users/felipe/Dev/BastionVault/crates/bv_crypto)

Tongsuo is no longer a supported BastionVault backend. Remaining OpenSSL-based paths are being reduced incrementally as the PQ migration continues.
