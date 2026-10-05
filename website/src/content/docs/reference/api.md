---
title: "API and example library"
description: "Find exact signatures for the release or current source without mixing their contracts."
---

Use the website for tasks and the canonical references for exact methods, parameters, types and feature gates. Choose the revision first; development APIs may differ even while their package version still reads the latest release's number.

## Current development

Start with the [development overview](/rusty-bacnet/development/overview/) and [engineering documentation map](https://github.com/jscott3201/rusty-bacnet/blob/dev/docs/README.md).

| Reference | Use it for |
|---|---|
| [Rust API](https://github.com/jscott3201/rusty-bacnet/blob/dev/docs/rust-api.md) | Crate APIs, feature gates, shared endpoint contracts, transport ownership and migration details |
| [Python API](https://github.com/jscott3201/rusty-bacnet/blob/dev/docs/python-api.md) | Constructors, native Awaitable results, endpoint lifecycle and binding-specific limits |
| [Python type stub](https://github.com/jscott3201/rusty-bacnet/blob/dev/crates/rusty-bacnet/rusty_bacnet.pyi) | Editor-facing signatures for the matching native build |
| [CLI reference](https://github.com/jscott3201/rusty-bacnet/blob/dev/docs/CLI.md) | Current flags and transport prerequisites |
| [Architecture](https://github.com/jscott3201/rusty-bacnet/blob/dev/docs/architecture.md) | Crate composition, packet paths and lifecycle ownership |

For source checkout rustdoc, select the features used by your application. Do not assume every workspace crate is published or that a published documentation page matches the current checkout. Use the [shared endpoint guide](/rusty-bacnet/development/shared-endpoints/) to compare requester, responder and source Audit scope before choosing that owner.

## Release v0.11.0

The preserved [Rust API guide](https://github.com/jscott3201/rusty-bacnet/blob/v0.11.0/docs/rust-api.md), [Python API guide](https://github.com/jscott3201/rusty-bacnet/blob/v0.11.0/docs/python-api.md) and [distributed type stub](https://github.com/jscott3201/rusty-bacnet/blob/v0.11.0/crates/rusty-bacnet/rusty_bacnet.pyi) describe the release. Its workspace manifest defines the release version and Rust minimum.

The release Python transport summary omits MS/TP; use the versioned mini-device example and implementation for that path. A type constant alone does not prove that a bundled server implements an object family.

## Examples by task

| Example | Read it for | Review before running |
|---|---|---|
| `bip_client_server.py` | Client/server lifecycle, reads and RPM | Socket exposure and demonstration writes |
| `cov_subscriptions.py` | Subscriptions and consumption | Remote subscription state and cleanup |
| `sc_secure_connect.py` | Hub and node configuration | Credentials and identity rules at the chosen revision |
| `mstp_mini_device.py` | Standalone serial device | Adapter, MAC, baud and token participation |
| `device_management.py` | Management services and errors | Control-changing operations |

Browse [current examples](https://github.com/jscott3201/rusty-bacnet/tree/dev/examples/python) or [v0.11 examples](https://github.com/jscott3201/rusty-bacnet/tree/v0.11.0/examples/python). The site's [local lab](/rusty-bacnet/start/local-lab/) keeps its tested release source and download together.
