---
title: "Upgrade and migrate from v0.11.0"
description: "Review breaking changes before replacing a working integration."
---

Do not treat this pre-1.0 update as a drop-in replacement merely because the package name stayed the same. Read the release notes and changelog, then test the application behaviors you actually use.

## Choose the destination

The release instructions below remain specific to v0.11.0. Moving to current development is a separate source migration; use the checklist later on this page and keep the checkout revision with your environment.

## Before updating

Record your current package/binary version, enabled features, platform, transport, and important application workflows. Back up persisted Audit Log snapshots before attempting a migration. Keep a known-working deployment or environment available according to your operational policy.

## Update the selected interface

In a Python virtual environment:

```sh
python -m pip install --upgrade rusty-bacnet==0.11.0
```

For Rust, align the application's `bacnet-*` dependencies with `0.11.0`. For the CLI, install or download the intended v0.11.0 binary and confirm its version and required features.

## Review the affected behavior

The release calls out CLI alarm timestamp inputs; Rust event and recipient APIs; typed Audit/COV models; object constructor changes; corrected wire/property values; and withdrawn unsupported server/WASM surfaces.

Audit Log persistence has a new receipt-aware snapshot format documented in the Rust API guide. Do not invent a generic converter or assume old and new snapshots are interchangeable. Follow the documented format and verify restoration in a non-production environment.

## Verify more than import success

Exercise a known read, error handling, any routing or segmentation paths you depend on, subscription lifecycle, relevant server objects, and controlled cleanup. SC and MS/TP deployments need transport-specific validation, not only package-level tests.

Retest your application's output parsing where it depends on CLI JSON or typed Python/Rust models. Separate regressions from corrected behavior that an older integration may have depended on accidentally.

## Moving from v0.11 to current development

Build a separate [development environment](/rusty-bacnet/development/overview/#build-a-source-checkout). Do not overwrite a working release environment before exercising the operations your application uses. Pre-1.0 APIs may be removed directly; compilation and import success are only the first checks.

| Area | Migration checkpoint |
|---|---|
| SC trust and identity | Explicit CLI CA; required Python operational credentials and durable device UUID; review [current SC setup](/rusty-bacnet/development/bacnet-sc/) |
| Shared endpoints | Choose the one-transport owner and its narrower responder; await cleanup; do not assume standalone service parity |
| Endpoint writes/Audit | Declare commandability for direct B/IP writes; source Reporter configuration remains Rust-only and distinct from target reporting |
| Network Port | Explicitly select the NORMAL B/IP receiving port; a declaration alone does not bind it or supply configured authority |
| Number helper | Rust `NetworkNumber` moved from `bacnet_objects::network_port` to `bacnet_types::network_number` without an alias; use the checked configured constructor |
| IPv6 | Select a concrete interface/address when automatic selection is ambiguous; no silent physical-selection fallback to loopback |
| Python async calls | Native methods return Futures typed as Awaitable; await them or use `ensure_future`, not `create_task` directly on a native Future |

The [shared endpoint guide](/rusty-bacnet/development/shared-endpoints/), [Network Port guide](/rusty-bacnet/development/network-number/) and [canonical APIs](/rusty-bacnet/reference/api/) explain the contracts. This is a navigation checklist, not an exhaustive changelog. Retest request errors, subscriptions, mutation authorization, persistence and shutdown relevant to your application. The [current changelog](https://gitlab.com/justinscott-group/rusty-bacnet/-/blob/dev/CHANGELOG.md) and source references remain the detail authority.

## Sources and release scope

The release update above targets **v0.11.0**; the development checklist is explicitly unreleased. Source review is not hardware qualification.

[v0.11.0 release notes](https://github.com/jscott3201/rusty-bacnet/releases/tag/v0.11.0) · [Changelog](https://github.com/jscott3201/rusty-bacnet/blob/v0.11.0/CHANGELOG.md) · [Audit persistence documentation](https://github.com/jscott3201/rusty-bacnet/blob/v0.11.0/docs/rust-api.md).
