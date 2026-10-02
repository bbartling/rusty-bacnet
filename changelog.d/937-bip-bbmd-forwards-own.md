---
section: Fixed
---
- A B/IP BBMD now forwards its own broadcasts (#937). Before, `send_broadcast`
  in BBMD mode sent only the local Original-Broadcast-NPDU, so the BBMD's own
  Who-Is, I-Am and Network-Number-Is, and broadcasts it routed, never reached
  remote subnets or foreign devices, and they could not discover its device by
  broadcast. It now also queues a Forwarded-NPDU, with its own B/IP address as
  the originating address, for every BDT entry except its own (directed
  broadcast or unicast, by the entry's mask) and for its registered foreign
  devices (Annex J.4.5), at most `ForeignDevicePolicy::max_fdt_fanout` of them
  (default 32) and `FanoutPolicy::max_fanout_per_input` targets in all
  (default 64). This fanout goes through the same `FanoutPolicy` queue and rate
  limits, and `fanout_counters()`, as forwarded input. The per-origin limit is
  keyed on IP, so the BBMD's own broadcasts, routed ones included, share one
  budget of 128 forwarded packets per second by default: about 128/T complete
  broadcasts per second with T targets, after which foreign devices are cut
  first. Throttled targets, queue overflow and failed sends are counted and
  logged, and none of them fail the local broadcast; in BBMD mode an `Err` from
  `send_broadcast` can follow a forward that was already queued. Plain and
  foreign-device modes are unchanged.

  A BBMD bound to `0.0.0.0` now reads its own address from the BDT it starts
  with: the one row at a local IPv4 address and the bound port, or else the
  local address toward the default route if that is one of the host's
  addresses and not loopback. `start()` fails, asking for an explicit
  interface, when several rows qualify or no usable address is found. A
  persisted BDT that loads is authoritative: a failure to choose from it fails
  `start()` rather than falling back to the configured BDT (a self row that
  would overflow it still falls back, with a warning). Windows applies the
  same rules, since it now lists local addresses too (#952). Before, it took
  the default-route address or 127.0.0.1, so a multihomed or offline BBMD
  forwarded with the wrong origin and could forward to itself. Each start of a
  `0.0.0.0` BBMD chooses again, moving the self row the BBMD appended; a
  failed start keeps the BBMD configuration, and a failed restart keeps its
  BDT and FDT. With broadcast address 255.255.255.255 and an own address that
  is not the default-route address, `start()` warns that the kernel may send
  broadcasts from another interface, whose echo would not be recognised.
  `BbmdState::local_address` is new.

  A BBMD no longer rebroadcasts on its subnet a Forwarded-NPDU that arrived by
  broadcast, to the configured broadcast address or 255.255.255.255, even from
  a peer whose BDT mask calls for a local rebroadcast; it still sends it to its
  foreign devices. The subnet already received it (Annex J.4.5), and a BDT row
  that is the BBMD itself under another address could otherwise loop it.
