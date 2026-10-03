---
section: Fixed
---
- Replace incomplete raw Network Port construction with a configured, unbound
  IPV4/NORMAL snapshot: required application properties and DNS array, readonly
  configuration/derived MAC, optional unknown Link_Speed, and no inert Command or
  obsolete port62. Python uses `add_bip_network_port`; Device62 is unchanged (#867).
