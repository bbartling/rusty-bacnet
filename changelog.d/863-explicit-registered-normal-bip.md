---
section: Fixed
---
- Explicit registered NORMAL B/IP Network Port selection now reconciles the chosen
  object/identity with its actual bind, protects it through admitted work and final
  cleanup, and resolves receiving-port wildcard RP/RPM with concrete Audit targets.
  Python B/IP endpoint address/status are active-only and report actual port-zero
  binds. Removed the pre-1.0 `DeviceIdentity::sync_bip_bind` mutation hook; endpoint
  stop now reports ingress cleanup failures. Multiport/rebind remains separate (#863).
