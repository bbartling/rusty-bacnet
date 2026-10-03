---
section: Fixed
---
- Served Device service bits, COV property presence, Property_List and RPM
  classification now come from the actual executor (#834). Full-server reads,
  local reads and PICS remain coherent after Device profile mutation, replacement
  or custom readers. WP, WPM and network-equivalent local writes deny assignment
  of these executor-owned fields before custom Device writers. Endpoint responders
  expose RP or RP+WP and no COV lists;
  incompatible server-role identity service declarations fail before ingress.
  Standalone built-in Device reads follow their declared profile, which does not
  enable or disable runtime dispatch. ClientOnly retains a local declaration.
