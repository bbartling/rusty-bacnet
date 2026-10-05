---
section: Changed
---
- **Python API:** `BACnetServer.start()` raises `BacnetError`, naming the
  device and the address, when `add_device_binding` gave a multicast address,
  255.255.255.255 or the broadcast IP at another port (#1493).
