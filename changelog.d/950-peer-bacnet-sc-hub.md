---
section: Fixed
---
- A peer that the BACnet/SC hub or a direct-connection listener refuses
  during the TLS handshake can now read the alert that says why (#950). The
  socket used to be dropped with the client's HTTP upgrade request unread,
  which resets the connection, and a Windows client then discarded the alert
  and saw only "connection reset". The listener now sends FIN after the alert
  and drains what the peer still sends until it closes, for at most 500 ms
  and 64 KiB, and within the handshake deadline.
