"""BACnet MS/TP mini-device example (USB RS-485).

Runs a token-participating MS/TP master with a small object set, similar to the
BACnet/IP ``bip_client_server`` sample but over RS-485.

Hardware notes
--------------
- Prefer a Waveshare / FTDI USB-RS485 adapter with automatic direction control.
- Pick a free station MAC (never steal MAC 0 if a BAS router owns it).
- Live trunk coexistence with commercial masters needs the Clause 9 CRC / USB
  stream / 9.5.6 token fixes (see upstream PR #467).

Usage::

    python mstp_mini_device.py --serial /dev/serial/by-id/usb-... --mac 3

Requires a build of ``rusty_bacnet`` that includes this PR (``transport=\"mstp\"``).
"""

from __future__ import annotations

import argparse
import asyncio
import signal

from rusty_bacnet import BACnetServer


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MS/TP BACnet mini-device example")
    p.add_argument(
        "--serial",
        required=True,
        help="Serial device path (prefer /dev/serial/by-id/...)",
    )
    p.add_argument("--baud", type=int, default=38400, help="MS/TP baud (default 38400)")
    p.add_argument("--mac", type=int, default=3, help="This station MAC (default 3)")
    p.add_argument(
        "--max-master",
        type=int,
        default=127,
        help="Max_Master (default 127; lower on small trunks)",
    )
    p.add_argument(
        "--max-info-frames",
        type=int,
        default=1,
        help="Max_Info_Frames per token (default 1)",
    )
    p.add_argument("--instance", type=int, default=123001, help="Device instance")
    p.add_argument(
        "--name",
        default="Python MS/TP Mini Device",
        help="Device object-name",
    )
    return p.parse_args()


async def main() -> None:
    args = parse_args()

    server = BACnetServer(
        device_instance=args.instance,
        device_name=args.name,
        transport="mstp",
        serial_port=args.serial,
        mstp_baud=args.baud,
        mstp_mac=args.mac,
        mstp_max_master=args.max_master,
        mstp_max_info_frames=args.max_info_frames,
    )
    server.add_analog_input(instance=1, name="Zone Temp", units=62, present_value=72.5)
    server.add_binary_input(instance=1, name="Occupancy")
    server.add_analog_value(instance=2, name="Cooling Setpoint", units=62)
    server.add_binary_value(instance=2, name="Override Mode")

    await server.start()
    addr = await server.local_address()
    print(
        f"MS/TP mini-device running: MAC={addr} instance={args.instance} "
        f"baud={args.baud} serial={args.serial}"
    )
    print("Discover from Workbench / a peer client; Ctrl-C to stop.")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            # Windows: fall back to KeyboardInterrupt via wait
            pass
    try:
        await stop.wait()
    except KeyboardInterrupt:
        pass

    await server.stop()
    print("Stopped.")


if __name__ == "__main__":
    asyncio.run(main())
