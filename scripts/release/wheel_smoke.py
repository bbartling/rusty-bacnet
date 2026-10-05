#!/usr/bin/env python3
"""Smoke-test an installed rusty_bacnet wheel (#951), in the interpreter it is
installed into:

    python -I scripts/release/wheel_smoke.py --version 0.12.0

- the installed distribution is the release version (Cargo's form is given,
  mapped to PEP 440 as maturin does);
- list_serial_ports() returns a list of port names. On macOS that call goes
  through IOKit and CoreFoundation, which the extension module links, and the
  script checks that both frameworks are loaded; on Windows it goes through
  SetupAPI;
- a loopback round trip with the public API: a BACnetServer on 127.0.0.1 with
  an analog input and an analog value, and a BACnetClient that reads the
  input's present value, reads it and the object name with
  ReadPropertyMultiple, writes the value's present value at priority 8 and
  reads it back.

Every network step has a timeout, and a stuck run dumps its threads and exits
after two minutes.
"""

import argparse
import asyncio
import faulthandler
import importlib.metadata
import importlib.util
import platform
import sys
from pathlib import Path

DEVICE = 9951


def pep440(version):
    """check_artifacts.py's mapping, loaded by path: -I keeps this directory off sys.path."""
    spec = importlib.util.spec_from_file_location("check_artifacts", Path(__file__).with_name("check_artifacts.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.pep440(version)


def loaded_images():
    """The paths of the images dyld has loaded into this process (macOS)."""
    import ctypes

    libc = ctypes.CDLL(None)
    libc._dyld_image_count.restype = ctypes.c_uint32
    libc._dyld_get_image_name.restype = ctypes.c_char_p
    libc._dyld_get_image_name.argtypes = [ctypes.c_uint32]
    return [libc._dyld_get_image_name(i).decode() for i in range(libc._dyld_image_count())]


def check_serial_ports(rb):
    ports = rb.list_serial_ports()
    if not isinstance(ports, list) or not all(isinstance(p, str) and p for p in ports):
        raise SystemExit(f"list_serial_ports() returned {ports!r}, not a list of port names")
    print(f"list_serial_ports(): {ports}")
    if sys.platform == "darwin":
        images = loaded_images()
        for framework in ("IOKit", "CoreFoundation"):
            found = [path for path in images if f"/{framework}.framework/" in path]
            if not found:
                raise SystemExit(f"{framework} isn't loaded after list_serial_ports()")
            print(f"loaded: {found[0]}")


async def round_trip(rb):
    pv, name = rb.PropertyIdentifier.PRESENT_VALUE, rb.PropertyIdentifier.OBJECT_NAME
    ai = rb.ObjectIdentifier(rb.ObjectType.ANALOG_INPUT, 1)
    av = rb.ObjectIdentifier(rb.ObjectType.ANALOG_VALUE, 2)
    server = rb.BACnetServer(DEVICE, "Release smoke test", interface="127.0.0.1", port=0,
                             broadcast_address="127.0.0.1")
    server.add_analog_input(1, "Zone temperature", units=62, present_value=22.5)
    server.add_analog_value(2, "Setpoint", units=62)
    await asyncio.wait_for(server.start(), 10)
    try:
        address = await asyncio.wait_for(server.local_address(), 10)
        print(f"server listening at {address}")
        client = rb.BACnetClient(interface="127.0.0.1", port=0, broadcast_address="127.0.0.1",
                                 apdu_timeout_ms=3000)
        async with client:
            value = await asyncio.wait_for(client.read_property(address, ai, pv), 10)
            print(f"ReadProperty AI 1 present value: {value.value}")
            if value.value != 22.5:
                raise SystemExit(f"read {value.value!r}, expected 22.5")

            results = await asyncio.wait_for(
                client.read_property_multiple(address, [(ai, [(pv, None), (name, None)])]), 10)
            got = {r["property_id"]: r["value"] for r in results[0]["results"]}
            print(f"ReadPropertyMultiple AI 1: {[(str(k), getattr(v, 'value', v)) for k, v in got.items()]}")
            if got.get(pv) is None or got[pv].value != 22.5 or got.get(name) is None \
                    or got[name].value != "Zone temperature":
                raise SystemExit(f"ReadPropertyMultiple returned {results!r}")

            await asyncio.wait_for(client.write_property(address, av, pv, rb.PropertyValue.real(21.5), priority=8), 10)
            value = await asyncio.wait_for(client.read_property(address, av, pv), 10)
            print(f"WriteProperty AV 2 present value 21.5 at priority 8, read back: {value.value}")
            if value.value != 21.5:
                raise SystemExit(f"read back {value.value!r}, expected 21.5")
    finally:
        await asyncio.wait_for(server.stop(), 10)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="the release version, in Cargo's form")
    args = parser.parse_args(argv)
    faulthandler.dump_traceback_later(120, exit=True)

    import rusty_bacnet as rb

    installed = importlib.metadata.version("rusty-bacnet")
    print(f"rusty_bacnet {installed} from {rb.__file__}")
    print(f"Python {platform.python_version()} ({sys.implementation.name}) on {platform.platform()},"
          f" {platform.machine()}")
    if installed != pep440(args.version):
        raise SystemExit(f"the installed rusty-bacnet is {installed}, not {pep440(args.version)}")
    check_serial_ports(rb)
    asyncio.run(round_trip(rb))
    print("wheel smoke test passed")


if __name__ == "__main__":
    main()
