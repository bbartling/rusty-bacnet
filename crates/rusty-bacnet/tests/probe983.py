"""TEMPORARY diagnostic for #983; remove before merge.

Repeats AcceptUuidTests in one process with an instrumented check_accept that
timestamps each phase, plus three stall monitors: a separate process (machine
stalls), a Python thread (GIL starvation), and an event-loop task that arms a
faulthandler dump when the loop stalls.
"""
import asyncio
import base64
import faulthandler
import gc
import hashlib
import logging
import os
import ssl
import subprocess
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rusty_bacnet import BACnetClient, BACnetServer, BacnetError  # noqa: E402
import test_sc_hub_mtls as mtls  # noqa: E402
import test_sc_accept_uuid as accept  # noqa: E402

T0 = time.time()


def stamp():
    now = time.time()
    wall = time.strftime("%H:%M:%S", time.gmtime(now)) + f".{int(now * 1000) % 1000:03d}"
    return f"{now - T0:9.3f} {wall}"


def log(msg):
    print(f"[{stamp()}] {msg}", flush=True)


MONITOR = r"""
import sys, time
t0 = float(sys.argv[1]); last = time.perf_counter()
while True:
    time.sleep(0.005)
    n = time.perf_counter()
    if n - last > 0.15:
        print(f"[{time.time() - t0:9.3f}] PROC-STALL {n - last:.3f}s", flush=True)
    last = n
"""


def gil_monitor(dump):
    # Needs the GIL after every sleep. With dump set, faulthandler's watchdog
    # (which needs no GIL) prints every thread's stack once this thread has
    # gone 0.6 s without re-arming it.
    last = time.perf_counter()
    tick = 0
    while True:
        if dump and tick % 20 == 0:
            faulthandler.dump_traceback_later(0.6, repeat=False)
        tick += 1
        time.sleep(0.005)
        n = time.perf_counter()
        if n - last > 0.15:
            log(f"GIL-STALL {n - last:.3f}s")
        last = n


GC_START = {}


def gc_timer(phase, info):
    if phase == "start":
        GC_START[threading.get_ident()] = time.perf_counter()
    else:
        took = time.perf_counter() - GC_START.pop(threading.get_ident(), time.perf_counter())
        if took > 0.05:
            log(f"GC gen={info['generation']} took={took:.3f}s collected={info['collected']} "
                f"thread={threading.current_thread().name} objects={len(gc.get_objects())}")


async def loop_monitor():
    last = time.perf_counter()
    while True:
        faulthandler.dump_traceback_later(0.75, repeat=False)
        await asyncio.sleep(0.01)
        n = time.perf_counter()
        if n - last > 0.15:
            log(f"LOOP-STALL {n - last:.3f}s")
        last = n


async def check_accept(self, api, recover, limits=None):
    loop = asyncio.get_running_loop()
    loop.slow_callback_duration = 0.1
    monitor = asyncio.ensure_future(loop_monitor())
    t = time.perf_counter()
    marks = {}

    def mark(name):
        marks[name] = time.perf_counter() - t

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(self.path("hub.pem"), self.path("hub.key"))
    context.load_verify_locations(self.path("site.pem"))
    context.verify_mode = ssl.CERT_REQUIRED
    tasks = []
    nil_checked = asyncio.Event()
    release_valid = asyncio.Event()
    outcome = loop.create_future()
    uuid = mtls.SERVER_UUID if api is BACnetServer else mtls.CLIENT_UUID
    vmac = b"\x02\0\0\0\0\x04" if api is BACnetServer else b"\x02\0\0\0\0\x02"

    async def peer(reader, writer):
        mark("tls_accepted")
        tasks.append(asyncio.current_task())
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
            mark("http_read")
            headers = dict(line.split(b":", 1) for line in request.split(b"\r\n")[1:] if b":" in line)
            key = next(value.strip() for name, value in headers.items()
                       if name.lower() == b"sec-websocket-key")
            accept_key = base64.b64encode(hashlib.sha1(
                key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
            writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                         b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept_key +
                         b"\r\nSec-WebSocket-Protocol: hub.bsc.bacnet.org\r\n\r\n")
            await asyncio.wait_for(writer.drain(), 30)
            opcode, request = await self.frame(reader, True)
            mark("connect_request")
            nil = b"\x07\0\0\1" + b"\x22" * 6 + bytes(16) + b"\x20\0\x10\0"
            if limits is not None:
                nil = nil[:10] + b"\xff" * 16 + limits
            for wire in (nil, nil[:2] + b"\x33\x44" + nil[4:], b"\x07\x02\0\1\x5e" + nil[4:]):
                await self.send_frame(writer, wire)
                try:
                    await asyncio.wait_for(reader.read(1), 0.05)
                except asyncio.TimeoutError:
                    pass
            mark("nil_checked")
            nil_checked.set()
            if recover:
                await asyncio.wait_for(release_valid.wait(), 30)
                await self.send_frame(writer, nil[:10] + b"\xff" * 16 + b"\x20\0\x10\0")

                async def drain():
                    while await reader.read(4096):
                        pass
                await asyncio.wait_for(drain(), 30)
            else:
                await asyncio.wait_for(reader.read(1), 30)
                mark("peer_eof")
            outcome.set_result(None)
        except Exception as error:
            outcome.set_exception(error)
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 3)
            except Exception:
                pass

    listener = await asyncio.start_server(peer, "127.0.0.1", 0, ssl=context)
    mark("listening")
    node = self.node(api, f"wss://localhost:{listener.sockets[0].getsockname()[1]}", uuid, vmac)
    mark("constructed")
    started = asyncio.ensure_future(node.start() if api is BACnetServer else node.__aenter__())
    mark("start_called")
    status = "ok"
    try:
        await asyncio.wait_for(nil_checked.wait(), 30)
        if recover:
            release_valid.set()
            await asyncio.wait_for(started, 30)
            mark("started")
            await self.stop_server(node)
        else:
            try:
                await asyncio.wait_for(started, 30)
                status = "unexpected-start"
            except BacnetError:
                mark("start_failed")
        await asyncio.wait_for(outcome, 30)
    except Exception as error:
        status = f"error {type(error).__name__}: {error}"
    finally:
        if not started.done():
            started.cancel()
        await asyncio.gather(started, return_exceptions=True)
        await self.stop_server(node)
        mark("stopped")
        listener.close()
        await listener.wait_closed()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        monitor.cancel()
        faulthandler.cancel_dump_traceback_later()
        nil = marks.get("nil_checked", -1)
        log(f"RESULT api={api.__name__} recover={recover} status={status} "
            f"nil_checked={nil:.3f} over3={nil > 3 or nil < 0} "
            + " ".join(f"{k}={v:.3f}" for k, v in marks.items()))


class StampedResult(unittest.TextTestResult):
    def startTest(self, test):
        log(f"START {test.id()}")
        super().startTest(test)


def timed_setup_class(original):
    def setup(cls):
        log(f"setUpClass {cls.__name__} begin")
        try:
            original.__func__(cls)
        finally:
            log(f"setUpClass {cls.__name__} end")
    return classmethod(setup)


class Stamp(logging.Formatter):
    def format(self, record):
        return f"[{record.created - T0:9.3f}] {record.name} {record.getMessage()[-400:]}"


NIL = "test_native_nodes_nil_accept_expires_without_connecting"
VALID = "test_native_nodes_wait_silently_then_accept_valid_uuid"


def run_names(names):
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    return unittest.TextTestRunner(verbosity=1, resultclass=StampedResult).run(suite)


def repeat(n):
    """The real (current) tests, n times each in this process, no added load."""
    names = []
    for _ in range(n):
        names += [f"test_sc_accept_uuid.AcceptUuidTests.{NIL}", f"test_sc_accept_uuid.AcceptUuidTests.{VALID}"]
    result = run_names(names)
    bad = len(result.failures) + len(result.errors)
    log(f"REPEAT ran={result.testsRun} passed={result.testsRun - bad} failed={bad}")


def paired(hogs, rounds):
    """Dev's and this branch's nil test, alternately, while `hogs` processes spin."""
    procs = [subprocess.Popen([sys.executable, "-c", "while True: pass"]) for _ in range(hogs)]
    tally = {"old": [0, 0], "new": [0, 0]}
    try:
        for r in range(rounds):
            for label, module in (("old", "old983_sc_accept_uuid"), ("new", "test_sc_accept_uuid")):
                t = time.perf_counter()
                result = run_names([f"{module}.AcceptUuidTests.{NIL}"])
                ok = result.wasSuccessful()
                tally[label][0 if ok else 1] += 1
                log(f"PAIRED round={r} {label} {'PASS' if ok else 'FAIL'} {time.perf_counter() - t:.1f}s")
    finally:
        for proc in procs:
            proc.kill()
    log(f"PAIRED hogs={hogs} old pass={tally['old'][0]} fail={tally['old'][1]} "
        f"new pass={tally['new'][0]} fail={tally['new'][1]}")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "30"
    if mode.startswith("repeat:"):
        log(f"start mode={mode} python={sys.version.split()[0]} platform={sys.platform} cpus={os.cpu_count()}")
        return repeat(int(mode.split(":")[1]))
    if mode.startswith("paired:"):
        _, hogs, rounds = mode.split(":")
        log(f"start mode={mode} python={sys.version.split()[0]} platform={sys.platform} cpus={os.cpu_count()}")
        return paired(int(hogs), int(rounds))
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(Stamp())
    logging.basicConfig(level=logging.WARNING, handlers=[handler])
    faulthandler.enable()
    proc = subprocess.Popen([sys.executable, "-c", MONITOR, str(T0)])
    real = mode.startswith("realsuite")
    threading.Thread(target=gil_monitor, args=(real,), daemon=True).start()
    gc.callbacks.append(gc_timer)
    if not real:
        accept.AcceptUuidTests.check_accept = check_accept
    mtls.MtlsFixture.setUpClass = timed_setup_class(mtls.MtlsFixture.setUpClass)
    log(f"start mode={mode} python={sys.version.split()[0]} platform={sys.platform} cpus={os.cpu_count()}")
    try:
        if real:
            here = os.path.dirname(os.path.abspath(__file__))
            failures = 0
            for run in range(int(mode.split(":")[1])):
                log(f"SUITE RUN {run} begin")
                suite = unittest.defaultTestLoader.discover(here)
                result = unittest.TextTestRunner(verbosity=1, resultclass=StampedResult).run(suite)
                bad = [t.id() for t, _ in result.failures + result.errors]
                failures += bool(bad)
                log(f"SUITE RUN {run} end ran={result.testsRun} bad={bad}")
            log(f"SUITE RUNS failed={failures}")
        elif mode == "suite":
            here = os.path.dirname(os.path.abspath(__file__))
            suite = unittest.defaultTestLoader.discover(here)
            unittest.TextTestRunner(verbosity=1, resultclass=StampedResult).run(suite)
        else:
            names = []
            for _ in range(int(mode)):
                names += ["test_sc_accept_uuid.AcceptUuidTests.test_native_nodes_nil_accept_expires_without_connecting",
                          "test_sc_accept_uuid.AcceptUuidTests.test_native_nodes_wait_silently_then_accept_valid_uuid"]
            unittest.main(module=None, argv=["probe983", *names], exit=False, verbosity=1,
                          testRunner=unittest.TextTestRunner(verbosity=1, resultclass=StampedResult))
    finally:
        proc.kill()
    log("done")


if __name__ == "__main__":
    main()
