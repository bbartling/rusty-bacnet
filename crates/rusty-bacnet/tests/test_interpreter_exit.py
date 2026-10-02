"""Interpreter exit while a binding thread completes a future (#1002).

A Tokio thread completes an asyncio future through call_soon_threadsafe,
which queues the callback and then releases the GIL to wake the loop. The
main thread could run the callback and start finalizing in that window, and
CPython 3.12/3.13 end a thread that takes the GIL back during finalization:
a segfault at exit. The bindings now close an exit gate from atexit and wait
for attached binding threads before finalization begins.

Each case runs in a fresh interpreter, because the exit is what is tested.
Holding the completing thread in that window makes the race deterministic.
"""

import subprocess
import sys
import unittest

OWNERS = {
    "server": ('rb.BACnetServer(4001, interface="127.0.0.1", port=0)', "start"),
    "client": ('rb.BACnetClient(interface="127.0.0.1", port=0)', "__aenter__"),
}

# Holds the completing thread inside call_soon_threadsafe, GIL released, after
# it queued stop()'s result: the main thread finishes the program meanwhile.
HELD_COMPLETION = """
import asyncio
import threading
import time

import rusty_bacnet as rb

MAIN = threading.get_ident()


class HeldWakeLoop(asyncio.SelectorEventLoop):
    hold = False

    def call_soon_threadsafe(self, callback, *args, context=None):
        handle = super().call_soon_threadsafe(callback, *args, context=context)
        if self.hold and threading.get_ident() != MAIN:
            time.sleep(0.5)
            print("completion returned", flush=True)
        return handle


async def call(method):
    return await method()


loop = HeldWakeLoop()
owner = {owner}
loop.run_until_complete(call(owner.{enter}))
loop.hold = True
loop.run_until_complete(call(owner.stop))
"""

# Registered before the import, so it runs after the bindings' exit hook.
AFTER_EXIT_HOOK = """
import asyncio
import atexit


def late():
    import rusty_bacnet as rb

    server = rb.BACnetServer(4002, interface="127.0.0.1", port=0)

    async def stop():
        await server.stop()

    try:
        asyncio.run(stop())
    except RuntimeError as error:
        print("refused:", error, flush=True)


atexit.register(late)
import rusty_bacnet
"""


def python(source):
    return subprocess.run([sys.executable, "-c", source], capture_output=True,
                          text=True, timeout=60)


class InterpreterExitTests(unittest.TestCase):
    def test_exit_waits_for_a_completion_still_on_a_binding_thread(self):
        for name, (owner, enter) in OWNERS.items():
            with self.subTest(owner=name):
                result = python(HELD_COMPLETION.format(owner=owner, enter=enter))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("completion returned", result.stdout, result.stderr)

    def test_futures_created_after_the_exit_hook_raise_instead_of_hanging(self):
        result = python(AFTER_EXIT_HOOK)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("refused: the Python interpreter is exiting", result.stdout, result.stderr)


if __name__ == "__main__":
    unittest.main()
