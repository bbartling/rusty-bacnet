"""Installed policy parity: native shared validation and independent real TLS peers."""
import asyncio
import hashlib
import ssl
import unittest

from rusty_bacnet import ScHub, ScHubCertificateBinding
import test_sc_hub_mtls as mtls
import test_sc_peer_uuid as peer
import test_sc_hub_conflict_admission as conflict


def group(uuid=1, vmacs=(1,), leaves=(b"x" * 32,)):
    return ScHubCertificateBinding(uuid=bytes([uuid]) * 16,
                                   allowed_vmacs=[bytes([v]) * 6 for v in vmacs],
                                   leaf_sha256=leaves)


def constructor(**kwargs):
    return ScHub("127.0.0.1:0", "missing-cert.pem", "missing-key.pem", mtls.HUB_VMAC,
                 ca_cert="missing-ca.pem", device_uuid=mtls.HUB_UUID, **kwargs)


class BindingValidationTests(unittest.TestCase):
    def test_group_shape_ownership_and_immutable_copies(self):
        valid = dict(uuid=b"a" * 16, allowed_vmacs=[b"b" * 6], leaf_sha256=[b"c" * 32])
        for key, values in {
            "uuid": (b"", b"a" * 15, bytes(16), b"a" * 17),
            "allowed_vmacs": ([], [b""], [bytes(6)], [b"\xff" * 6], [b"b" * 6] * 2),
            "leaf_sha256": ([], [b"c" * 31], [b"c" * 33], [b"c" * 32] * 2),
        }.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    ScHubCertificateBinding(**(valid | {key: value}))
        with self.assertRaises(TypeError):
            ScHubCertificateBinding(b"a" * 16, [b"b" * 6], [b"c" * 32])
        g = ScHubCertificateBinding(**valid)
        valid["allowed_vmacs"].clear()
        valid["leaf_sha256"].clear()
        self.assertEqual(g.uuid, b"a" * 16)
        self.assertEqual(g.allowed_vmacs, (b"b" * 6,))
        self.assertEqual(g.leaf_sha256, (b"c" * 32,))
        self.assertEqual(repr(g), "ScHubCertificateBinding(<redacted>)")
        for key in ("uuid", "allowed_vmacs", "leaf_sha256"):
            with self.assertRaises(AttributeError):
                setattr(g, key, None)

    def test_map_conflicts_fail_synchronously_before_pem_io(self):
        for groups in ([], [group(), group()],
                       [group(), group(2, (1,), (b"y" * 32,))],
                       [group(), group(2, (2,))],
                       [ScHubCertificateBinding(uuid=b"a" * 16,
                            allowed_vmacs=[mtls.HUB_VMAC], leaf_sha256=[b"x" * 32])]):
            with self.subTest(groups=groups), self.assertRaises(ValueError):
                constructor(certificate_bindings=groups)
        for groups in ([(b"a" * 16, [b"b" * 6], [b"c" * 32])], [{}]):
            with self.assertRaises(TypeError):
                constructor(certificate_bindings=groups)
        constructor(certificate_bindings=None)
        constructor(certificate_bindings=[group()])
        # No invented same-as-Hub UUID restriction.
        constructor(certificate_bindings=[ScHubCertificateBinding(uuid=mtls.HUB_UUID,
                    allowed_vmacs=[b"b" * 6], leaf_sha256=[b"c" * 32])])


class BindingRuntimeTests(mtls.MtlsFixture):
    open_peer = peer.PeerUuidTests.open_peer
    send = peer.PeerUuidTests.send
    binary = peer.PeerUuidTests.binary
    connect = conflict.HubConflictAdmissionTests.connect
    close_peer = conflict.HubConflictAdmissionTests.close_peer

    def digest(self, name):
        der = ssl.PEM_cert_to_DER_cert((self.root / f"{name}.pem").read_text())
        return hashlib.sha256(der).digest()

    def bound_hub(self, groups=None, policy="allow_all"):
        return ScHub("127.0.0.1:0", self.path("hub.pem"), self.path("hub.key"),
                     mtls.HUB_VMAC, ca_cert=self.path("site.pem"), device_uuid=mtls.HUB_UUID,
                     certificate_bindings=groups, admission_policy=policy)

    async def start_hub(self, hub):
        self.addAsyncCleanup(self.stop_hub, hub)
        await asyncio.wait_for(hub.start(), 3)
        return await hub.address()

    async def open(self, address, certificate):
        endpoint = await self.open_peer(address, certificate)
        self.addAsyncCleanup(self.close_peer, endpoint)
        return endpoint

    async def test_bound_online_offline_unmapped_claims_and_incumbent_relay(self):
        groups = [group(1, (1, 3), (self.digest("client"),)),
                  group(2, (2,), (self.digest("server"),))]
        hub = self.bound_hub(groups)
        groups.clear()  # Constructor has copied the entire policy.
        address = await self.start_hub(hub)
        nak = b"\0\0\x22\x33\x06\1\0\0\3\0\0"
        for cert, vmac, uuid in (("server", 1, 1), ("server", 1, 2),
                                  ("server", 2, 1), ("hub", 4, 4),
                                  ("client", 2, 1), ("client", 3, 9)):
            endpoint = await self.open(address, cert)
            self.assertEqual(await self.connect(endpoint, bytes([vmac])*6, bytes([uuid])*16), nak)
        source = await self.open(address, "client")
        target = await self.open(address, "server")
        for endpoint, value in ((source, 1), (target, 2)):
            self.assertEqual((await self.connect(endpoint, bytes([value])*6, bytes([value])*16))[:4], b"\x07\0\x22\x33")
        intruder = await self.open(address, "server")
        self.assertEqual(await self.connect(intruder, b"\3"*6, b"\1"*16), nak)
        await self.send(source[1], b"\1\4\x33\1" + b"\2"*6 + b"\1\0\x10\10")
        self.assertEqual(await self.binary(target[0]), b"\1\10\x33\1" + b"\1"*6 + b"\1\0\x10\10")
        status = await hub.status()
        self.assertEqual(status["client_count"], 2)
        self.assertEqual(status["admin_denied"], 7)
        self.assertEqual(status["outcomes"]["uuid_replacements"], 0)
        await self.stop_hub(hub)
        with self.assertRaises(RuntimeError):
            await hub.status()

    async def test_rotation_no_map_and_static_policy_conjunction(self):
        for bound, policy in ((True, "allow_all"), (True, "deny_all"),
                              (True, "deny_uuid_replacement"), (False, "allow_all")):
            with self.subTest(bound=bound, policy=policy):
                groups = [group(1, (1, 3), (self.digest("client"), self.digest("server")))] if bound else None
                hub = self.bound_hub(groups, policy)
                address = await self.start_hub(hub)
                for index, (cert, vmac) in enumerate((("client", 1), ("client", 1), ("server", 3))):
                    endpoint = await self.open(address, cert)
                    wire = await self.connect(endpoint, bytes([vmac])*6, b"\1"*16)
                    denied = policy == "deny_all" or (index > 0 and policy == "deny_uuid_replacement")
                    if denied:
                        self.assertEqual(wire, b"\0\0\x22\x33\6\1\0\0\3\0\0")
                    else:
                        self.assertEqual(wire[:4], b"\7\0\x22\x33")
                self.assertEqual((await hub.status())["client_count"], int(policy != "deny_all"))
                await self.stop_hub(hub)
