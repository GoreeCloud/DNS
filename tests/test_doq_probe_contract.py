"""Static acceptance guards for the optional isolated DoQ source probe.

These tests prove only first-party source/CI constraints. The .NET CLI self-
test verifies parser behavior. Neither is proof of a live QUIC handshake.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DoqSourceContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "tests/DoQProbe/Program.cs").read_text()
        cls.project = (ROOT / "tests/DoQProbe/DoQProbe.csproj").read_text()
        cls.ci = (ROOT / ".github/workflows/goreecloud-static-checks.yml").read_text()

    def test_exact_local_quic_transport_and_tls_trust_boundary(self):
        for fragment in (
            'private const int DoqPort = 1854;',
            'SslApplicationProtocol DoqAlpn = new("doq")',
            'IPAddress.Loopback',
            'TargetHost = "localhost"',
            'SslProtocols.Tls13',
            'SslPolicyErrors.RemoteCertificateChainErrors',
            'X509ChainTrustMode.CustomRootTrust',
            'CheckCertificate',
            'GC_DNS_DOQ_ISOLATED_TEST',
            'NetworkInterfaceType.Loopback',
        ):
            self.assertIn(fragment, self.source)
        for forbidden in ('DangerousAcceptAnyServerCertificateValidator',
                          'ServerCertificateValidationCallback = (_, _, _, _) => true',
                          'IPAddress.Any', 'https://'):
            self.assertNotIn(forbidden, self.source)

    def test_wire_protocol_boundaries_include_fin_and_two_streams(self):
        for fragment in (
            'QuicStreamType.Bidirectional',
            'completeWrites: true',
            'BinaryPrimitives.WriteUInt16BigEndian',
            'BinaryPrimitives.ReadUInt16BigEndian',
            'for (int repeat = 0; repeat < 2; repeat++)',
            'VerifyAnswer(query, response)',
            'if (await stream.ReadAsync(extra, deadline.Token) != 0)',
            'TimeSpan.FromSeconds(8)',
            'ushort id =',
        ):
            self.assertIn(fragment, self.source)

    def test_exact_framed_dns_rejects_overlong_truncated_and_mismatch(self):
        for fragment in (
            "private static int DecodeFrameLength(",
            "private static void VerifyExactFramedAnswer(",
            "VerifyExactFramedAnswer(query, framed);",
            "VerifyBadFrameRefused(query, []);",
            "VerifyBadFrameRefused(query, [0]);",
            "VerifyBadFrameRefused(query, [0, 0]);",
            "VerifyBadFrameRefused(query, [0x10, 0x01]);",
            "VerifyBadFrameRefused(query, framed[..^1]);",
            "VerifyBadFrameRefused(query, [.. framed, 0]);",
            "VerifyBadFrameRefused(query, shortDeclared);",
            "VerifyBadFrameRefused(query, longDeclared);",
            "VerifyBadFrameRefused(query, changedBody);",
            "int size = DecodeFrameLength(length);",
        ):
            self.assertIn(fragment, self.source)

    def test_selftest_compiled_in_pinned_sdk_without_real_quic_listener(self):
        self.assertIn('<TargetFramework>net10.0</TargetFramework>', self.project)
        self.assertIn('dotnet build tests/DoQProbe/DoQProbe.csproj', self.ci)
        self.assertIn('dotnet run --no-build --project tests/DoQProbe/DoQProbe.csproj', self.ci)
        self.assertIn('-- --self-test', self.ci)
        self.assertNotIn('--loopback', self.ci)
        self.assertNotIn('--network=host', self.ci)


if __name__ == "__main__":
    unittest.main()
