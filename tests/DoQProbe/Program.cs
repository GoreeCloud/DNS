// Development-only RFC 9250 DNS-over-QUIC source probe.
// Self-test is entirely offline. --loopback is explicitly gated to an isolated
// network-none container and connects ONLY to 127.0.0.1:1854.
// No production DNS configuration, credentials, host networking or private keys.
using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Quic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

internal static class Program
{
    private const int DoqPort = 1854;
    private static readonly SslApplicationProtocol DoqAlpn = new("doq");
    private static readonly byte[] ExpectedIp = [192, 0, 2, 42];

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 1 && args[0] == "--self-test")
            {
                SelfTest();
                Console.WriteLine("PASS: offline DoQ framing and authoritative answer parser");
                return 0;
            }
            if (args.Length == 1 && args[0] == "--loopback")
            {
                LoopbackAsync().GetAwaiter().GetResult();
                Console.WriteLine("PASS: isolated DoQ TLS/ALPN, two framed DNS streams, and authoritative A answers");
                return 0;
            }
        }
        catch (Exception)
        {
            // Intentionally no exception, certificate, IP or token details.
            Console.Error.WriteLine("FAIL: bounded DoQ acceptance was not established");
            return 1;
        }
        Console.Error.WriteLine("FAIL: only --self-test or --loopback is supported");
        return 2;
    }

    private static byte[] Query()
    {
        var bytes = new List<byte>(80)
        {
            0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0
        };
        foreach (var label in new[] { "host", "smoke", "invalid" })
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(Encoding.ASCII.GetBytes(label));
        }
        bytes.AddRange([0, 0, 1, 0, 1]);
        return bytes.ToArray();
    }

    private static byte[] SyntheticResponse(byte[] query)
    {
        var answer = new List<byte>(query.Length + 16)
        {
            0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0
        };
        answer.AddRange(query.AsSpan(12).ToArray());
        answer.AddRange([0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        answer.AddRange(ExpectedIp);
        return answer.ToArray();
    }

    private static int SkipUncompressedName(ReadOnlySpan<byte> wire, int at)
    {
        for (int labels = 0; labels < 128; labels++)
        {
            if (at >= wire.Length) throw new InvalidDataException();
            int size = wire[at++];
            if (size == 0) return at;
            if (size > 63 || at + size > wire.Length) throw new InvalidDataException();
            at += size;
        }
        throw new InvalidDataException();
    }

    private static void VerifyAnswer(byte[] query, byte[] response)
    {
        if (query.Length < 17 || query.Length > 4096 ||
            response.Length < 12 || response.Length > 4096)
            throw new InvalidDataException();
        var q = query.AsSpan();
        var r = response.AsSpan();
        ushort id = BinaryPrimitives.ReadUInt16BigEndian(r);
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(r[2..]);
        ushort questions = BinaryPrimitives.ReadUInt16BigEndian(r[4..]);
        ushort answers = BinaryPrimitives.ReadUInt16BigEndian(r[6..]);
        if (id != 0 || (flags & 0x8400) != 0x8400 ||
            (flags & 0x7A0F) != 0 || questions != 1 || answers < 1)
            throw new InvalidDataException();
        int at = SkipUncompressedName(r, 12);
        if (at + 4 > r.Length || !r.Slice(12, at + 4 - 12)
                .SequenceEqual(q[12..]))
            throw new InvalidDataException();
        at += 4;
        bool matched = false;
        for (int n = 0; n < answers; n++)
        {
            int ownerAt = at;
            if (at + 2 <= r.Length && r[at] == 0xC0 && r[at + 1] == 12)
                at += 2;
            else
            {
                at = SkipUncompressedName(r, at);
                int qNameEnd = SkipUncompressedName(q, 12);
                if (!r.Slice(ownerAt, at - ownerAt)
                      .SequenceEqual(q.Slice(12, qNameEnd - 12)))
                    throw new InvalidDataException();
            }
            if (at + 10 > r.Length) throw new InvalidDataException();
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(r[at..]);
            ushort klass = BinaryPrimitives.ReadUInt16BigEndian(r[(at + 2)..]);
            uint ttl = BinaryPrimitives.ReadUInt32BigEndian(r[(at + 4)..]);
            ushort size = BinaryPrimitives.ReadUInt16BigEndian(r[(at + 8)..]);
            at += 10;
            if (at + size > r.Length) throw new InvalidDataException();
            if (type == 1 && klass == 1 && ttl > 0 && ttl <= 120 && size == 4 &&
                r.Slice(at, 4).SequenceEqual(ExpectedIp))
                matched = true;
            at += size;
        }
        if (!matched || at != r.Length) throw new InvalidDataException();
    }

    private static void SelfTest()
    {
        byte[] query = Query();
        byte[] correct = SyntheticResponse(query);
        VerifyAnswer(query, correct);
        foreach (var offset in new[] { 1, 3, 4, 5, correct.Length - 1 })
        {
            var changed = (byte[])correct.Clone();
            changed[offset] ^= 1;
            bool denied = false;
            try { VerifyAnswer(query, changed); }
            catch (InvalidDataException) { denied = true; }
            if (!denied) throw new InvalidDataException();
        }
        // A changed response RD bit is allowed by DNS; a changed opcode is
        // not. Test the actual forbidden bit rather than assuming all flags
        // must equal one fixed response header.
        var opcode = (byte[])correct.Clone();
        opcode[2] ^= 0x08;
        bool invalidOpcode = false;
        try { VerifyAnswer(query, opcode); }
        catch (InvalidDataException) { invalidOpcode = true; }
        if (!invalidOpcode) throw new InvalidDataException();
        bool truncated = false;
        try { VerifyAnswer(query, correct[..^1]); }
        catch (InvalidDataException) { truncated = true; }
        if (!truncated) throw new InvalidDataException();
    }

    private static async Task ReadExactlyAsync(
        QuicStream stream, Memory<byte> buffer, CancellationToken cancellation)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        while (buffer.Length > 0)
        {
            int got = await stream.ReadAsync(buffer, cancellation);
            if (got <= 0) throw new InvalidDataException();
            buffer = buffer[got..];
        }
    }

    private static async Task LoopbackAsync()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        if (Environment.GetEnvironmentVariable("GC_DNS_DOQ_ISOLATED_TEST") != "1" ||
            (!File.Exists("/.dockerenv") && !File.Exists("/run/.containerenv")))
            throw new InvalidOperationException();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            if (nic.OperationalStatus == OperationalStatus.Up &&
                nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                throw new InvalidOperationException();
        if (!QuicConnection.IsSupported) throw new InvalidOperationException();

        // The ephemeral self-signed localhost certificate is trusted ONLY in
        // this disposable probe, not in a global trust store. Hostname mismatch
        // and all TLS errors other than the custom-root chain remain fatal.
        using var ephemeralRoot = X509Certificate2.CreateFromPemFile("/work/doh-cert.pem");
        bool CheckCertificate(object _, X509Certificate? certificate,
                              X509Chain? __, SslPolicyErrors errors)
        {
            if (certificate is null ||
                (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != 0)
                return false;
            using var leaf = new X509Certificate2(certificate);
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(ephemeralRoot);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            return chain.Build(leaf);
        }
        byte[] query = File.ReadAllBytes("/work/doh-query.bin");
        if (!query.AsSpan().SequenceEqual(Query())) throw new InvalidDataException();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var options = new QuicClientConnectionOptions
        {
            RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, DoqPort),
            DefaultCloseErrorCode = 0,
            DefaultStreamErrorCode = 0,
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                ApplicationProtocols = [DoqAlpn],
                EnabledSslProtocols = SslProtocols.Tls13,
                RemoteCertificateValidationCallback = CheckCertificate,
            },
        };
        await using var connection = await QuicConnection.ConnectAsync(options, deadline.Token);
        if (!connection.NegotiatedApplicationProtocol.Equals(DoqAlpn) ||
            connection.SslProtocol != SslProtocols.Tls13)
            throw new InvalidDataException();

        // RFC 9250: one client-initiated bidirectional stream per query, ID=0,
        // a 2-byte length prefix, explicit FIN, and same-stream response.
        for (int repeat = 0; repeat < 2; repeat++)
        {
            await using var stream = await connection.OpenOutboundStreamAsync(
                QuicStreamType.Bidirectional, deadline.Token);
            byte[] framed = new byte[query.Length + 2];
            BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
            query.CopyTo(framed.AsSpan(2));
            await stream.WriteAsync(framed, completeWrites: true, deadline.Token);
            byte[] length = new byte[2];
            await ReadExactlyAsync(stream, length, deadline.Token);
            int size = BinaryPrimitives.ReadUInt16BigEndian(length);
            if (size < 12 || size > 4096) throw new InvalidDataException();
            byte[] response = new byte[size];
            await ReadExactlyAsync(stream, response, deadline.Token);
            VerifyAnswer(query, response);
            byte[] extra = new byte[1];
            if (await stream.ReadAsync(extra, deadline.Token) != 0)
                throw new InvalidDataException();
        }
        await connection.CloseAsync(0, deadline.Token);
    }
}
