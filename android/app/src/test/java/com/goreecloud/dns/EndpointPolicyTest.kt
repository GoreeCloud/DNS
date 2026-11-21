package com.goreecloud.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class EndpointPolicyTest {
    @Test fun acceptsStrictHttpsOrigin() {
        assertEquals("https://dns.example.org", EndpointPolicy.validate(" https://dns.example.org/ "))
        assertEquals("https://dns.example.org:8443", EndpointPolicy.validate("https://dns.example.org:8443"))
        assertEquals("https://[::1]:8443", EndpointPolicy.validate("https://[::1]:8443"))
    }

    @Test fun refusesCredentialLeakAndDeceptiveOrigins() {
        val invalid = listOf(
            "http://127.0.0.1:8080",
            "https://trusted.example@evil.example",
            "https://user:pass@dns.example.org",
            "https://dns.example.org/path",
            "https://dns.example.org?query=secret",
            "https://dns.example.org#fragment",
            "https://dns.example.org:0",
            "https://dns.example.org:99999",
            "file:///tmp/resolver",
            "https://",
            "",
            "javascript:alert(1)"
        )
        invalid.forEach { value ->
            try {
                EndpointPolicy.validate(value)
                fail("Unexpected acceptance: $value")
            } catch (_: IllegalArgumentException) {
                // Invalid endpoint rejected as expected.
            } catch (_: java.net.URISyntaxException) {
                // Invalid URI syntax also fails before a network request.
            }
        }
    }
}
