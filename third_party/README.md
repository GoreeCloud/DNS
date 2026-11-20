# Third-party components and source licensing

| Project | Source | Upstream license | Current use |
| --- | --- | --- | --- |
| miekg/dns | https://github.com/miekg/dns | BSD-3-Clause | Linked Go module dependency for DNS message handling |
| Unbound | https://github.com/NLnetLabs/unbound | BSD-3-Clause | Independently installed recursive resolver in development container |
| Technitium DNS | https://github.com/TechnitiumSoftware/DnsServer | GPL-3.0 | Planned separate compatibility adapter; not bundled |
| AdGuard Home | https://github.com/AdguardTeam/AdGuardHome | GPL-3.0 | Planned separate filtering interoperability; not bundled |
| Pi-hole FTL | https://github.com/pi-hole/FTL | EUPL-1.2 | Planned separate interoperability adapter; not bundled |

The first-party MIT license does not relicense upstream components. These projects retain their own copyrights, notices, obligations and trademarks. No full upstream code trees have been copied into this repository. Reevaluate exact revisions, transitive dependencies, vulnerabilities, provenance and redistribution rights before importing or repackaging external source.

React, AndroidX, Qt, base container images and operating system packages also retain their respective license terms. This attribution list is not a legal or security certification.
