from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class GoreeCloudFrontend(unittest.TestCase):
    def source(self, name):
        return (ROOT/name).read_text(encoding="utf-8")

    def test_admin_brand_and_credit(self):
        page=self.source("DnsServerCore/www/index.html")
        script=self.source("DnsServerCore/www/js/main.js")
        self.assertIn("<title>GoreeCloud DNS</title>",page)
        self.assertIn('class="gc-skip-link"',page)
        self.assertIn("GoreeCloud DNS home",script)
        self.assertIn("github.com/GoreeCloud/DNS",page)
        self.assertIn("github.com/TechnitiumSoftware/DnsServer",page)
        self.assertIn("Copyright (C) 2026  Shreyas Zare",page)

    def test_encrypted_dns_copy(self):
        page=self.source("DnsServerCore/dohwww/index.html")
        script=self.source("DnsServerCore/dohwww/js/main.js")
        self.assertIn('id="btnCopyDoH"',page)
        self.assertIn('role="status" aria-live="polite"',page)
        self.assertIn("window.isSecureContext",script)
        self.assertIn("navigator.clipboard.writeText(link)",script)
        self.assertIn("Select and copy the URL above",script)

    def test_new_stylesheets_are_packaged(self):
        from xml.etree import ElementTree
        root=ElementTree.parse(ROOT/"DnsServerCore/DnsServerCore.csproj").getroot()
        content={e.attrib["Include"] for e in root.iter("Content") if "Include" in e.attrib}
        self.assertIn(r"www\css\goreecloud.css",content)
        self.assertIn(r"dohwww\css\goreecloud.css",content)

    def test_autofill_and_product_metadata(self):
        from xml.etree import ElementTree
        page=self.source("DnsServerCore/www/index.html")
        for item in ['autocomplete="username"','autocomplete="current-password"','autocomplete="one-time-code"']:
            self.assertIn(item,page)
        root=ElementTree.parse(ROOT/"DnsServerApp/DnsServerApp.csproj").getroot()
        product=root.findtext(".//Product")
        self.assertIn("GoreeCloud DNS",product)
        self.assertIn("Technitium DNS Server",product)

    def test_cli_and_image_provenance(self):
        cli=self.source("DnsServerApp/Program.cs")
        docker=self.source("Dockerfile")
        self.assertIn("GoreeCloud DNS (based on Technitium DNS Server)", cli)
        self.assertIn('org.opencontainers.image.title="GoreeCloud DNS"', docker)
        self.assertIn('org.opencontainers.image.vendor="GoreeCloud"', docker)
        self.assertIn('org.opencontainers.image.licenses="GPL-3.0-or-later"', docker)
        self.assertIn("https://github.com/GoreeCloud/DNS",docker)

    def test_ci_pins_upstream_dependency(self):
        workflow=self.source(".github/workflows/goreecloud-static-checks.yml")
        self.assertIn("4a5a530ac6c4114e72216e0b9c74208a7a5e3fa0",workflow)
        self.assertIn("mcr.microsoft.com/dotnet/sdk@sha256:",workflow)
        self.assertIn("dotnet build DnsServerApp/DnsServerApp.csproj",workflow)

    def test_license_preserved(self):
        self.assertIn("GNU GENERAL PUBLIC LICENSE",self.source("LICENSE"))
        self.assertIn("Copyright (C) 2026  Shreyas Zare",self.source("DnsServerCore/www/js/main.js"))

if __name__=="__main__":
    unittest.main()
