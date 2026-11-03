"""Guard immutable release Docker inputs; does not certify the final image."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DockerReleaseInputContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    def test_runtime_base_image_is_digest_pinned(self):
        self.assertRegex(self.docker,
                         r"(?m)^FROM mcr\.microsoft\.com/dotnet/aspnet:10\.0@sha256:[0-9a-f]{64}$")
        self.assertNotRegex(self.docker, r"(?m)^FROM [^\n]*:latest(?:\s|$)")
        self.assertNotRegex(self.docker, r"(?m)^FROM mcr\.microsoft\.com/dotnet/aspnet:10\.0$")

    def test_microsoft_repository_bootstrap_requires_exact_checksum(self):
        self.assertRegex(
            self.docker,
            r"(?m)^ADD https://packages\.microsoft\.com/config/ubuntu/24\.04/"
            r"packages-microsoft-prod\.deb /$")
        self.assertIn("RUN set -eu;", self.docker)
        self.assertIn(
            "echo 'c13f01ac7c3001b51a9281d40dde666db5e037e05512840c319832f7852bfec4  packages-microsoft-prod.deb' | sha256sum --check --status;",
            self.docker)
        self.assertLess(self.docker.index("sha256sum --check --status"),
                        self.docker.index("dpkg -i packages-microsoft-prod.deb"))
        self.assertNotIn("RUN <<HEREDOC", self.docker)
        self.assertIn("c13f01ac7c3001b51a9281d40dde666db5e037e05512840c319832f7852bfec4", self.docker)
        self.assertIn("dpkg -i packages-microsoft-prod.deb", self.docker)
        self.assertNotIn("ADD --link", self.docker)
        self.assertNotIn("COPY --link", self.docker)
        self.assertNotIn("curl | bash", self.docker)
        self.assertNotIn("curl | sh", self.docker)

    def test_release_is_not_misrepresented_as_production_ready(self):
        self.assertIn("org.opencontainers.image.licenses", self.docker)
        self.assertIn("GPL-3.0-or-later", self.docker)
        self.assertIn("no production release certification", self.docker)
        docs = (ROOT / "docs/GOREECLOUD_DNS.md").read_text(encoding="utf-8")
        self.assertIn("Package versions remain unpinned", docs)
        self.assertIn("not a production-ready image", docs)


if __name__ == "__main__":
    unittest.main()
