from __future__ import annotations

import re
from dataclasses import dataclass, field

from .score import SecurityScore
from .vulnerability import Vulnerability

_CPE_23_RE = re.compile(
    r"^cpe:2\.3:"
    r"([aho]):"  # part
    r"([^:]+):"  # vendor
    r"([^:]+):"  # product
    r"([^:]+):"  # version
    r"([^:]+):"  # update
    r"([^:]+):"  # edition
    r"([^:]+):"  # language
    r"([^:]+):"  # sw_edition
    r"([^:]+):"  # target_sw
    r"([^:]+):"  # target_hw
    r"([^:]+)$"  # other
)

PART_LABELS = {"a": "application", "o": "operating_system", "h": "hardware"}

# Common aliases: user-friendly name -> (part, vendor, product) in CPE dictionary
# part: a=application, o=operating system, h=hardware
PRODUCT_ALIASES: dict[str, tuple[str, str, str]] = {
    "rhel": ("o", "redhat", "enterprise_linux"),
    "red hat enterprise linux": ("o", "redhat", "enterprise_linux"),
    "red hat": ("o", "redhat", "enterprise_linux"),
    "centos": ("o", "centos", "centos"),
    "ubuntu": ("o", "canonical", "ubuntu_linux"),
    "debian": ("o", "debian", "debian_linux"),
    "fedora": ("o", "fedoraproject", "fedora"),
    "windows": ("o", "microsoft", "windows_10"),
    "windows 10": ("o", "microsoft", "windows_10"),
    "windows 11": ("o", "microsoft", "windows_11"),
    "windows server": ("o", "microsoft", "windows_server"),
    "macos": ("o", "apple", "macos"),
    "mac os": ("o", "apple", "macos"),
    "ios": ("o", "apple", "iphone_os"),
    "android": ("o", "google", "android"),
    "chrome": ("a", "google", "chrome"),
    "firefox": ("a", "mozilla", "firefox"),
    "nginx": ("a", "f5", "nginx"),
    "apache httpd": ("a", "apache", "http_server"),
    "apache http": ("a", "apache", "http_server"),
    "httpd": ("a", "apache", "http_server"),
    "tomcat": ("a", "apache", "tomcat"),
    "struts": ("a", "apache", "struts"),
    "log4j": ("a", "apache", "log4j"),
    "postgres": ("a", "postgresql", "postgresql"),
    "postgresql": ("a", "postgresql", "postgresql"),
    "mysql": ("a", "oracle", "mysql"),
    "node": ("a", "nodejs", "node.js"),
    "nodejs": ("a", "nodejs", "node.js"),
    "node.js": ("a", "nodejs", "node.js"),
    "java": ("a", "oracle", "jdk"),
    "jdk": ("a", "oracle", "jdk"),
    "linux kernel": ("o", "linux", "linux_kernel"),
    "kernel": ("o", "linux", "linux_kernel"),
    "openssl": ("a", "openssl", "openssl"),
    "openssh": ("a", "openbsd", "openssh"),
    "curl": ("a", "haxx", "curl"),
    "docker": ("a", "docker", "docker"),
    "kubernetes": ("a", "kubernetes", "kubernetes"),
    "k8s": ("a", "kubernetes", "kubernetes"),
}

# Friendly display names for vendors
VENDOR_DISPLAY: dict[str, str] = {
    "redhat": "Red Hat",
    "canonical": "Canonical",
    "debian": "Debian",
    "fedoraproject": "Fedora Project",
    "microsoft": "Microsoft",
    "apple": "Apple",
    "google": "Google",
    "mozilla": "Mozilla",
    "apache": "Apache",
    "openssl": "OpenSSL",
    "openbsd": "OpenBSD",
    "linux": "Linux",
    "oracle": "Oracle",
    "f5": "F5/NGINX",
    "postgresql": "PostgreSQL",
    "nodejs": "Node.js",
    "haxx": "Haxx",
    "docker": "Docker",
    "kubernetes": "Kubernetes",
}

# Friendly display names for products
PRODUCT_DISPLAY: dict[str, str] = {
    "enterprise_linux": "Enterprise Linux",
    "ubuntu_linux": "Ubuntu",
    "debian_linux": "Debian",
    "fedora": "Fedora",
    "windows_10": "Windows 10",
    "windows_11": "Windows 11",
    "windows_server": "Windows Server",
    "macos": "macOS",
    "iphone_os": "iOS",
    "android": "Android",
    "chrome": "Chrome",
    "firefox": "Firefox",
    "nginx": "NGINX",
    "http_server": "HTTP Server",
    "tomcat": "Tomcat",
    "struts": "Struts",
    "log4j": "Log4j",
    "postgresql": "PostgreSQL",
    "mysql": "MySQL",
    "node.js": "Node.js",
    "jdk": "JDK",
    "linux_kernel": "Linux Kernel",
    "openssl": "OpenSSL",
    "openssh": "OpenSSH",
    "curl": "curl",
    "docker": "Docker",
    "kubernetes": "Kubernetes",
}


@dataclass(frozen=True)
class CPE:
    """Common Platform Enumeration identifier (CPE 2.3 format)."""

    uri: str
    part: str
    vendor: str
    product: str
    version: str

    @classmethod
    def from_uri(cls, uri: str) -> CPE:
        m = _CPE_23_RE.match(uri)
        if not m:
            raise ValueError(f"Invalid CPE 2.3 URI: {uri}")
        return cls(
            uri=uri,
            part=m.group(1),
            vendor=m.group(2),
            product=m.group(3),
            version=m.group(4),
        )

    @classmethod
    def build(cls, part: str, vendor: str, product: str, version: str = "*") -> CPE:
        uri = f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        return cls(uri=uri, part=part, vendor=vendor, product=product, version=version)

    @property
    def part_label(self) -> str:
        return PART_LABELS.get(self.part, self.part)

    @property
    def vendor_display(self) -> str:
        return VENDOR_DISPLAY.get(self.vendor, self.vendor.replace("_", " ").title())

    @property
    def product_display(self) -> str:
        return PRODUCT_DISPLAY.get(self.product, self.product.replace("_", " ").title())

    @property
    def display_name(self) -> str:
        vendor = self.vendor_display
        product = self.product_display
        # Avoid redundancy: "Linux Linux Kernel" -> "Linux Kernel"
        v_lower = vendor.lower()
        p_lower = product.lower()
        if v_lower == p_lower or p_lower.startswith(v_lower + " ") or v_lower.startswith(p_lower):
            name = product
        else:
            name = f"{vendor} {product}"
        if self.version and self.version not in ("*", "-"):
            return f"{name} {self.version}"
        return name


@dataclass
class Product:
    """A software or hardware product identified by CPE."""

    name: str
    cpe: CPE
    vendor: str
    version: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    score: SecurityScore | None = None
