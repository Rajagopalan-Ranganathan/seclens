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
    # Mobile devices — CVEs tracked under their OS, not hardware
    "iphone": ("o", "apple", "iphone_os"),
    "ipad": ("o", "apple", "ipados"),
    "ipados": ("o", "apple", "ipados"),
    "apple watch": ("o", "apple", "watchos"),
    "watchos": ("o", "apple", "watchos"),
    "apple tv": ("o", "apple", "tvos"),
    "tvos": ("o", "apple", "tvos"),
    "visionos": ("o", "apple", "visionos"),
    "pixel": ("o", "google", "android"),
    "samsung galaxy": ("o", "google", "android"),
    "galaxy": ("o", "google", "android"),
    "chromeos": ("o", "google", "chrome_os"),
    "chrome os": ("o", "google", "chrome_os"),
    # Networking hardware — Cisco
    "cisco asa": ("h", "cisco", "adaptive_security_appliance"),
    "cisco firepower": ("h", "cisco", "firepower"),
    "cisco catalyst": ("h", "cisco", "catalyst"),
    "cisco nexus": ("h", "cisco", "nexus"),
    "cisco meraki": ("h", "cisco", "meraki"),
    "cisco ios": ("o", "cisco", "ios"),
    "cisco ios-xe": ("o", "cisco", "ios_xe"),
    "cisco ios xe": ("o", "cisco", "ios_xe"),
    "cisco nx-os": ("o", "cisco", "nx-os"),
    # Processors — Intel
    "intel core": ("h", "intel", "core"),
    "intel xeon": ("h", "intel", "xeon"),
    "intel atom": ("h", "intel", "atom"),
    "intel celeron": ("h", "intel", "celeron"),
    "intel pentium": ("h", "intel", "pentium"),
    # Processors — AMD
    "amd ryzen": ("h", "amd", "ryzen"),
    "amd epyc": ("h", "amd", "epyc"),
    "amd athlon": ("h", "amd", "athlon"),
    # Processors — Qualcomm
    "qualcomm snapdragon": ("h", "qualcomm", "snapdragon"),
    "snapdragon": ("h", "qualcomm", "snapdragon"),
    # Processors — Samsung
    "samsung exynos": ("h", "samsung", "exynos"),
    "exynos": ("h", "samsung", "exynos"),
    # Processors — Apple
    "apple m1": ("h", "apple", "m1"),
    "apple m2": ("h", "apple", "m2"),
    "apple m3": ("h", "apple", "m3"),
    "apple m4": ("h", "apple", "m4"),
    # Networking — Fortinet
    "fortigate": ("o", "fortinet", "fortios"),
    "fortios": ("o", "fortinet", "fortios"),
    "fortinet": ("o", "fortinet", "fortios"),
    # Networking — Palo Alto
    "palo alto": ("o", "paloaltonetworks", "pan-os"),
    "pan-os": ("o", "paloaltonetworks", "pan-os"),
    # Networking — Juniper
    "junos": ("o", "juniper", "junos"),
    "juniper": ("o", "juniper", "junos"),
    # Storage / NAS
    "synology": ("o", "synology", "diskstation_manager"),
    "qnap": ("o", "qnap", "qts"),
    # Printers
    "hp laserjet": ("h", "hp", "laserjet"),
    "hp printer": ("h", "hp", "laserjet"),
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
    "cisco": "Cisco",
    "intel": "Intel",
    "amd": "AMD",
    "qualcomm": "Qualcomm",
    "samsung": "Samsung",
    "fortinet": "Fortinet",
    "paloaltonetworks": "Palo Alto Networks",
    "juniper": "Juniper",
    "synology": "Synology",
    "qnap": "QNAP",
    "hp": "HP",
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
    "ipados": "iPadOS",
    "watchos": "watchOS",
    "tvos": "tvOS",
    "visionos": "visionOS",
    "chrome_os": "Chrome OS",
    "adaptive_security_appliance": "ASA",
    "firepower": "Firepower",
    "catalyst": "Catalyst",
    "nexus": "Nexus",
    "meraki": "Meraki",
    "ios_xe": "IOS XE",
    "nx-os": "NX-OS",
    "core": "Core",
    "xeon": "Xeon",
    "atom": "Atom",
    "celeron": "Celeron",
    "pentium": "Pentium",
    "ryzen": "Ryzen",
    "epyc": "EPYC",
    "athlon": "Athlon",
    "snapdragon": "Snapdragon",
    "exynos": "Exynos",
    "m1": "M1",
    "m2": "M2",
    "m3": "M3",
    "m4": "M4",
    "fortios": "FortiOS",
    "pan-os": "PAN-OS",
    "junos": "Junos",
    "diskstation_manager": "DiskStation Manager",
    "qts": "QTS",
    "laserjet": "LaserJet",
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
