"""Enrichment data: MAC OUI -> vendor, SaaS catalog, port -> service, cloud CIDR.

OUI database is loaded lazily from a small embedded subset (covers ~80% of
common vendors). For full coverage, drop the IEEE OUI CSV at data/oui.csv
and it will be loaded automatically.
"""

import csv
import ipaddress
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OUI -> Vendor (subset — covers most consumer/enterprise gear)
# ---------------------------------------------------------------------------
# Full IEEE OUI list: http://standards-oui.ieee.org/oui/oui.csv (~5MB)
# Drop it at infra/data/oui.csv to extend.
OUI_BUILTIN: dict[str, str] = {
    # Apple
    "00:03:93": "Apple", "00:0a:27": "Apple", "00:0a:95": "Apple",
    "00:0d:93": "Apple", "00:10:fa": "Apple", "00:11:24": "Apple",
    "00:14:51": "Apple", "00:16:cb": "Apple", "00:17:f2": "Apple",
    "00:19:e3": "Apple", "00:1b:63": "Apple", "00:1c:b3": "Apple",
    "00:1d:4f": "Apple", "00:1e:52": "Apple", "00:1e:c2": "Apple",
    "00:1f:5b": "Apple", "00:1f:f3": "Apple", "00:21:e9": "Apple",
    "00:22:41": "Apple", "00:23:12": "Apple", "00:23:32": "Apple",
    "00:23:6c": "Apple", "00:23:df": "Apple", "00:24:36": "Apple",
    "00:25:00": "Apple", "00:25:4b": "Apple", "00:25:bc": "Apple",
    "00:26:08": "Apple", "00:26:4a": "Apple", "00:26:b0": "Apple",
    "00:26:bb": "Apple", "00:30:65": "Apple", "00:50:e4": "Apple",
    "00:88:65": "Apple", "00:a0:40": "Apple", "00:c6:10": "Apple",
    "00:cd:fe": "Apple", "00:db:70": "Apple", "00:f4:b9": "Apple",
    "00:f7:6f": "Apple", "04:0c:ce": "Apple", "04:1e:64": "Apple",
    "04:48:9a": "Apple", "04:4b:ed": "Apple", "04:54:53": "Apple",
    "04:db:56": "Apple", "04:e5:36": "Apple", "04:f1:3e": "Apple",
    "04:f7:e4": "Apple",
    # Microsoft / Surface
    "00:03:ff": "Microsoft", "00:0d:3a": "Microsoft", "00:12:5a": "Microsoft",
    "00:15:5d": "Microsoft (Hyper-V)", "00:17:fa": "Microsoft",
    "00:1d:d8": "Microsoft", "00:22:48": "Microsoft", "00:25:ae": "Microsoft",
    "28:18:78": "Microsoft", "60:45:bd": "Microsoft", "7c:1e:52": "Microsoft",
    "7c:ed:8d": "Microsoft", "98:5f:d3": "Microsoft", "c4:9d:ed": "Microsoft",
    # Cisco
    "00:00:0c": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco",
    "00:01:63": "Cisco", "00:01:64": "Cisco", "00:01:96": "Cisco",
    "00:01:97": "Cisco", "00:01:c7": "Cisco", "00:01:c9": "Cisco",
    "00:02:16": "Cisco", "00:02:17": "Cisco", "00:02:4a": "Cisco",
    "00:02:4b": "Cisco", "00:02:7d": "Cisco", "00:02:7e": "Cisco",
    "00:02:b9": "Cisco", "00:02:ba": "Cisco", "00:02:fc": "Cisco",
    "00:02:fd": "Cisco", "00:03:31": "Cisco", "00:03:32": "Cisco",
    "00:03:6b": "Cisco", "00:03:6c": "Cisco", "00:03:9f": "Cisco",
    "00:03:a0": "Cisco", "00:03:e3": "Cisco", "00:03:e4": "Cisco",
    "00:03:fd": "Cisco", "00:03:fe": "Cisco", "00:04:27": "Cisco",
    "00:04:28": "Cisco",
    # HP / HPE / Aruba
    "00:01:e6": "HP", "00:01:e7": "HP", "00:02:a5": "HP", "00:04:ea": "HP",
    "00:08:02": "HP", "00:08:83": "HP", "00:0a:57": "HP", "00:0b:cd": "HP",
    "00:0d:88": "HP", "00:0e:7f": "HP", "00:0e:b3": "HP", "00:0f:20": "HP",
    "00:10:83": "HP", "00:11:0a": "HP", "00:11:85": "HP", "00:12:79": "HP",
    "00:13:21": "HP", "00:14:38": "HP", "00:14:c2": "HP", "00:15:60": "HP",
    "00:16:35": "HP", "00:16:b9": "HP", "00:17:08": "HP", "00:17:a4": "HP",
    "00:18:fe": "HP", "00:19:bb": "HP", "00:1a:4b": "HP", "00:1b:78": "HP",
    "00:1c:c4": "HP", "00:1e:0b": "HP", "00:1f:29": "HP", "00:21:5a": "HP",
    "00:22:64": "HP", "00:23:7d": "HP", "00:24:81": "HP", "00:25:b3": "HP",
    "00:26:55": "HP", "00:0b:86": "Aruba", "94:b4:0f": "Aruba",
    # Dell
    "00:06:5b": "Dell", "00:08:74": "Dell", "00:0b:db": "Dell",
    "00:0d:56": "Dell", "00:0f:1f": "Dell", "00:11:43": "Dell",
    "00:12:3f": "Dell", "00:13:72": "Dell", "00:14:22": "Dell",
    "00:15:c5": "Dell", "00:16:f0": "Dell", "00:18:8b": "Dell",
    "00:19:b9": "Dell", "00:1a:a0": "Dell", "00:1c:23": "Dell",
    "00:1d:09": "Dell", "00:1e:4f": "Dell", "00:1e:c9": "Dell",
    "00:21:70": "Dell", "00:21:9b": "Dell", "00:22:19": "Dell",
    "00:23:ae": "Dell", "00:24:e8": "Dell", "00:25:64": "Dell",
    "00:26:b9": "Dell", "84:2b:2b": "Dell", "b8:ca:3a": "Dell",
    "f0:1f:af": "Dell", "f4:8e:38": "Dell",
    # Samsung
    "00:00:f0": "Samsung", "00:07:ab": "Samsung", "00:0d:e5": "Samsung",
    "00:12:fb": "Samsung", "00:15:99": "Samsung", "00:16:32": "Samsung",
    "00:16:6b": "Samsung", "00:16:6c": "Samsung", "00:17:c9": "Samsung",
    "00:17:d5": "Samsung", "00:18:af": "Samsung", "00:1a:8a": "Samsung",
    "00:1b:98": "Samsung", "00:1c:43": "Samsung",
    # Huawei
    "00:18:82": "Huawei", "00:1e:10": "Huawei", "00:25:68": "Huawei",
    "00:25:9e": "Huawei", "00:34:fe": "Huawei", "00:46:4b": "Huawei",
    "00:5a:13": "Huawei", "00:9a:cd": "Huawei",
    # Ubiquiti / Mikrotik / TP-Link
    "00:15:6d": "Ubiquiti", "04:18:d6": "Ubiquiti", "24:5a:4c": "Ubiquiti",
    "44:d9:e7": "Ubiquiti", "68:72:51": "Ubiquiti", "78:8a:20": "Ubiquiti",
    "80:2a:a8": "Ubiquiti", "dc:9f:db": "Ubiquiti",
    "00:0c:42": "MikroTik", "4c:5e:0c": "MikroTik", "6c:3b:6b": "MikroTik",
    "b8:69:f4": "MikroTik", "c4:ad:34": "MikroTik", "cc:2d:e0": "MikroTik",
    "00:14:78": "TP-Link", "00:23:cd": "TP-Link", "00:25:86": "TP-Link",
    "00:27:19": "TP-Link", "10:fe:ed": "TP-Link", "14:cc:20": "TP-Link",
    # Raspberry Pi Foundation
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "28:cd:c1": "Raspberry Pi",
    "d8:3a:dd": "Raspberry Pi", "2c:cf:67": "Raspberry Pi",
    # Printers
    "00:01:e6": "HP Printer", "00:00:74": "Ricoh", "00:00:85": "Canon",
    "00:00:aa": "Xerox", "00:00:e2": "Brother", "00:80:77": "Brother",
    "00:80:92": "Lexmark", "00:c0:eb": "Epson",
    # Network gear
    "00:90:7f": "WatchGuard", "00:1b:17": "Palo Alto Networks",
    "00:1b:11": "D-Link", "00:1c:f0": "D-Link",
    "00:09:5b": "Netgear", "00:14:6c": "Netgear", "00:1b:2f": "Netgear",
    # Virtualization
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:1c:14": "VMware",
    "00:05:69": "VMware", "00:1c:42": "Parallels",
    "08:00:27": "VirtualBox", "0a:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    # Smart home / IoT
    "ec:fa:bc": "Amazon", "44:65:0d": "Amazon", "f0:27:2d": "Amazon",
    "fc:65:de": "Amazon", "84:d6:d0": "Amazon",
    "94:c6:91": "Google Nest", "e4:f0:42": "Google", "08:9e:08": "Google",
    "f4:f5:e8": "Google", "44:07:0b": "Google",
    "00:17:88": "Philips Hue", "00:1f:60": "Philips",
    # Sonos
    "00:0e:58": "Sonos", "94:9f:3e": "Sonos", "5c:aa:fd": "Sonos",
    "78:28:ca": "Sonos", "b8:e9:37": "Sonos",
}


def load_oui_extended(path: str | Path = "infra/data/oui.csv") -> dict[str, str]:
    """Load extended OUI database from IEEE CSV if available.

    Format: Registry,Assignment,Organization Name,Organization Address
    Returns dict keyed by lowercase 'xx:xx:xx'. Falls back silently if
    file is missing.
    """
    p = Path(path)
    if not p.exists():
        return {}
    out: dict[str, str] = {}
    try:
        with p.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                assignment = row.get("Assignment", "").strip().lower()
                if len(assignment) == 6:
                    key = f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}"
                    out[key] = row.get("Organization Name", "").strip()
        log.info(f"[OUI] Loaded {len(out)} entries from {p}")
    except (OSError, csv.Error) as e:
        log.warning(f"[OUI] Could not load {p}: {e}")
    return out


_OUI_DB = {**OUI_BUILTIN, **load_oui_extended()}


def lookup_vendor(mac: str) -> str:
    """Resolve an OUI prefix to a vendor name. Returns '' if unknown."""
    if not mac or len(mac) < 8:
        return ""
    prefix = mac[:8].lower()
    return _OUI_DB.get(prefix, "")


# ---------------------------------------------------------------------------
# SaaS catalog (SNI domain -> human-readable name)
# ---------------------------------------------------------------------------
SAAS = {
    # Communication
    "slack.com": "Slack", "slack-edge.com": "Slack",
    "teams.microsoft.com": "MS Teams", "teams.live.com": "MS Teams",
    "zoom.us": "Zoom", "zoom.com": "Zoom",
    "meet.google.com": "Google Meet", "webex.com": "Webex",
    "discord.com": "Discord", "discordapp.com": "Discord",
    "telegram.org": "Telegram", "whatsapp.net": "WhatsApp",
    # Productivity / Storage
    "drive.google.com": "Google Drive", "docs.google.com": "Google Docs",
    "dropbox.com": "Dropbox", "dropboxapi.com": "Dropbox",
    "sharepoint.com": "SharePoint", "onedrive.live.com": "OneDrive",
    "box.com": "Box", "wetransfer.com": "WeTransfer",
    "icloud.com": "iCloud", "apple-cloudkit.com": "iCloud",
    # Project mgmt
    "trello.com": "Trello", "notion.so": "Notion", "asana.com": "Asana",
    "monday.com": "Monday", "linear.app": "Linear", "clickup.com": "ClickUp",
    "atlassian.com": "Atlassian", "atlassian.net": "Jira/Confluence",
    # Dev
    "github.com": "GitHub", "githubusercontent.com": "GitHub",
    "gitlab.com": "GitLab", "bitbucket.org": "Bitbucket",
    "stackoverflow.com": "StackOverflow", "npmjs.org": "npm",
    "pypi.org": "PyPI", "docker.io": "Docker Hub",
    # CRM / Sales
    "salesforce.com": "Salesforce", "force.com": "Salesforce",
    "hubspot.com": "HubSpot", "pipedrive.com": "Pipedrive",
    "zendesk.com": "Zendesk", "intercom.io": "Intercom",
    # AI
    "claude.ai": "Claude", "anthropic.com": "Anthropic",
    "chat.openai.com": "ChatGPT", "openai.com": "OpenAI",
    "gemini.google.com": "Gemini", "perplexity.ai": "Perplexity",
    "copilot.microsoft.com": "Copilot",
    # Email / Calendar
    "outlook.office365.com": "Office 365", "office.com": "Office 365",
    "login.microsoftonline.com": "Azure AD",
    "mail.google.com": "Gmail", "calendar.google.com": "Google Calendar",
    "protonmail.com": "ProtonMail", "tutanota.com": "Tutanota",
    # Accounting (FR/BE)
    "sage.com": "Sage", "ebp.com": "EBP",
    "quickbooks.intuit.com": "QuickBooks", "xero.com": "Xero",
    "horus.io": "Horus", "pennylane.com": "Pennylane",
    # Communication (calls)
    "leexi.ai": "Leexi", "aircall.io": "Aircall",
    "ringcentral.com": "RingCentral", "twilio.com": "Twilio",
    # Automation
    "zapier.com": "Zapier", "make.com": "Make", "n8n.io": "n8n",
    "ifttt.com": "IFTTT",
    # Security / Auth
    "1password.com": "1Password", "lastpass.com": "LastPass",
    "bitwarden.com": "Bitwarden", "okta.com": "Okta",
    "auth0.com": "Auth0", "duo.com": "Duo",
    # Design
    "figma.com": "Figma", "canva.com": "Canva", "adobe.com": "Adobe",
    "miro.com": "Miro", "lucidchart.com": "Lucidchart",
    # Payments
    "stripe.com": "Stripe", "paypal.com": "PayPal", "square.com": "Square",
    # Cloud (admin consoles)
    "aws.amazon.com": "AWS Console", "console.aws.amazon.com": "AWS Console",
    "portal.azure.com": "Azure Portal",
    "console.cloud.google.com": "GCP Console",
    "digitalocean.com": "DigitalOcean", "ovh.com": "OVH",
    "scaleway.com": "Scaleway", "hetzner.com": "Hetzner",
    # CDN / Analytics
    "cloudflare.com": "Cloudflare", "datadog.com": "Datadog",
    "sentry.io": "Sentry", "newrelic.com": "New Relic",
}

# Port -> service (TCP/UDP common ports, plus OT/IoT)
PORTS = {
    # Standard
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 123: "NTP",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "LPD-Print",
    587: "SMTP-Sub", 593: "RPC-HTTP", 631: "IPP-Print",
    636: "LDAPS", 873: "Rsync",
    993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1434: "MSSQL-UDP",
    1521: "Oracle", 1701: "L2TP", 1723: "PPTP", 1812: "RADIUS",
    2049: "NFS", 2375: "Docker", 2376: "Docker-TLS",
    3128: "HTTP-Proxy", 3268: "GC-LDAP", 3306: "MySQL", 3389: "RDP",
    3478: "STUN", 3702: "WS-Discovery",
    4500: "IPSec-NAT", 5060: "SIP", 5061: "SIP-TLS",
    5222: "XMPP", 5353: "mDNS", 5355: "LLMNR",
    5432: "PostgreSQL", 5672: "AMQP", 5900: "VNC", 5938: "TeamViewer",
    6379: "Redis", 6443: "Kubernetes-API", 6667: "IRC",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8883: "MQTT-TLS",
    9000: "PHP-FPM", 9090: "Prometheus", 9100: "Printer-RAW",
    9200: "Elasticsearch", 9418: "Git",
    11211: "Memcached", 27017: "MongoDB",
    # OT / IoT — often missed by generic tools
    102: "S7 (Siemens PLC)",
    502: "Modbus",
    1883: "MQTT",
    20000: "DNP3",
    44818: "EtherNet/IP",
    47808: "BACnet",
    554: "RTSP (Camera)", 1935: "RTMP",
    8554: "RTSP-Alt",
    32400: "Plex",
    49152: "ONVIF",
}

# Cloud provider CIDR ranges (very small subset — production should pull
# the full lists from each provider's published ranges).
CLOUD_CIDRS: list[tuple[str, str]] = [
    # AWS (sample)
    ("3.0.0.0/8", "AWS"), ("13.32.0.0/15", "AWS-CloudFront"),
    ("18.0.0.0/8", "AWS"), ("52.0.0.0/8", "AWS"),
    ("54.0.0.0/8", "AWS"),
    # Azure (sample)
    ("13.64.0.0/11", "Azure"), ("20.0.0.0/8", "Azure"),
    ("40.64.0.0/10", "Azure"), ("52.96.0.0/12", "Azure"),
    # GCP (sample)
    ("34.64.0.0/10", "GCP"), ("35.184.0.0/13", "GCP"),
    ("35.192.0.0/14", "GCP"),
    # Cloudflare
    ("1.1.1.0/24", "Cloudflare-DNS"),
    ("104.16.0.0/13", "Cloudflare"), ("172.64.0.0/13", "Cloudflare"),
    # Apple iCloud
    ("17.0.0.0/8", "Apple"),
]

_cidr_cache: list[tuple[ipaddress.IPv4Network, str]] = [
    (ipaddress.ip_network(c), n) for c, n in CLOUD_CIDRS
]


def lookup_cloud(ip: str) -> str:
    """Return cloud provider name if IP belongs to a known range, else ''."""
    try:
        addr = ipaddress.ip_address(ip)
        if not isinstance(addr, ipaddress.IPv4Address):
            return ""
        for net, name in _cidr_cache:
            if addr in net:
                return name
        return ""
    except ValueError:
        return ""


def identify_service(port: int, sni: str = "", dns: str = "", http_host: str = "") -> str:
    """Resolve to a service label using domain first, then port."""
    domain = sni or http_host or dns
    if domain:
        # Match against SaaS catalog (suffix match)
        for pattern, name in SAAS.items():
            if pattern in domain:
                return name
    return PORTS.get(port, "")


def is_private_ip(ip: str) -> bool:
    """True if ip is in RFC1918 / loopback / link-local."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
