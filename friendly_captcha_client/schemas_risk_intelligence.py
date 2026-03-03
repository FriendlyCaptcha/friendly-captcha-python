from pydantic import BaseModel, Field
from typing import Optional


class RiskScoresData(BaseModel):
    """RiskScoresData summarizes the entire risk intelligence assessment into scores per category.

    Available when the Risk Scores module is enabled for your account.
    None when the Risk Scores module is not enabled for your account.
    """

    # Overall risk score combining all signals.
    overall: int
    # Network-related risk score. Captures likelihood of automation/malicious activity based on
    # IP address, ASN, reputation, geolocation, past abuse from this network, and other network signals.
    network: int
    # Browser-related risk score. Captures likelihood of automation, malicious activity or browser spoofing based on
    # user agent consistency, automation traces, past abuse, and browser characteristics.
    browser: int


class NetworkAutonomousSystemData(BaseModel):
    """NetworkAutonomousSystemData contains information about the AS that owns the IP.

    Available when the IP Intelligence module is enabled for your account.
    None when the IP Intelligence module is not enabled for your account.
    """

    # Autonomous System Number (ASN) identifier.
    # Example: 3209 for Vodafone GmbH
    number: int
    # Name of the autonomous system. This is usually a short name or handle.
    # Example: "VODANET"
    name: str
    # Company is the organization name that owns the ASN.
    # Example: "Vodafone GmbH"
    company: str
    # Description of the company that owns the ASN.
    # Example: "Provides mobile and fixed broadband and telecommunication services to consumers and businesses."
    description: str
    # Domain name associated with the ASN.
    # Example: "vodafone.de"
    domain: str
    # Two-letter ISO 3166-1 alpha-2 country code where the ASN is registered.
    # Example: "DE"
    country: str
    # Regional Internet Registry that allocated the ASN.
    # Example: "RIPE"
    rir: str
    # IP route associated with the ASN in CIDR notation.
    # Example: "88.64.0.0/12"
    route: str
    # Autonomous system type.
    # Example: "isp"
    type: str


class NetworkGeolocationCountryData(BaseModel):
    """NetworkGeolocationCountryData contains detailed country data."""

    # Two-letter ISO 3166-1 alpha-2 country code.
    # Example: "DE"
    iso2: str
    # Three-letter ISO 3166-1 alpha-3 country code.
    # Example: "DEU"
    iso3: str
    # English name of the country.
    # Example: "Germany"
    name: str
    # Native name of the country.
    # Example: "Deutschland"
    name_native: str
    # Major world region.
    # Example: "Europe"
    region: str
    # More specific world region.
    # Example: "Western Europe"
    subregion: str
    # ISO 4217 currency code.
    # Example: "EUR"
    currency: str
    # Full name of the currency.
    # Example: "Euro"
    currency_name: str
    # International dialing code.
    # Example: "49"
    phone_code: str
    # Name of the capital city.
    # Example: "Berlin"
    capital: str


class NetworkGeolocationData(BaseModel):
    """NetworkGeolocationData contains geographic location of the IP address.

    Available when the IP Intelligence module is enabled.
    None when the IP Intelligence module is not enabled.
    """

    # Country information.
    country: NetworkGeolocationCountryData
    # City name. Empty string if unknown.
    # Example: "Eschborn"
    city: str
    # State, region, or province. Empty string if unknown.
    # Example: "Hessen"
    state: str


class NetworkAbuseContactData(BaseModel):
    """NetworkAbuseContactData contains contact details for reporting abuse.

    Available when the IP Intelligence module is enabled.
    None when the IP Intelligence module is not enabled.
    """

    # Postal address of the abuse contact.
    # Example: "Vodafone GmbH, Campus Eschborn, Duesseldorfer Strasse 15, D-65760 Eschborn, Germany"
    address: str
    # Name of the abuse contact person or team.
    # Example: "Vodafone Germany IP Core Backbone"
    name: str
    # Abuse contact email address.
    # Example: "abuse.de@vodafone.com"
    email: str
    # Abuse contact phone number.
    # Example: "+49 6196 52352105"
    phone: str


class NetworkAnonymizationData(BaseModel):
    """NetworkAnonymizationData contains detection of VPNs, proxies, and anonymization services.

    Available when the Anonymization Detection module is enabled.
    None when the Anonymization Detection module is not enabled.
    """

    # Likelihood that the IP is from a VPN service.
    vpn_score: int
    # Likelihood that the IP is from a proxy service.
    proxy_score: int
    # Whether the IP is a Tor exit node.
    tor: bool
    # Whether the IP is from iCloud Private Relay.
    icloud_private_relay: bool


class NetworkData(BaseModel):
    """NetworkData contains information about the network."""

    # IP address used when requesting the challenge.
    # Example: "88.64.4.22"
    ip: str
    # Autonomous System information.
    #
    # Available when the IP Intelligence module is enabled.
    # None when the IP Intelligence module is not enabled.
    as_: Optional[NetworkAutonomousSystemData] = Field(default=None, alias="as")
    # Geolocation information.
    #
    # Available when the IP Intelligence module is enabled.
    # None when the IP Intelligence module is not enabled.
    geolocation: Optional[NetworkGeolocationData] = None
    # Abuse contact information.
    #
    # Available when the IP Intelligence module is enabled.
    # None when the IP Intelligence module is not enabled.
    abuse_contact: Optional[NetworkAbuseContactData] = None
    # IP masking/anonymization information.
    #
    # Available when the Anonymization Detection module is enabled.
    # None when the Anonymization Detection module is not enabled.
    anonymization: Optional[NetworkAnonymizationData] = None


class ClientTimeZoneData(BaseModel):
    """ClientTimeZoneData contains IANA time zone data.

    Available when the Browser Identification module is enabled.
    None when the Browser Identification module is not enabled.
    """

    # IANA time zone name reported by the browser.
    # Example: "America/New_York" or "Europe/Berlin"
    name: str
    # Two-letter ISO 3166-1 alpha-2 country code derived from the time zone.
    # "XU" if timezone is missing or cannot be mapped to a country (e.g., "Etc/UTC").
    # Example: "US" or "DE"
    country_iso2: str


class ClientBrowserData(BaseModel):
    """ClientBrowserData contains detected browser details.

    Available when the Browser Identification module is enabled.
    None when the Browser Identification module is not enabled.
    """

    # Unique browser identifier. Empty string if browser could not be identified.
    # Example: "firefox", "chrome", "chrome_android", "edge", "safari", "safari_ios", "webview_ios"
    id: str
    # Human-readable browser name. Empty string if browser could not be identified.
    # Example: "Firefox", "Chrome", "Edge", "Safari", "Safari on iOS", "WebView on iOS"
    name: str
    # Browser version name. Assumed to be the most recent release matching the signature if exact version unknown. Empty if unknown.
    # Example: "146.0" or "16.5"
    version: str
    # Release date of the browser version in "YYYY-MM-DD" format. Empty string if unknown.
    # Example: "2026-01-28"
    release_date: str


class ClientBrowserEngineData(BaseModel):
    """ClientBrowserEngineData contains detected rendering engine details.

    Available when the Browser Identification module is enabled.
    None when the Browser Identification module is not enabled.
    """

    # Unique rendering engine identifier. Empty string if engine could not be identified.
    # Example: "gecko", "blink", "webkit"
    id: str
    # Human-readable engine name. Empty string if engine could not be identified.
    # Example: "Gecko", "Blink", "WebKit"
    name: str
    # Rendering engine version. Assumed to be the most recent release matching the signature if exact version unknown. Empty if unknown.
    # Example: "146.0" or "16.5"
    version: str


class ClientDeviceData(BaseModel):
    """ClientDeviceData contains detected device details.

    Available when the Browser Identification module is enabled.
    None when the Browser Identification module is not enabled.
    """

    # Device type.
    # Example: "desktop", "mobile", "tablet"
    type: str
    # Device brand.
    # Example: "Apple", "Samsung", "Google"
    brand: str
    # Device model name.
    # Example: "iPhone 17", "Galaxy S21 (SM-G991B)", "Pixel 10"
    model: str


class ClientOSData(BaseModel):
    """ClientOSData contains detected OS details.

    Available when the Browser Identification module is enabled.
    None when the Browser Identification module is not enabled.
    """

    # Unique operating system identifier. Empty string if OS could not be identified.
    # Example: "windows", "macos", "ios", "android", "linux"
    id: str
    # Human-readable operating system name. Empty string if OS could not be identified.
    # Example: "Windows", "macOS", "iOS", "Android", "Linux"
    name: str
    # Operating system version.
    # Example: "10", "11.2.3", "14.4"
    version: str


class TLSSignatureData(BaseModel):
    """TLSSignatureData contains TLS client hello signatures.

    Available when the Bot Detection module is enabled.
    None when the Bot Detection module is not enabled.
    """

    # JA3 hash.
    # Example: "d87a30a5782a73a83c1544bb06332780"
    ja3: str
    # JA3N hash.
    # Example: "28ecc2d2875b345cecbb632b12d8c1e0"
    ja3n: str
    # JA4 signature.
    # Example: "t13d1516h2_8daaf6152771_02713d6af862"
    ja4: str


class ClientAutomationKnownBotData(BaseModel):
    """ClientAutomationKnownBotData contains detected known bot details."""

    # Whether a known bot was detected.
    detected: bool
    # Bot identifier. Empty if no bot detected.
    # Example: "googlebot", "bingbot", "chatgpt"
    id: str
    # Human-readable bot name. Empty if no bot detected.
    # Example: "Googlebot", "Bingbot", "ChatGPT"
    name: str
    # Bot type classification. Empty if no bot detected.
    type: str
    # Link to bot documentation. Empty if no bot detected.
    # Example: "https://developers.google.com/search/docs/crawling-indexing/googlebot"
    url: str


class ClientAutomationToolData(BaseModel):
    """ClientAutomationToolData contains detected automation tool details."""

    # Whether an automation tool was detected.
    detected: bool
    # Automation tool identifier. Empty if no tool detected.
    # Example: "puppeteer", "selenium", "playwright"
    id: str
    # Human-readable tool name. Empty if no tool detected.
    # Example: "Puppeteer", "Selenium WebDriver", "Playwright"
    name: str
    # Automation tool type. Empty if no tool detected.
    type: str


class ClientAutomationData(BaseModel):
    """ClientAutomationData contains information about detected automation.

    Available when the Bot Detection module is enabled.
    None when the Bot Detection module is not enabled.
    """

    # Detected automation tool information.
    automation_tool: ClientAutomationToolData
    # Detected known bot information.
    known_bot: ClientAutomationKnownBotData


class ClientData(BaseModel):
    """ClientData contains information about the user agent and device."""

    # User-Agent HTTP header value.
    # Example: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0"
    header_user_agent: str
    # Time zone information.
    #
    # Available when the Browser Identification module is enabled.
    # None when the Browser Identification module is not enabled.
    time_zone: Optional[ClientTimeZoneData] = None
    # Browser information.
    #
    # Available when the Browser Identification module is enabled.
    # None when the Browser Identification module is not enabled.
    browser: Optional[ClientBrowserData] = None
    # Browser engine information.
    #
    # Available when the Browser Identification module is enabled.
    # None when the Browser Identification module is not enabled.
    browser_engine: Optional[ClientBrowserEngineData] = None
    # Device information.
    #
    # Available when the Browser Identification module is enabled.
    # None when the Browser Identification module is not enabled.
    device: Optional[ClientDeviceData] = None
    # OS information.
    #
    # Available when the Browser Identification module is enabled.
    # None when the Browser Identification module is not enabled.
    os: Optional[ClientOSData] = None
    # TLS signatures.
    #
    # Available when the Bot Detection module is enabled.
    # None when the Bot Detection module is not enabled.
    tls_signature: Optional[TLSSignatureData] = None
    # Automation detection data.
    #
    # Available when the Bot Detection module is enabled.
    # None when the Bot Detection module is not enabled.
    automation: Optional[ClientAutomationData] = None


class RiskIntelligenceData(BaseModel):
    """RiskIntelligenceData contains all risk intelligence information.

    Field availability depends on enabled modules.
    """

    # Risk scores from various signals, these summarize the risk intelligence assessment.
    #
    # Available when the Risk Scores module is enabled.
    # None when the Risk Scores module is not enabled.
    risk_scores: Optional[RiskScoresData] = None
    # Network-related risk intelligence.
    network: NetworkData
    # Client/device risk intelligence.
    client: ClientData
