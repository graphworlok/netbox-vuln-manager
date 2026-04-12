from netbox.plugins import PluginConfig


class VulnManagerConfig(PluginConfig):
    name = "netbox_vuln_manager"
    verbose_name = "Vulnerability Manager"
    description = "CVE and non-CVE vulnerability and risk management for NetBox"
    version = "0.1.0"
    author = "NetBox Vuln Manager"
    base_url = "vulns"
    min_version = "4.0.0"

    # Default plugin settings; override in NetBox's PLUGINS_CONFIG
    default_settings = {
        # Allow source syncs to create new NetBox assets when an asset is found
        # in vulnerability data but does not exist in NetBox yet.
        "auto_create_assets": False,
        # Strategy used when matching vulnerability report assets to NetBox objects.
        # Options: "ip" | "hostname" | "both"
        "asset_match_strategy": "ip",
        # Number of days after which a finding with no update from source is
        # considered stale and automatically resolved.
        "stale_finding_days": 30,
        # Proxy for outbound API calls (e.g. "http://proxy:3128")
        "http_proxy": None,
    }

    def ready(self):
        # Register signal handlers if needed in future
        pass


config = VulnManagerConfig
