from netbox.plugins.navigation import PluginMenu, PluginMenuButton, PluginMenuItem
from utilities.choices import ButtonColorChoices


menu = PluginMenu(
    label="Vulnerability Manager",
    groups=(
        (
            "Findings",
            (
                PluginMenuItem(
                    link="plugins:netbox_vuln_manager:vulnerabilityfinding_list",
                    link_text="All Findings",
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_vuln_manager:vulnerabilityfinding_add",
                            title="Add Finding",
                            icon_class="mdi mdi-plus-thick",
                            color=ButtonColorChoices.GREEN,
                        ),
                    ),
                ),
            ),
        ),
        (
            "Vulnerabilities",
            (
                PluginMenuItem(
                    link="plugins:netbox_vuln_manager:vulnerability_list",
                    link_text="Vulnerabilities",
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_vuln_manager:vulnerability_add",
                            title="Add Vulnerability",
                            icon_class="mdi mdi-plus-thick",
                            color=ButtonColorChoices.GREEN,
                        ),
                    ),
                ),
            ),
        ),
        (
            "Sources",
            (
                PluginMenuItem(
                    link="plugins:netbox_vuln_manager:vulnerabilitysource_list",
                    link_text="Data Sources",
                    buttons=(
                        PluginMenuButton(
                            link="plugins:netbox_vuln_manager:vulnerabilitysource_add",
                            title="Add Source",
                            icon_class="mdi mdi-plus-thick",
                            color=ButtonColorChoices.GREEN,
                        ),
                    ),
                ),
            ),
        ),
    ),
    icon_class="mdi mdi-shield-bug",
)
