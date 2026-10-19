"""Generate fail-closed nftables firewall policies (operator-applied only)."""


def client_policy(endpoint, port, proto="udp"):
    if proto not in ("tcp", "udp"):
        raise ValueError("Unsupported transport")
    return (
        "table inet gcvpn_client {\n"
        "  chain output {\n"
        "    type filter hook output priority -100; policy drop;\n"
        "    oifname \"lo\" accept\n"
        "    oifname \"gpv0\" accept\n"
        f"    ip daddr {endpoint} {proto} dport {port} accept\n"
        "  }\n"
        "}\n"
    )


def entry_policy():
    return (
        "table inet gcvpn_entry {\n"
        "  chain forward {\n"
        "    type filter hook forward priority -100; policy accept;\n"
        "    iifname \"gpe0\" ip saddr != 10.77.1.0/24 drop\n"
        "    iifname \"gpe0\" oifname != \"gpt0\" drop\n"
        "    oifname \"gpe0\" iifname != \"gpt0\" drop\n"
        "    oifname \"gpe0\" ct state != established,related drop\n"
        "  }\n"
        "}\n"
    )


def exit_policy(wan):
    return (
        "table inet gcvpn_exit {\n"
        "  chain forward {\n"
        "    type filter hook forward priority -100; policy accept;\n"
        "    iifname \"gpt0\" ip saddr != 10.77.1.0/24 drop\n"
        f"    iifname \"gpt0\" oifname != \"{wan}\" drop\n"
        f"    oifname \"gpt0\" iifname != \"{wan}\" drop\n"
        "    oifname \"gpt0\" ct state != established,related drop\n"
        "  }\n"
        "}\n"
        "table ip gcvpn_exit_nat {\n"
        "  chain postrouting {\n"
        "    type nat hook postrouting priority srcnat; policy accept;\n"
        f"    oifname \"{wan}\" ip saddr 10.77.1.0/24 masquerade\n"
        "  }\n"
        "}\n"
    )
