#!/usr/bin/env bash

set -o errexit -o noclobber -o nounset -o pipefail

mkdir --parents --verbose /etc/nftables.conf
rm --force --verbose /etc/nftables.conf
cat << 'EONFT' > /etc/nftables.conf
#!/usr/bin/env nft -f

╔═════════════════════════════════════════════════════╗
║         Diagram of Netfilter Hook Locations         ║
║        ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾        ║
║                        Local Process                ║
║                        ▲           ▼                ║
║                    Input           Output           ║
║                        ▲           ▼                ║
║ Net─►Prerouting─►Routing─►Forward─►Postrouting─►Net ║
╚═════════════════════════════════════════════════════╝

# Clear all rules.
flush ruleset

# Create an IPv4+IPv6 table called "firewall"
table inet firewall {

    # Define interval sets

#    set input_allowed_source_addrs {
#        type ipv4_addr
#        flags interval
#        elements = {
#            192.168.200.0/24,
#            192.168.300.123/32
#        }
#    }
#
#    set input_allowed_source_6addrs {
#        type ipv6_addr
#        flags interval
#        elements = {
#            fdab:cdef:abcd::/64,
#            fdab:cdef:abcd:1::/64
#        }
#    }
#
#    set input_allowed_destination_ports {
#        type inet_service
#        flags interval
#        elements = {
#            1234,
#            2345
#        }
#    }

    # Wireguard
#Example with fda:b:c::/64 to fda:b:c:4::/64 IPv6 networks.
#    set wg_admins = {
#        type ipv6_addr
#        flags interval
#        elements = {
#            fda:b:c::/64,
#            fda:b:c:1::/64
#        }
#    }
#
#    set wg_admin_ports = {
#        type inet_service
#        flags interval
#        elements = {
#            ssh,
#            3456,
#            4567
#        }
#    }
#
#    set wg_users = {
#        type ipv6_addr
#        flags interval
#        elements = {
#            fda:b:c:2::/64,
#            fda:b:c:3::/64,
#            fda:b:c:4::/64
#        }
#    }
#
#    set wg_user_ports = {
#        type inet_service
#        flags interval
#        elements = {
#            8080,
#            8081,8082
#        }
#    }


    # Create base chain called "fw_input". This is a base chain because it has a type, hook, and priority.
    chain fw_input {
        # Designates this chain as a type:filter with a hook:input.
        #   The priority determines when the hook is activated. The priority can be negative, but should be kept at the value "filter".
        # The policy drops all packets not accepted by this chain ruleset.
        type filter hook input priority filter
        policy drop

        # Note: For optimal performance, accept the most common traffic earlier.

        # Conntrack: Accept packets that have an established or related state. Very common.
        ct state established,related accept

        # Accept loopback packets. Use iifname for interfaces that may change.
        iif lo accept

# Example: Accept private ips for SSH
#        ip saddr {10.0.0.0/8,172.16.0.0/12,192.168.0.0/16} tcp dport ssh accept
#        ip6 saddr fc00::/7 tcp dport ssh accept

# Example: Accept private ips for DNS
#        ip saddr {10.0.0.0/8,172.16.0.0/12,192.168.0.0/16} udp dport 53 accept
#        ip6 saddr fc00::/7 udp dport 53 accept

#        ip6 saddr @input_allowed_source_addrs tcp dport @input_allowed_destination_ports accept
#        ip6 saddr @input_allowed_source_addrs udp dport @input_allowed_destination_ports accept
#        ip6 saddr @input_allowed_source_6addrs tcp dport @input_allowed_destination_ports accept
#        ip6 saddr @input_allowed_source_6addrs udp dport @input_allowed_destination_ports accept

        # Accept Wireguard connections.
#        udp dport 51820 accept
#
#        ip6 saddr @wg_admins tcp dport @wg_admin_ports accept
#        ip6 saddr @wg_admins udp dport @wg_admin_ports accept
#        ip6 saddr @wg_admins tcp dport @wg_user_ports accept
#        ip6 saddr @wg_admins udp dport @wg_user_ports accept
#
#        ip6 saddr @wg_users tcp dport @wg_user_ports accept
#        ip6 saddr @wg_users udp dport @wg_user_ports accept

        # Accept pings at a limited rate.
        icmp type echo-request limit rate 5/second accept

        # Accept ipv6 pings at a limited rate.
        icmpv6 type echo-request limit rate 5/second accept
        
        # IPv6 neighbor discovery works over ICMPv6
        icmpv6 type {nd-neighbor-solicit,nd-router-advert,nd-neighbor-advert} accept

        # Conntrack: Drop packets with an invalid state. Uncommon.
        ct state invalid drop

        # Log dropped packets
        # log prefix "[nftables] Dropped by firewall: " counter drop
    }

    chain fw_preroute {
        type nat hook prerouting priority filter
        policy accept
        # This is to port forward 80 to 8880 to bypass giving Python lower port binding permissions.
#        tcp dport 80 redirect to 8880
    }

    chain fw_forward {
        type filter hook forward priority filter
        # No ip forwarding
        policy drop
    }

    chain fw_output {
        type filter hook output priority filter
        policy accept
    }
}
EONFT

echo 'Wrote /etc/nftables.conf'

echo 'Make sure to disable, stop, and flush iptables; and enable and restart nftables'
echo 'Confirm ruleset is active with: nft list ruleset'
