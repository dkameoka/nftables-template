#!/usr/bin/env bash

set -o errexit -o noclobber -o nounset -o pipefail

rm --force --verbose /etc/nftables.conf
cat << 'EONFT' > /etc/nftables.conf
#!/usr/bin/env nft -f

#╔═════════════════════════════════════════════════════╗
#║         Diagram of Netfilter Hook Locations         ║
#║        ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾        ║
#║                        Local Process                ║
#║                        ▲           ▼                ║
#║                    Input           Output           ║
#║                        ▲           ▼                ║
#║ Net─►Prerouting─►Routing─►Forward─►Postrouting─►Net ║
#╚═════════════════════════════════════════════════════╝

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

        # Accept pings at a limited rate.
        icmp type echo-request limit rate 5/second accept

        # Accept ipv6 pings at a limited rate.
        icmpv6 type echo-request limit rate 5/second accept
        
        # IPv6 neighbor discovery works over ICMPv6
        icmpv6 type {nd-neighbor-solicit,nd-router-advert,nd-neighbor-advert} accept

        # Conntrack: Drop packets with an invalid state. Uncommon.
        ct state invalid drop

        # Log dropped packets
#        log prefix "[nftables] Dropped by firewall: "
#        counter
    }

    chain fw_preroute {
        type nat hook prerouting priority filter
        policy accept
    }

    chain fw_forward {
        type filter hook forward priority filter
        # No ip forwarding
        policy drop
    }

    # Egress safelisting
#    set output_allow_dest_addrs {
#        type ipv4_addr
#        flags interval
#        elements = {
#            192.168.0.0/24,
#            10.0.0.0/8
#        }
#    }
#    set output_allow_dest_6addrs {
#        type ipv6_addr
#        flags interval
#        elements = {
#        }
#    }
#    chain fw_output {
#        type filter hook output priority filter
#        policy drop
#        ip daddr @output_allow_dest_addrs accept
#        ip6 daddr @output_allow_dest_6addrs accept
#        log prefix "[nftables] Dropped by firewall whitelist: " counter drop
#    }

    # Egress blocklisting
    # nft add rule inet firewall fw_output ip daddr 192.168.2.0/32 drop
#    chain fw_output {
#        type filter hook output priority filter
#        policy accept
#    }
}
EONFT
echo 'Wrote /etc/nftables.conf'

chmod --changes 700 /etc/nftables.conf

echo 'Make sure to disable, stop, and flush iptables; and enable and restart nftables'
echo 'Confirm ruleset is active with: nft list ruleset'
