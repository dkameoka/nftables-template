# A Netfilter configuration setup script template

1. Review and edit the scripts and run as root
2. Then run it as root. Configure only one per OS because these scripts write to /etc/nftables.conf
3. Make sure iptables is disabled, stopped, and flushed
4. Make sure nftables is enabled and restart it
5. Confirm that the ruleset is active with: nft list ruleset

