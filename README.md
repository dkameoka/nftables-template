# A Netfilter configuration setup script template

1. Review and edit the scripts
2. Run as root. Configure only one per OS because these scripts write to /etc/nftables.conf
3. Make sure iptables is disabled, stopped, and flushed.
```
systemctl disable --now iptables
iptables --flush
```
4. Make sure nftables is enabled and restart it.
```
systemctl enable nftables
systemctl restart nftables
```
5. Confirm that the ruleset is active with `nft list ruleset`

