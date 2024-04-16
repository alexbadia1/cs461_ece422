#!/bin/bash

GITHUB_API_SUBNETS="\
192.30.252.0/22
185.199.108.0/22
140.82.112.0/20
143.55.64.0/20
2a0a:a440::/29
2606:50c0::/32
20.27.177.113/32
20.27.177.116/32
20.27.177.118/32
20.29.134.17/32
20.29.134.19/32
20.29.134.23/32
20.87.245.0/32
20.87.245.4/32
20.87.245.6/32
20.175.192.146/32
20.175.192.147/32
20.175.192.149/32
20.199.39.227/32
20.199.39.228/32
20.199.39.232/32
20.200.245.245/32
20.200.245.247/32
20.200.245.248/32
20.201.28.148/32
20.201.28.151/32
20.201.28.152/32
20.205.243.160/32
20.205.243.166/32
20.205.243.168/32
20.207.73.82/32
20.207.73.83/32
20.207.73.85/32
20.233.83.145/32
20.233.83.146/32
20.233.83.149/32
20.248.137.48/32
20.248.137.49/32
20.248.137.50/32
4.208.26.197/32
4.208.26.198/32
4.208.26.200/32"

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

while read -r subnet; do
    iptables -A OUTPUT -d "${subnet}" -p tcp -m tcp \
        --dport 22  -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT 2> /dev/null
    iptables -A OUTPUT -d "${subnet}" -p tcp -m tcp \
        --dport 80  -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT 2> /dev/null
    iptables -A OUTPUT -d "${subnet}" -p tcp -m tcp \
        --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT 2> /dev/null
done <<< "${GITHUB_API_SUBNETS}"

echo "Allow upload configuration done"