# Example of a Simple Plug-Based Firewall

## Install ipset

sudo apt install ipset

## Create Blacklist sets

  * sudo ipset create blacklist_ipv4 hash:ip timeout 86400
  * sudo ipset create blacklist_ipv6 hash:ip timeout 86400 family inet6

## Add iptables rules to match sets

  * sudo iptables  -I INPUT -m set --match-set blacklist_ipv4 src -j DROP
  * sudo ip6tables -I INPUT -m set --match-set blacklist_ipv6 src -j DROP

## Run the server

  * Install dependencies with `mix deps.get`
  * Install Node.js dependencies with `npm install` inside the `assets` directory
  * Start Phoenix endpoint with `mix phx.server`
  * Visit [`localhost:4000`](http://localhost:4000) from your browser

## Further information

  * Plug is at lib/phx_firewallplug_web/plugs/firewall.ex
  * Plug added to lib/phx_firewallplug_web/endpoint.ex 
  * Supporting content: https://www.sonajen.com/articles/211101