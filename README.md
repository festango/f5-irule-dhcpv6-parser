f5 iRule for parsing DHCPv6 server reply
======================

The iRule is to demonstrate how to parse DHCPv6 packet and extract information such that client DUID and assigned IPv6 address.

## Description

iRule is parsing mirrored DHCPv6 traffic to extract client device unique identifier (DUID) and IA (ipv6 address) from server reply and store them into session table for traffic steering and log enrichment purpose.

1. This irule is to scan UDP payload and store information into session tables

    ```[tabe set <client_address> <DUID>]```

2. The rule can be changed to insert client MAC address rather than DUID into session table if needed

    ```[tabe set <client_address> <MAC>]```

## How to use
The rule requires virtual server to listen on DHCP traffic in the middle either in inline or out of band.

1. Add following DB key

    ```
    tmsh modify sys db tm.allowmulticastl2destinationtraffic value enable
    tmsh modify sys db vlangroup.forwarding.override value disable
    ```

    **note** changing db key might cause a unexpected behaviour in traffic management and discourage you to perform this unless you are fully understanding the impact.

2. Create VS to receive mirrored DHCPv6 stream

    ```
    ltm virtual vs_dhcpv6 {
      destination 0::0.546
      ip-protocol udp
      mask any6
      profiles {
        udp { }
      }
      rules {
        dhcp-v6
      }
      translate-address disabled
      translate-port disabled
      vlans {
        local
      }
        vlans-enabled
      }
    ```

## Roadmap

* To set expiretion value onto table entries corresponding to DHCP lifetime values

## Sample Output

```
 [dhcpv6-parser](2001:fb64::222)(debug)  ***** iRule: Simple DHCPv6 Parser v0.1 executed ***** 
 [dhcpv6-parser](2001:fb64::222)(debug) DHCPv6 REPLY (7) TID 0x1403e7 
 [dhcpv6-parser](2001:fb64::222)(debug) Server DUID: 00010000512adf93000c2997c2f1 
 [dhcpv6-parser](2001:fb64::222)(debug) Client DUID: 0001000118bed2eb000c29643bc1 
 [dhcpv6-parser](2001:fb64::222)(debug) Client IA: 2001:fb64:0000:0000:1b5a:9e2b:4385:ac3a 
 [dhcpv6-parser](2001:fb64::222) Rule added IPv6 Addr: 2001:fb64:0000:0000:1b5a:9e2b:4385:ac3a - Client DUID: 0001000118bed2eb000c29643bc1 
 [dhcpv6-parser](2001:fb64::222)(debug)  ***** iRule: Simple DHCPv6 Parser v0.1 competed ***** 
```

## Reference

* References:  RFC 3315 Dynamic Host Configuration Protocol for IPv6 (DHCPv6
