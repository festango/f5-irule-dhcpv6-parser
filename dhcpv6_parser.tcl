#
# DHCPv6 Option Field Parser rev 0.1 (2013/02/25)
#
#   Written By:  Shun Takahashi (s.takahashi at f5.com)
#
#   Description: iRule to demonstrate how tocapture and binary scan DHCPv6 server
#                response and extract client  
#
#                RFC2131 defines DHCP packet structure. This irule is to scan 
#                UDP payload and store information into session tables with
#                your_ip as a key.
#
#                Rule stores client address and DUID into session table
#
#                      [tabe set <client_address> <DUID>]
#                                                   
#                
#   Requirement: The rule requires virtual server to listen on DHCP traffic in the
#                middle either in inline or out of band.
#
#                1) Add following DB key
#
#                tmsh modify tmos.sys.db.tm.allowmulticastl2destinationtraffic value enable
#                tmsh modify sys db vlangroup.forwarding.override value disable
#
#                2) Create VS to receive mirrored DHCPv6 stream
#
#                            ltm virtual vs_dhcpv6 {
#                                destination 0::0.546
#                                ip-protocol udp
#                                mask any6
#                                profiles {
#                                    udp { }
#                                }
#                                rules {
#                                    dhcp-v6
#                                }
#                                translate-address disabled
#                                translate-port disabled
#                                vlans {
#                                    local
#                                }
#                                vlans-enabled
#                            }
#
#   References:  RFC 3315 Dynamic Host Configuration Protocol for IPv6 (DHCPv6)
#
#   Todo:        To set expiration value for table entry corresponding to DHCP lifetime
#
timing off
when CLIENT_ACCEPTED priority 100 {

    # Rule Name and Version shown in the log
    set static::RULE_NAME "Simple DHCPv6 Parser v0.1"
    set static::RULE_ID   "dhcpv6-parser"
    
    # 0: No Debug Logging 1: Debug Logging
    set DBG 1
    
    # Using High-Speed Logging in thie rule
    set log_prefix   "\[$static::RULE_ID\]([IP::client_addr])"
    set log_prefix_d "$log_prefix\(debug\)"
 
}

when CLIENT_DATA {
    if {$DBG}{log local0.debug "$log_prefix_d  ***** iRule: $static::RULE_NAME executed *****"}

    binary scan [UDP::payload] cH6H* msg_type_hex transaction_id options 

    set msg_type [expr 0x$msg_type_hex]
    switch $msg_type {
         1 {set msg_type "SOLICIT"}
         2 {set msg_type "ADVERTISE"}
         3 {set msg_type "REQUEST"}
         4 {set msg_type "CONFIRM"}
         5 {set msg_type "RENEW"}
         6 {set msg_type "REBIND"}
         7 {set msg_type "REPLY"}
         8 {set msg_type "RELEASE"}
         9 {set msg_type "DECLINE"}
        10 {set msg_type "RECONFIGURE"}
        11 {set msg_type "INFORMATION-REQUEST"}
        12 {set msg_type "RELAY-FORW"}
        13 {set msg_type "RELAU-REPL"}
    }

    if {$DBG}{log local0.debug "$log_prefix_d DHCPv6 $msg_type ($msg_type_hex) TID 0x$transaction_id"}
 
    # Extract DHCPv6 Options Field
    set index 0
    set options_length [expr {([UDP::payload length] - 3) * 2 }]
    
    set client_ipv6_addr "none"
    set client_duid "none"
    
    while { $index < $options_length} {
        binary scan $options @${index}a4a4 option_code_hex option_length_hex
        
        set option_code [expr 0x$option_code_hex]
        set option_length [expr (0x$option_length_hex) * 2]

        switch $option_code {
            1 { 
            # Client Identifier
            # The Client Identifier option is used to carry a DUID (see section 9)
            # identifying a client between a client and a server.  The format of
            # the Client Identifier option is:
            #
            # 0                   1                   2                   3
            # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |        OPTION_CLIENTID        |          option-len           |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # .                                                               .
            # .                              DUID                             .
            # .                        (variable length)                      .
            # .                                                               .
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            #
                binary scan $options @${index}x8a${option_length} client_duid
                if {$DBG}{log local0.debug "$log_prefix_d Client DUID: $client_duid"}
            }

            2 {
            # Server Identifier
            # The Server Identifier option is used to carry a DUID (see section 9)
            # identifying a server between a client and a server.  The format of
            # the Server Identifier option is:
            #
            # 0                   1                   2                   3
            # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |        OPTION_SERVERID        |          option-len           |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # .                                                               .
            # .                              DUID                             .
            # .                        (variable length)                      .
            # .                                                               .
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            #
                binary scan $options @${index}x8a${option_length} server_duid
                if {$DBG}{log local0.debug "$log_prefix_d Server DUID: $server_duid"}
            }

            3 {
            # Identity Association for Non-temporary Addresses
            # The Identity Association for Non-temporary Addresses option (IA_NA
            # option) is used to carry an IA_NA, the parameters associated with the
            # IA_NA, and the non-temporary addresses associated with the IA_NA.
            # 
            # Addresses appearing in an IA_NA option are not temporary addresses
            #
            # The format of the IA_NA option is:
            # 
            # 0                   1                   2                   3
            # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |          OPTION_IA_NA         |          option-len           |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |                        IAID (4 octets)                        |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |                              T1                               |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |                              T2                               |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |                                                               |
            # .                         IA_NA-options                         .
            # .                                                               .
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # 
                binary scan $options @${index}x8a${option_length} value
                binary scan $value a8a8a8a4a4a* IAID T1 T2 ia_na_option_hex ia_na_len_hex value
                
                set ia_na_option [expr 0x$ia_na_option_hex]
                set ia_na_len [expr 0x$ia_na_len_hex]
                
                # The rule only handles Internet Address(option 5) 
                if {$ia_na_option == 5} {
                    binary scan $value a4a4a4a4a4a4a4a4h8h8 \
                        a(1) a(2) a(3) a(4) a(5) a(6) a(7) a(8) preffered_lifetime valid_lifetime
                    # Returns IPv6 address
                    set client_ipv6_addr "$a(1):$a(2):$a(3):$a(4):$a(5):$a(6):$a(7):$a(8)"
                    if {$DBG}{log local0.debug "$log_prefix_d Client IA: $client_ipv6_addr"}
                }
            }
        }
        
        set index [expr {$index + 8 + $option_length}]
    }

    # Stores Result into session table
    table set $client_ipv6_addr $client_duid

    log local0.info "$log_prefix Rule added IPv6 Addr: $client_ipv6_addr - Client DUID: $client_duid"
    if {$DBG}{log local0.debug "$log_prefix_d  ***** iRule: $static::RULE_NAME competed *****"}
}