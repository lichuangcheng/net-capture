#ifndef NETCAP_PROTOCOL_TYPE_INCLUDED
#define NETCAP_PROTOCOL_TYPE_INCLUDED

#include <stdint.h>

enum class ProtocolType : uint8_t {
    Reserved = 0, // 保留Reserved
    ICMP = 1, // ICMP Internet Control Message [RFC792]
    IGMP = 2, // IGMP Internet Group Management [RFC1112]
    GGP = 3, // GGP Gateway-to-Gateway [RFC823]
    IP = 4, // IP in IP (encapsulation) [RFC2003]
    TCP = 6, // TCP Transmission Control Protocol [RFC793]
    UDP = 17, // UDP User Datagram Protocol [RFC768]
    HMP = 20, // HMP Host Monitoring Protocol [RFC 869]
    RDP = 27, // RDP Reliable Data Protocol [ RFC908 ]
    RSVP = 46, // RSVP (Reservation Protocol)
    GRE = 47, // GRE (General Routing Encapsulation)
    ESP = 50, // ESP Encap Security Payload [RFC2406]
    AH = 51, // AH (Authentication Header) [RFC2402]
    NARP = 54, // NARP (NBMA Address Resolution Protocol) [RFC1735]
    IPv6_ICMP = 58, // IPv6-ICMP (ICMP for IPv6) [RFC1883]
    IPv6_NoNxt = 59, // IPv6-NoNxt (No Next Header for IPv6) [RFC1883]
    IPv6_Opts = 60, // IPv6-Opts (Destination Options for IPv6) [RFC1883]
    OSPF = 89, // OSPF (OSPF Version 2) [RFC 1583]
    VRRP = 112, // VRRP (Virtual Router Redundancy Protocol) [RFC3768]
    L2TP = 115, // L2TP (Layer Two Tunneling Protocol)
    ISIS = 124, // ISIS over IPv4
    CRTP = 126, // CRTP (Combat Radio Transport Protocol)
    CRUDP = 127, // CRUDP (Combat Radio User Protocol)
    SCTP = 132, // SCTP (Stream Control Transmission Protocol)
    UDPLite = 136, // UDPLite [RFC 3828]
    MPLS_in_IP = 137, // MPLS-in-IP [RFC 4023]
};

inline const char *to_string(ProtocolType t) {
    using enum ProtocolType;
    switch (t) {
    case Reserved: return "Reserved";
    case ICMP: return "ICMP";
    case IGMP: return "IGMP";
    case GGP: return "GGP";
    case IP: return "IP";
    case TCP: return "TCP";
    case UDP: return "UDP";
    case HMP: return "HMP";
    case RDP: return "RDP";
    case RSVP: return "RSVP";
    case GRE: return "GRE";
    case ESP: return "ESP";
    case AH: return "AH";
    case NARP: return "NARP";
    case IPv6_ICMP: return "IPv6_ICMP";
    case IPv6_NoNxt: return "IPv6_NoNxt";
    case IPv6_Opts: return "IPv6_Opts";
    case OSPF: return "OSPF";
    case VRRP: return "VRRP";
    case L2TP: return "L2TP";
    case ISIS: return "ISIS";
    case CRTP: return "CRTP";
    case CRUDP: return "CRUDP";
    case SCTP: return "SCTP";
    case UDPLite: return "UDPLite";
    case MPLS_in_IP: return "MPLS_in_IP";
    default: return "";
    }
}

#endif // NETCAP_PROTOCOL_TYPE_INCLUDED
