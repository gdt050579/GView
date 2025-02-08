#pragma once

#include <GView.hpp>

namespace GView::Type::PCAP
{

namespace Utils
{
static void IPv4ElementToString(uint32 ip, LocalString<64>& out)
{
    union {
        uint8 values[4];
        uint32 value;
    } ipv4{ .value = ip };

    out.Format("%02u.%02u.%02u.%02u (0x%X)", ipv4.values[3], ipv4.values[2], ipv4.values[1], ipv4.values[0], ipv4.value);
}

static void IPv4ElementToStringNoHex(uint32 ip, LocalString<64>& out)
{
    union {
        uint8 values[4];
        uint32 value;
    } ipv4{ .value = ip };

    out.Format("%u.%u.%u.%u", ipv4.values[3], ipv4.values[2], ipv4.values[1], ipv4.values[0]);
}

static void IPv6ElementToString(const uint16 ipv6[8], LocalString<64>& out)
{
    out.Format("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6], ipv6[7]);
}
} // namespace Utils
} // namespace GView::Type::PCAP