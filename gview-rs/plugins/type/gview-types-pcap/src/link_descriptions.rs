//! `PCAP::LinkTypeDescriptions` (C++
//! `Types/PCAP/include/Internal.hpp`).
//!
//! Transcribed verbatim from the C++ table. The `Information` panel's
//! `Network` row renders `"%-20s (%s) %s"` with the link-type name,
//! its hex value and the description looked up here (C++
//! `Panels::Information::UpdatePcapHeader`).

/// `(LinkType, description)` pairs in ascending link-type order.
pub const LINK_TYPE_DESCRIPTIONS: [(u32, &str); 132] = [
    (0, "BSD loopback encapsulation; the link layer header is a 4-byte field, in host byte order, containing a value of 2 for IPv4 packets, a value of either 24, 28, or 30 for IPv6 packets, a value of 7 for OSI packets, or a value of 23 for IPX packets. All of the IPv6 values correspond to IPv6 packets; code reading files should check for all of them. ote that ``host byte order'' is the byte order of the machine on that the packets are captured; if a live capture is being done, ``host byte order'' is the byte order of the machine capturing the packets, but if a ``savefile'' is being read, the byte order is not necessarily that of the machine reading the capture file."), // LinkType::NULL_
    (1, "IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up); the 10MB in the DLT_ name is historical."), // LinkType::ETHERNET
    (3, "AX.25 packet, with nothing preceding it."), // LinkType::AX25
    (6, "IEEE 802.5 Token Ring; the IEEE802, without _5, in the DLT_ name is historical."), // LinkType::IEEE802_5
    (7, "ARCNET Data Packets, as described by the ARCNET Trade Association standard ATA 878.1-1999, but without the Starting Delimiter, Information Length, or Frame Check Sequence fields, and with only the first ISU of the Destination Identifier. For most packet types, ARCNET Trade Association draft standard ATA 878.2 is also used. See also RFC 1051 and RFC 1201; for RFC 1051 frames, ATA 878.2 is not used."), // LinkType::ARCNET_BSD
    (8, "SLIP, encapsulated with a LINKTYPE_SLIP header."), // LinkType::SLIP
    (9, "PPP, as per RFC 1661 and RFC 1662; if the first 2 bytes are 0xff and 0x03, it's PPP in HDLC-like framing, with the PPP header following those two bytes, otherwise it's PPP without framing, and the packet begins with the PPP header. The data in the frame is not octet-stuffed or bit-stuffed."), // LinkType::PPP
    (10, "FDDI, as specified by ANSI INCITS 239-1994."), // LinkType::FDDI
    (50, "PPP in HDLC-like framing, as per RFC 1662, or Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547; the first byte will be 0xFF for PPP in HDLC-like framing, and will be 0x0F or 0x8F for Cisco PPP with HDLC framing. The data in the frame is not octet-stuffed or bit-stuffed."), // LinkType::PPP_HDLC
    (51, "PPPoE; the packet begins with a PPPoE header, as per RFC 2516."), // LinkType::PPP_ETHER
    (100, "RFC 1483 LLC/SNAP-encapsulated ATM; the packet begins with an ISO 8802-2 (formerly known as IEEE 802.2) LLC header."), // LinkType::ATM_RFC1483
    (101, "Raw IP; the packet begins with an IPv4 or IPv6 header, with the version field of the header indicating whether it's an IPv4 or IPv6 header."), // LinkType::RAW
    (104, "Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547."), // LinkType::C_HDLC
    (105, "IEEE 802.11 wireless LAN."), // LinkType::IEEE802_11
    (107, "Frame Relay LAPF frames, beginning with a ITU-T Recommendation Q.922 LAPF header starting with the address field, and without an FCS at the end of the frame."), // LinkType::FRELAY
    (108, "OpenBSD loopback encapsulation; the link-layer header is a 4-byte field, in network byte order, containing a value of 2 for IPv4 packets, a value of either 24, 28, or 30 for IPv6 packets, a value of 7 for OSI packets, or a value of 23 for IPX packets. All of the IPv6 values correspond to IPv6 packets; code reading files should check for all of them."), // LinkType::LOOP
    (113, "Linux \"cooked\" capture encapsulation."), // LinkType::LINUX_SLL
    (114, "Apple LocalTalk; the packet begins with an AppleTalk LocalTalk Link Access Protocol header, as described in chapter 1 of Inside AppleTalk, Second Edition."), // LinkType::LTALK
    (117, "OpenBSD pflog; the link-layer header contains a struct pfloghdr structure, as defined by the host on that the file was saved. (This differs from operating system to operating system and release to release; there is nothing in the file to indicate what the layout of that structure is.)"), // LinkType::PFLOG
    (119, "Prism monitor mode information followed by an 802.11 header."), // LinkType::IEEE802_11_PRISM
    (122, "RFC 2625 IP-over-Fibre Channel, with the link-layer header being the Network_Header as described in that RFC."), // LinkType::IP_OVER_FC
    (123, "ATM traffic, encapsulated as per the scheme used by SunATM devices."), // LinkType::SUNATM
    (127, "Radiotap link-layer information followed by an 802.11 header."), // LinkType::IEEE802_11_RADIOTAP
    (129, "ARCNET Data Packets, as described by the ARCNET Trade Association standard ATA 878.1-1999, but without the Starting Delimiter, Information Length, or Frame Check Sequence fields, with only the first ISU of the Destination Identifier, and with an extra two-ISU offset field following the Destination Identifier. For most packet types, ARCNET Trade Association draft standard ATA 878.2 is also used; however, no exception frames are supplied, and reassembled frames, rather than fragments, are supplied. See also RFC 1051 and RFC 1201; for RFC 1051 frames, ATA 878.2 is not used."), // LinkType::ARCNET_LINUX
    (138, "Apple IP-over-IEEE 1394 cooked header."), // LinkType::APPLE_IP_OVER_IEEE1394
    (139, "Signaling System 7 Message Transfer Part Level 2, as specified by ITU-T Recommendation Q.703, preceded by a pseudo-header."), // LinkType::MTP2_WITH_PHDR
    (140, "Signaling System 7 Message Transfer Part Level 2, as specified by ITU-T Recommendation Q.703."), // LinkType::MTP2
    (141, "Signaling System 7 Message Transfer Part Level 3, as specified by ITU-T Recommendation Q.704, with no MTP2 header preceding the MTP3 packet."), // LinkType::MTP3
    (142, "Signaling System 7 Signalling Connection Control Part, as specified by ITU-T Recommendation Q.711, ITU-T Recommendation Q.712, ITU-T Recommendation Q.713, and ITU-T Recommendation Q.714, with no MTP3 or MTP2 headers preceding the SCCP packet."), // LinkType::SCCP
    (143, "DOCSIS MAC frames, as described by the DOCSIS 3.1 MAC and Upper Layer Protocols Interface Specification or earlier specifications for MAC frames."), // LinkType::DOCSIS
    (144, "Linux-IrDA packets, with a LINKTYPE_LINUX_IRDA header, with the payload for IrDA frames beginning with by the IrLAP header as defined by IrDA Data Specifications, including the IrDA Link Access Protocol specification."), // LinkType::LINUX_IRDA
    (147, "Reserved for private use."), // LinkType::USER0
    (148, "Reserved for private use."), // LinkType::USER1
    (149, "Reserved for private use."), // LinkType::USER2
    (150, "Reserved for private use."), // LinkType::USER3
    (151, "Reserved for private use."), // LinkType::USER4
    (152, "Reserved for private use."), // LinkType::USER5
    (153, "Reserved for private use."), // LinkType::USER6
    (154, "Reserved for private use."), // LinkType::USER7
    (155, "Reserved for private use."), // LinkType::USER8
    (156, "Reserved for private use."), // LinkType::USER10
    (157, "Reserved for private use."), // LinkType::USER11
    (158, "Reserved for private use."), // LinkType::USER12
    (159, "Reserved for private use."), // LinkType::USER13
    (160, "Reserved for private use."), // LinkType::USER14
    (161, "Reserved for private use."), // LinkType::USER15
    (162, "Reserved for private use."), // LinkType::USER16
    (163, "AVS monitor mode information followed by an 802.11 header."), // LinkType::IEEE802_11_AVS
    (165, "BACnet MS/TP frames, as specified by section 9.3 MS/TP Frame Format of ANSI/ASHRAE Standard 135, BACnet� - A Data Communication Protocol for Building Automation and Control Networks, including the preamble and, if present, the Data CRC."), // LinkType::BACNET_MS_TP
    (166, "PPP in HDLC-like encapsulation, like LINKTYPE_PPP_HDLC, but with the 0xff address byte replaced by a direction indication�0x00 for incoming and 0x01 for outgoing."), // LinkType::PPP_PPPD
    (169, "General Packet Radio Service Logical Link Control, as defined by 3GPP TS 04.64."), // LinkType::GPRS_LLC
    (170, "Transparent-mapped generic framing procedure, as specified by ITU-T Recommendation G.7041/Y.1303."), // LinkType::GPF_T
    (171, "Frame-mapped generic framing procedure, as specified by ITU-T Recommendation G.7041/Y.1303."), // LinkType::GPF_F
    (177, "Link Access Procedures on the D Channel (LAPD) frames, as specified by ITU-T Recommendation Q.920 and ITU-T Recommendation Q.921, captured via vISDN, with a LINKTYPE_LINUX_LAPD header, followed by the Q.921 frame, starting with the address field."), // LinkType::LINUX_LAPD
    (182, "Multi-Link Frame Relay frames, beginning with an FRF.12 Interface fragmentation format fragmentation header."), // LinkType::MFR
    (187, "Bluetooth HCI UART transport layer; the frame contains an HCI packet indicator byte, as specified by the UART Transport Layer portion of the most recent Bluetooth Core specification, followed by an HCI packet of the specified packet type, as specified by the Host Controller Interface Functional Specification portion of the most recent Bluetooth Core Specification."), // LinkType::BLUETOOTH_HCI_H4
    (189, "USB packets, beginning with a Linux USB header, as specified by the struct usbmon_packet in the Documentation/usb/usbmon.txt file in the Linux source tree. Only the first 48 bytes of that header are present. All fields in the header are in host byte order. When performing a live capture, the host byte order is the byte order of the machine on that the packets are captured. When reading a pcap file, the byte order is the byte order for the file, as specified by the file's magic number; when reading a pcapng file, the byte order is the byte order for the section of the pcapng file, as "), // LinkType::USB_LINUX
    (192, "Per-Packet Information information, as specified by the Per-Packet Information Header Specification, followed by a packet with the LINKTYPE_ value specified by the pph_dlt field of that header."), // LinkType::PPI
    (195, "IEEE 802.15.4 Low-Rate Wireless Networks, with each packet having the FCS at the end of the frame."), // LinkType::IEEE802_15_4_WITHFCS
    (196, "Various link-layer types, with a pseudo-header, for SITA."), // LinkType::SITA
    (197, "Various link-layer types, with a pseudo-header, for Endace DAG cards; encapsulates Endace ERF records."), // LinkType::ERF
    (201, "Bluetooth HCI UART transport layer; the frame contains a 4-byte direction field, in network byte order (big-endian), the low-order bit of which is set if the frame was sent from the host to the controller and clear if the frame was received by the host from the controller, followed by an HCI packet indicator byte, as specified by the UART Transport Layer portion of the most recent Bluetooth Core specification, followed by an HCI packet of the specified packet type, as specified by the Host Controller Interface Functional Specification portion of the most recent Bluetooth Core Specifi"), // LinkType::BLUETOOTH_HCI_H4_WITH_PHDR
    (202, "AX.25 packet, with a 1-byte KISS header containing a type indicator."), // LinkType::AX25_KISS
    (203, "Link Access Procedures on the D Channel (LAPD) frames, as specified by ITU-T Recommendation Q.920 and ITU-T Recommendation Q.921, starting with the address field, with no pseudo-header."), // LinkType::LAPD
    (204, "PPP, as per RFC 1661 and RFC 1662, preceded with a one-byte pseudo-header with a zero value meaning \"received by this host\" and a non-zero value meaning \"sent by this host\"; if the first 2 bytes are 0xff and 0x03, it's PPP in HDLC-like framing, with the PPP header following those two bytes, otherwise it's PPP without framing, and the packet begins with the PPP header. The data in the frame is not octet-stuffed or bit-stuffed."), // LinkType::PPP_WITH_DIR
    (205, "Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547, preceded with a one-byte pseudo-header with a zero value meaning \"received by this host\" and a non-zero value meaning \"sent by this host\"."), // LinkType::C_HDLC_WITH_DIR
    (206, "Frame Relay LAPF frames, beginning with a one-byte pseudo-header with a zero value meaning \"received by this host\" (DCE->DTE) and a non-zero value meaning \"sent by this host\" (DTE->DCE), followed by an ITU-T Recommendation Q.922 LAPF header starting with the address field, and without an FCS at the end of the frame."), // LinkType::FRELAY_WITH_DIR
    (207, "Link Access Procedure, Balanced (LAPB), as specified by ITU-T Recommendation X.25, preceded with a one-byte pseudo-header with a zero value meaning \"received by this host\" (DCE->DTE) and a non-zero value meaning \"sent by this host\" (DTE->DCE)."), // LinkType::LAPB_WITH_DIR
    (209, "IPMB over an I2C circuit, with a Linux-specific pseudo-header."), // LinkType::IPMB_LINUX
    (210, "FlexRay automotive bus frames or symbols, preceded by a pseudo-header."), // LinkType::FLEXRAY
    (212, "Local Interconnect Network (LIN) automotive bus, preceded by a pseudo-header."), // LinkType::LIN
    (215, "IEEE 802.15.4 Low-Rate Wireless Networks, with each packet having the FCS at the end of the frame, and with the PHY-level data for the O-QPSK, BPSK, GFSK, MSK, and RCC DSS BPSK PHYs (4 octets of 0 as preamble, one octet of SFD, one octet of frame length + reserved bit) preceding the MAC-layer data (starting with the frame control field)."), // LinkType::IEEE802_15_4_NONASK_PHY
    (220, "USB packets, beginning with a Linux USB header, as specified by the struct usbmon_packet in the Documentation/usb/usbmon.txt file in the Linux source tree. All 64 bytes of the header are present. All fields in the header are in host byte order. When performing a live capture, the host byte order is the byte order of the machine on that the packets are captured. When reading a pcap file, the byte order is the byte order for the file, as specified by the file's magic number; when reading a pcapng file, the byte order is the byte order for the section of the pcapng file, as specified by"), // LinkType::USB_LINUX_MMAPPED
    (224, "Fibre Channel FC-2 frames, beginning with a Frame_Header."), // LinkType::FC_2
    (225, "Fibre Channel FC-2 frames, beginning an encoding of the SOF, followed by a Frame_Header, and ending with an encoding of the SOF. The encodings represent the frame delimiters as 4-byte sequences representing the corresponding ordered sets, with K28.5 represented as 0xBC, and the D symbols as the corresponding byte values; for example, SOFi2, which is K28.5 - D21.5 - D1.2 - D21.2, is represented as 0xBC 0xB5 0x55 0x55."), // LinkType::FC_2_WITH_FRAME_DELIMS
    (226, "Solaris ipnet pseudo-header, followed by an IPv4 or IPv6 datagram."), // LinkType::IPNET
    (227, "CAN (Controller Area Network) frames, with a pseudo-header followed by the frame payload."), // LinkType::CAN_SOCKETCAN
    (228, "Raw IPv4; the packet begins with an IPv4 header."), // LinkType::IPV4
    (229, "Raw IPv6; the packet begins with an IPv6 header."), // LinkType::IPV6
    (230, "IEEE 802.15.4 Low-Rate Wireless Network, without the FCS at the end of the frame."), // LinkType::IEEE802_15_4_NOFCS
    (231, "Raw D-Bus messages, starting with the endianness flag, followed by the message type, etc., but without the authentication handshake before the message sequence."), // LinkType::DBUS
    (235, "DVB-CI (DVB Common Interface for communication between a PC Card module and a DVB receiver), with the message format specified by the PCAP format for DVB-CI specification."), // LinkType::DVB_CI
    (236, "Variant of 3GPP TS 27.010 multiplexing protocol (similar to, but not the same as, 27.010)."), // LinkType::MUX27010
    (237, "D_PDUs as described by NATO standard STANAG 5066, starting with the synchronization sequence, and including both header and data CRCs. The current version of STANAG 5066 is backwards-compatible with the 1.0.2 version, although newer versions are classified."), // LinkType::STANAG_5066_D_PDU
    (239, "Linux netlink NETLINK NFLOG socket log messages."), // LinkType::NFLOG
    (240, "Pseudo-header for Hilscher Gesellschaft f�r Systemautomation mbH netANALYZER devices, followed by an Ethernet frame, beginning with the MAC header and ending with the FCS."), // LinkType::NETANALYZER
    (241, "Pseudo-header for Hilscher Gesellschaft f�r Systemautomation mbH netANALYZER devices, followed by an Ethernet frame, beginning with the preamble, SFD, and MAC header, and ending with the FCS."), // LinkType::NETANALYZER_TRANSPARENT
    (242, "IP-over-InfiniBand, as specified by RFC 4391 section 6."), // LinkType::IPOIB
    (243, "MPEG-2 Transport Stream transport packets, as specified by ISO 13818-1/ITU-T Recommendation H.222.0 (see table 2-2 of section 2.4.3.2 \"Transport Stream packet layer\")."), // LinkType::MPEG_2_TS
    (244, "Pseudo-header for ng4T GmbH's UMTS Iub/Iur-over-ATM and Iub/Iur-over-IP format as used by their ng40 protocol tester, followed by frames for the Frame Protocol as specified by 3GPP TS 25.427 for dedicated channels and 3GPP TS 25.435 for common/shared channels in the case of ATM AAL2 or UDP traffic, by SSCOP packets as specified by ITU-T Recommendation Q.2110 for ATM AAL5 traffic, and by NBAP packets for SCTP traffic."), // LinkType::NG40
    (245, "Pseudo-header for NFC LLCP packet captures, followed by frame data for the LLCP Protocol as specified by NFCForum-TS-LLCP_1.1."), // LinkType::NFC_LLCP
    (247, "Raw InfiniBand frames, starting with the Local Routing Header, as specified in Chapter 5 \"Data packet format\" of InfiniBand� Architectural Specification Release 1.2.1 Volume 1 - General Specifications."), // LinkType::INFINIBAND
    (248, "SCTP packets, as defined by RFC 4960, with no lower-level protocols such as IPv4 or IPv6."), // LinkType::SCTP
    (249, "USB packets, beginning with a USBPcap header."), // LinkType::USBPCAP
    (250, "Serial-line packet header for the Schweitzer Engineering Laboratories \"RTAC\" product, followed by a payload for one of a number of industrial control protocols."), // LinkType::RTAC_SERIAL
    (251, "Bluetooth Low Energy air interface Link Layer packets, in the format described in section 2.1 \"PACKET FORMAT\" of volume 6 of the Bluetooth Specification Version 4.0 (see PDF page 2200), but without the Preamble."), // LinkType::BLUETOOTH_LE_LL
    (253, "Linux Netlink capture encapsulation."), // LinkType::NETLINK
    (254, "Bluetooth Linux Monitor encapsulation of traffic for the BlueZ stack."), // LinkType::BLUETOOTH_LINUX_MONITOR
    (255, "Bluetooth Basic Rate and Enhanced Data Rate baseband packets."), // LinkType::BLUETOOTH_BREDR_BB
    (256, "Bluetooth Low Energy link-layer packets."), // LinkType::BLUETOOTH_LE_LL_WITH_PHDR
    (257, "PROFIBUS data link layer packets, as specified by IEC standard 61158-4-3, beginning with the start delimiter, ending with the end delimiter, and including all octets between them."), // LinkType::PROFIBUS_DL
    (258, "Apple PKTAP capture encapsulation."), // LinkType::PKTAP
    (259, "Ethernet-over-passive-optical-network packets, starting with the last 6 octets of the modified preamble as specified by 65.1.3.2 \"Transmit\" in Clause 65 of Section 5 of IEEE 802.3, followed immediately by an Ethernet frame."), // LinkType::EPON
    (260, "IPMI trace packets, as specified by Table 3-20 \"Trace Data Block Format\" in the PICMG HPM.2 specification. The time stamps for packets in this format must match the time stamps in the Trace Data Blocks."), // LinkType::IPMI_HPM_2
    (261, "Z-Wave RF profile R1 and R2 packets, as specified by ITU-T Recommendation G.9959, with some MAC layer fields moved."), // LinkType::ZWAVE_R1_R2
    (262, "Z-Wave RF profile R3 packets, as specified by ITU-T Recommendation G.9959, with some MAC layer fields moved."), // LinkType::ZWAVE_R3
    (263, "Formats for WattStopper Digital Lighting Management (DLM) and Legrand Nitoo Open protocol common packet structure captures."), // LinkType::WATTSTOPPER_DLM
    (264, "Messages between ISO 14443 contactless smartcards (Proximity Integrated Circuit Card, PICC) and card readers (Proximity Coupling Device, PCD), with the message format specified by the PCAP format for ISO14443 specification."), // LinkType::ISO_14443
    (265, "Radio data system (RDS) groups, as per IEC 62106, encapsulated in this form."), // LinkType::RDS
    (266, "USB packets, beginning with a Darwin (macOS, etc.) USB header."), // LinkType::USB_DARWIN
    (268, "SDLC packets, as specified by Chapter 1, \"DLC Links\", section \"Synchronous Data Link Control(SDLC)\" of Systems Network Architecture Formats, GA27-3136-20, without the flag fields, zero-bit insertion, or Frame Check Sequence field, containing SNA path information units (PIUs) as the payload."), // LinkType::SDLC
    (270, "LoRaTap pseudo-header, followed by the payload, which is typically the PHYPayload from the LoRaWan specification."), // LinkType::LORATAP
    (271, "Protocol for communication between host and guest machines in VMware and KVM hypervisors."), // LinkType::VSOCK
    (272, "Messages to and from a Nordic Semiconductor nRF Sniffer for Bluetooth LE packets, beginning with a pseudo-header."), // LinkType::NORDIC_BLE
    (273, "DOCSIS packets and bursts, preceded by a pseudo-header giving metadata about the packet."), // LinkType::DOCSIS31_XRA31
    (274, "mPackets, as specified by IEEE 802.3br Figure 99-4, starting with the preamble and always ending with a CRC field."), // LinkType::ETHERNET_MPACKET
    (275, "DisplayPort AUX channel monitoring data as specified by VESA DisplayPort (DP) Standard preceded by a pseudo-header."), // LinkType::DISPLAYPORT_AUX
    (276, "Linux \"cooked\" capture encapsulation v2."), // LinkType::LINUX_SLL2
    (278, "Openvizsla FPGA-based USB sniffer."), // LinkType::OPENVIZSLA
    (279, "Elektrobit High Speed Capture and Replay (EBHSCR) format."), // LinkType::EBHSCR
    (280, "Records in traces from the http://fd.io VPP graph dispatch tracer, in the the graph dispatcher trace format."), // LinkType::VPP_DISPATCH
    (281, "Ethernet frames, with a switch tag inserted between the source address field and the type/length field in the Ethernet header."), // LinkType::DSA_TAG_BRCM
    (282, "Ethernet frames, with a switch tag inserted before the destination address in the Ethernet header."), // LinkType::DSA_TAG_BRCM_PREPEND
    (283, "IEEE 802.15.4 Low-Rate Wireless Networks, with a pseudo-header containing TLVs with metadata preceding the 802.15.4 header."), // LinkType::IEEE802_15_4_TAP
    (284, "Ethernet frames, with a switch tag inserted between the source address field and the type/length field in the Ethernet header."), // LinkType::DSA_TAG_DSA
    (285, "Ethernet frames, with a programmable Ethernet type switch tag inserted between the source address field and the type/length field in the Ethernet header."), // LinkType::DSA_TAG_EDSA
    (286, "Payload of lawful intercept packets using the ELEE protocol. The packet begins with the ELEE header; it does not include any transport-layer or lower-layer headers for protcols used to transport ELEE packets."), // LinkType::ELEE
    (287, "Serial frames transmitted between a host and a Z-Wave chip over an RS-232 or USB serial connection, as described in section 5 of the Z-Wave Serial API Host Application Programming Guide."), // LinkType::Z_WAVE_SERIAL
    (288, "USB 2.0, 1.1, or 1.0 packet, beginning with a PID, as described by Chapter 8 \"Protocol Layer\" of the the Universal Serial Bus Specification Revision 2.0."), // LinkType::USB_2_0
    (289, "ATSC Link-Layer Protocol frames, as described in section 5 of the A/330 Link-Layer Protocol specification, found at the ATSC 3.0 standards page, beginning with a Base Header."), // LinkType::ATSC_ALP
    (290, "Event Tracing for Windows messages, beginning with a pseudo-header."), // LinkType::ETW
    (292, "Serial NCP (Network Co-Processor) protocol for Zigbee stack ZBOSS by DSR. ZBOSS NCP protocol, beginning with a header"), // LinkType::ZBOSS_NCP
];

/// `LinkTypeDescriptions.at(type)` — empty for an unknown value,
/// where the C++ `std::map::at` would throw.
#[must_use]
pub fn link_type_description(network: u32) -> &'static str {
    LINK_TYPE_DESCRIPTIONS
        .iter()
        .find(|(value, _)| *value == network)
        .map_or("", |(_, text)| text)
}
