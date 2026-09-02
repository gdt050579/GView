//! PCAP global header and packet-record walk.
//!
//! Spec `06_TYPE_PLUGINS` §PCAP Packet records; C++ `PCAPFile.cpp`
//! `Update`, `Internal.hpp` `Header` / `PacketHeader` / `Magic` /
//! `LinkType` / `Swap(Header&)`.
//!
//! [`PcapFile::parse_bytes`] / [`PcapFile::parse_cache`] are `Update()`:
//!
//! 1. the 24-byte global header is read at offset 0; when the magic is
//!    `Swapped` every field is byte-swapped (`Swap(header)`);
//! 2. the rest of the file is the packet area (`CopyToBuffer` from
//!    offset 24 to the end; the C++ fails when it is empty);
//! 3. packet headers are walked from offset 24: each record is
//!    `sizeof(PacketHeader) + origLen` bytes, until the offset reaches
//!    the file size.
//!
//! Parity notes (the C++ walk has two quirks that the spec's
//! `incl_len` description does not mention; C++ wins):
//!
//! - the walk advances by **`origLen`** (the wire length), not
//!   `inclLen` (the saved length), so captures with truncated packets
//!   desynchronise exactly as they do in the C++;
//! - packet headers are **never byte-swapped**, even for `Swapped`
//!   captures (only the global header is);
//! - the C++ `do { … } while` reads the record at the current offset
//!   without checking that 16 bytes remain; here the walk stops at the
//!   first header that cannot be read in full and the file is marked
//!   [`PcapFile::truncated`].

use gview_core::cache::DataCache;

/// `Magic::Identical`.
pub const MAGIC_IDENTICAL: u32 = 0xA1B2_C3D4;
/// `Magic::Swapped`.
pub const MAGIC_SWAPPED: u32 = 0xD4C3_B2A1;
/// `sizeof(Header)`.
pub const HEADER_SIZE: usize = 24;
/// `sizeof(PacketHeader)`.
pub const PACKET_HEADER_SIZE: usize = 16;
/// Seconds per day (timestamp formatting).
const SECONDS_PER_DAY: u64 = 86_400;

/// `MAC::LinkType` values with their `LinkTypeNames` (`Internal.hpp`).
pub const LINK_TYPE_NAMES: [(u32, &str); 132] = [
    (0, "NULL_"),
    (1, "ETHERNET"),
    (3, "AX25"),
    (6, "IEEE802_5"),
    (7, "ARCNET_BSD"),
    (8, "SLIP"),
    (9, "PPP"),
    (10, "FDDI"),
    (50, "PPP_HDLC"),
    (51, "PPP_ETHER"),
    (100, "ATM_RFC1483"),
    (101, "RAW"),
    (104, "C_HDLC"),
    (105, "IEEE802_11"),
    (107, "FRELAY"),
    (108, "LOOP"),
    (113, "LINUX_SLL"),
    (114, "LTALK"),
    (117, "PFLOG"),
    (119, "IEEE802_11_PRISM"),
    (122, "IP_OVER_FC"),
    (123, "SUNATM"),
    (127, "IEEE802_11_RADIOTAP"),
    (129, "ARCNET_LINUX"),
    (138, "APPLE_IP_OVER_IEEE1394"),
    (139, "MTP2_WITH_PHDR"),
    (140, "MTP2"),
    (141, "MTP3"),
    (142, "SCCP"),
    (143, "DOCSIS"),
    (144, "LINUX_IRDA"),
    (147, "USER0"),
    (148, "USER1"),
    (149, "USER2"),
    (150, "USER3"),
    (151, "USER4"),
    (152, "USER5"),
    (153, "USER6"),
    (154, "USER7"),
    (155, "USER8"),
    (156, "USER10"),
    (157, "USER11"),
    (158, "USER12"),
    (159, "USER13"),
    (160, "USER14"),
    (161, "USER15"),
    (162, "USER16"),
    (163, "IEEE802_11_AVS"),
    (165, "BACNET_MS_TP"),
    (166, "PPP_PPPD"),
    (169, "GPRS_LLC"),
    (170, "GPF_T"),
    (171, "GPF_F"),
    (177, "LINUX_LAPD"),
    (182, "MFR"),
    (187, "BLUETOOTH_HCI_H4"),
    (189, "USB_LINUX"),
    (192, "PPI"),
    (195, "IEEE802_15_4_WITHFCS"),
    (196, "SITA"),
    (197, "ERF"),
    (201, "BLUETOOTH_HCI_H4_WITH_PHDR"),
    (202, "AX25_KISS"),
    (203, "LAPD"),
    (204, "PPP_WITH_DIR"),
    (205, "C_HDLC_WITH_DIR"),
    (206, "FRELAY_WITH_DIR"),
    (207, "LAPB_WITH_DIR"),
    (209, "IPMB_LINUX"),
    (210, "FLEXRAY"),
    (212, "LIN"),
    (215, "IEEE802_15_4_NONASK_PHY"),
    (220, "USB_LINUX_MMAPPED"),
    (224, "FC_2"),
    (225, "FC_2_WITH_FRAME_DELIMS"),
    (226, "IPNET"),
    (227, "CAN_SOCKETCAN"),
    (228, "IPV4"),
    (229, "IPV6"),
    (230, "IEEE802_15_4_NOFCS"),
    (231, "DBUS"),
    (235, "DVB_CI"),
    (236, "MUX27010"),
    (237, "STANAG_5066_D_PDU"),
    (239, "NFLOG"),
    (240, "NETANALYZER"),
    (241, "NETANALYZER_TRANSPARENT"),
    (242, "IPOIB"),
    (243, "MPEG_2_TS"),
    (244, "NG40"),
    (245, "NFC_LLCP"),
    (247, "INFINIBAND"),
    (248, "SCTP"),
    (249, "USBPCAP"),
    (250, "RTAC_SERIAL"),
    (251, "BLUETOOTH_LE_LL"),
    (253, "NETLINK"),
    (254, "BLUETOOTH_LINUX_MONITOR"),
    (255, "BLUETOOTH_BREDR_BB"),
    (256, "BLUETOOTH_LE_LL_WITH_PHDR"),
    (257, "PROFIBUS_DL"),
    (258, "PKTAP"),
    (259, "EPON"),
    (260, "IPMI_HPM_2"),
    (261, "ZWAVE_R1_R2"),
    (262, "ZWAVE_R3"),
    (263, "WATTSTOPPER_DLM"),
    (264, "ISO_14443"),
    (265, "RDS"),
    (266, "USB_DARWIN"),
    (268, "SDLC"),
    (270, "LORATAP"),
    (271, "VSOCK"),
    (272, "NORDIC_BLE"),
    (273, "DOCSIS31_XRA31"),
    (274, "ETHERNET_MPACKET"),
    (275, "DISPLAYPORT_AUX"),
    (276, "LINUX_SLL2"),
    (278, "OPENVIZSLA"),
    (279, "EBHSCR"),
    (280, "VPP_DISPATCH"),
    (281, "DSA_TAG_BRCM"),
    (282, "DSA_TAG_BRCM_PREPEND"),
    (283, "IEEE802_15_4_TAP"),
    (284, "DSA_TAG_DSA"),
    (285, "DSA_TAG_EDSA"),
    (286, "ELEE"),
    (287, "Z_WAVE_SERIAL"),
    (288, "USB_2_0"),
    (289, "ATSC_ALP"),
    (290, "ETW"),
    (292, "ZBOSS_NCP"),
];

/// `LinkTypeNames.at(type)` (empty for an unknown value, where the C++
/// `std::map::at` would throw).
#[must_use]
pub fn link_type_name(network: u32) -> &'static str {
    LINK_TYPE_NAMES
        .iter()
        .find(|(value, _)| *value == network)
        .map_or("", |(_, name)| name)
}

/// `MagicNames.at(magic)`.
#[must_use]
pub const fn magic_name(magic: u32) -> &'static str {
    match magic {
        MAGIC_IDENTICAL => "Identical",
        MAGIC_SWAPPED => "Swapped",
        _ => "",
    }
}

/// `PCAP::Header` after the optional swap.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GlobalHeader {
    /// `magicNumber`.
    pub magic: u32,
    /// `versionMajor`.
    pub version_major: u16,
    /// `versionMinor`.
    pub version_minor: u16,
    /// `thiszone`.
    pub thiszone: i32,
    /// `sigfigs`.
    pub sigfigs: u32,
    /// `snaplen`.
    pub snaplen: u32,
    /// `network` (`LinkType`).
    pub network: u32,
}

/// `PCAP::PacketHeader` (raw, never swapped — C++ parity).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketHeader {
    /// `tsSec`.
    pub ts_sec: u32,
    /// `tsUsec`.
    pub ts_usec: u32,
    /// `inclLen`.
    pub incl_len: u32,
    /// `origLen`.
    pub orig_len: u32,
}

impl PacketHeader {
    /// `sizeof(PacketHeader) + inclLen` — the record's zone size.
    #[must_use]
    pub const fn record_size(&self) -> u64 {
        (PACKET_HEADER_SIZE as u64).saturating_add(self.incl_len as u64)
    }

    /// `tsSec * 1000000 + tsUsec`, divided back to whole seconds — the
    /// C++ `timestamp` fed to `DateTime::CreateFromTimestamp`.
    #[must_use]
    pub const fn timestamp_seconds(&self) -> u64 {
        let micros = (self.ts_sec as u64).saturating_mul(1_000_000).saturating_add(self.ts_usec as u64);
        micros / 1_000_000
    }
}

/// One entry of C++ `packetHeaders`: the header and its file offset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketRecord {
    /// The packet header as stored.
    pub header: PacketHeader,
    /// File offset of the packet header.
    pub offset: u64,
}

/// Failures of `Update()` (C++ `return false`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcapError {
    /// The 24-byte global header cannot be read.
    Header,
    /// No packet data after the header (`CopyToBuffer` invalid).
    NoData,
}

impl core::fmt::Display for PcapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Header => f.write_str("PCAP global header truncated"),
            Self::NoData => f.write_str("PCAP file has no packet data"),
        }
    }
}

impl std::error::Error for PcapError {}

fn u16_at(buf: &[u8], at: usize) -> Option<u16> {
    let b = buf.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([*b.first()?, *b.get(1)?]))
}

fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    let b = buf.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?]))
}

/// Whether the on-disk magic is `Swapped` (the fields need swapping).
#[must_use]
pub fn is_swapped(buf: &[u8]) -> bool {
    u32_at(buf, 0) == Some(MAGIC_SWAPPED)
}

/// Reads the global header from its 24 bytes (`Copy<Header>` then
/// `Swap` when the magic says so).
#[must_use]
pub fn read_global_header(buf: &[u8]) -> Option<GlobalHeader> {
    let magic = u32_at(buf, 0)?;
    let swap = magic == MAGIC_SWAPPED;
    let s16 = |v: u16| if swap { v.swap_bytes() } else { v };
    let s32 = |v: u32| if swap { v.swap_bytes() } else { v };
    Some(GlobalHeader {
        magic: s32(magic),
        version_major: s16(u16_at(buf, 4)?),
        version_minor: s16(u16_at(buf, 6)?),
        thiszone: s32(u32_at(buf, 8)?).cast_signed(),
        sigfigs: s32(u32_at(buf, 12)?),
        snaplen: s32(u32_at(buf, 16)?),
        network: s32(u32_at(buf, 20)?),
    })
}

/// Reads a packet header at `at` (never swapped).
#[must_use]
pub fn read_packet_header(buf: &[u8], at: usize) -> Option<PacketHeader> {
    Some(PacketHeader {
        ts_sec: u32_at(buf, at)?,
        ts_usec: u32_at(buf, at.checked_add(4)?)?,
        incl_len: u32_at(buf, at.checked_add(8)?)?,
        orig_len: u32_at(buf, at.checked_add(12)?)?,
    })
}

/// C++ `PCAPFile` parse state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PcapFile {
    /// `header` (swapped into host order when needed).
    pub header: GlobalHeader,
    /// Whether the on-disk magic was `Swapped`.
    pub swapped: bool,
    /// `packetHeaders`.
    pub packets: Vec<PacketRecord>,
    /// Total file size.
    pub file_size: u64,
    /// The walk stopped at a record whose header does not fit (the C++
    /// would read past the buffer).
    pub truncated: bool,
}

impl PcapFile {
    /// C++ `Update()` over the object's cache.
    ///
    /// # Errors
    ///
    /// [`PcapError`] when the header or the packet area cannot be read.
    pub fn parse_cache(cache: &mut DataCache) -> Result<Self, PcapError> {
        let size = cache.size();
        let head = cache.copy_to_vec(0, HEADER_SIZE as u32, true).map_err(|_| PcapError::Header)?;
        let header = read_global_header(&head).ok_or(PcapError::Header)?;
        let swapped = is_swapped(&head);
        let rest = size.saturating_sub(HEADER_SIZE as u64);
        let rest = u32::try_from(rest).map_err(|_| PcapError::NoData)?;
        if rest == 0 {
            return Err(PcapError::NoData);
        }
        let data = cache
            .copy_to_vec(HEADER_SIZE as u64, rest, true)
            .map_err(|_| PcapError::NoData)?;
        Ok(Self::walk(header, swapped, &data, size))
    }

    /// C++ `Update()` over an in-memory capture.
    ///
    /// # Errors
    ///
    /// As [`Self::parse_cache`].
    pub fn parse_bytes(bytes: &[u8]) -> Result<Self, PcapError> {
        let header = read_global_header(bytes).ok_or(PcapError::Header)?;
        let data = bytes.get(HEADER_SIZE..).ok_or(PcapError::Header)?;
        if data.is_empty() {
            return Err(PcapError::NoData);
        }
        Ok(Self::walk(header, is_swapped(bytes), data, bytes.len() as u64))
    }

    /// The packet-record walk (`do { … } while (offset < size)`), with
    /// the C++ `origLen` stride.
    fn walk(header: GlobalHeader, swapped: bool, data: &[u8], file_size: u64) -> Self {
        let mut file = Self {
            header,
            swapped,
            packets: Vec::new(),
            file_size,
            truncated: false,
        };
        let mut offset = HEADER_SIZE as u64;
        while let Some(local) = offset.checked_sub(HEADER_SIZE as u64).and_then(|o| usize::try_from(o).ok()) {
            let Some(packet) = read_packet_header(data, local) else {
                file.truncated = true;
                break;
            };
            file.packets.push(PacketRecord { header: packet, offset });
            offset = offset
                .saturating_add(PACKET_HEADER_SIZE as u64)
                .saturating_add(u64::from(packet.orig_len));
            if offset >= file_size {
                break;
            }
        }
        file
    }

    /// `packetHeaders.size()`.
    #[must_use]
    pub const fn packet_count(&self) -> usize {
        self.packets.len()
    }

    /// `LinkTypeNames.at(header.network)`.
    #[must_use]
    pub fn network_name(&self) -> &'static str {
        link_type_name(self.header.network)
    }
}

/// `DateTime::CreateFromTimestamp(seconds).GetStringRepresentation()`
/// as `YYYY-MM-DD HH:MM:SS`. The C++ converts with `localtime`; this
/// port renders UTC (no time-zone database without extra crates).
#[must_use]
pub fn format_timestamp(seconds: u64) -> String {
    let days = seconds / SECONDS_PER_DAY;
    let rem = seconds % SECONDS_PER_DAY;
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

/// Days since 1970-01-01 to a proleptic Gregorian civil date
/// (Howard Hinnant's `civil_from_days`, non-negative days only).
const fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days.saturating_add(719_468);
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe.saturating_sub(doe / 1460).saturating_add(doe / 36_524).saturating_sub(doe / 146_096)) / 365;
    let y = yoe.saturating_add(era.saturating_mul(400));
    let doy = doe.saturating_sub(365_u64.saturating_mul(yoe).saturating_add(yoe / 4).saturating_sub(yoe / 100));
    let mp = (5_u64.saturating_mul(doy).saturating_add(2)) / 153;
    let d = doy.saturating_sub((153_u64.saturating_mul(mp).saturating_add(2)) / 5).saturating_add(1);
    let m = if mp < 10 { mp.saturating_add(3) } else { mp.saturating_sub(9) };
    let year = if m <= 2 { y.saturating_add(1) } else { y };
    (year, m, d)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::must_use_candidate,
    clippy::similar_names
)]
pub mod tests {
    use super::*;
    use gview_core::object::Object;

    /// A global header: `(magic bytes on disk, version, network)`.
    pub fn global_header(big_endian: bool, network: u32, snaplen: u32) -> Vec<u8> {
        let mut h = Vec::new();
        let half = |h: &mut Vec<u8>, v: u16| {
            if big_endian {
                h.extend_from_slice(&v.to_be_bytes());
            } else {
                h.extend_from_slice(&v.to_le_bytes());
            }
        };
        let word = |h: &mut Vec<u8>, v: u32| {
            if big_endian {
                h.extend_from_slice(&v.to_be_bytes());
            } else {
                h.extend_from_slice(&v.to_le_bytes());
            }
        };
        word(&mut h, MAGIC_IDENTICAL);
        half(&mut h, 2);
        half(&mut h, 4);
        word(&mut h, 0xFFFF_F1F0); // thiszone = -3600
        word(&mut h, 0);
        word(&mut h, snaplen);
        word(&mut h, network);
        h
    }

    /// A packet record (little-endian header, as every writer emits it).
    pub fn packet(ts_sec: u32, ts_usec: u32, incl_len: u32, orig_len: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&ts_sec.to_le_bytes());
        p.extend_from_slice(&ts_usec.to_le_bytes());
        p.extend_from_slice(&incl_len.to_le_bytes());
        p.extend_from_slice(&orig_len.to_le_bytes());
        p.extend_from_slice(payload);
        p
    }

    /// Ethernet capture with three complete packets.
    pub fn sample() -> Vec<u8> {
        let mut image = global_header(false, 1, 65_535);
        image.extend(packet(1_700_000_000, 5, 60, 60, &[0xAA; 60]));
        image.extend(packet(1_700_000_001, 999_999, 42, 42, &[0xBB; 42]));
        image.extend(packet(1_700_000_002, 0, 14, 14, &[0xCC; 14]));
        image
    }

    #[test]
    fn walks_records_and_reads_the_global_header() {
        let image = sample();
        let pcap = PcapFile::parse_bytes(&image).expect("parse");
        assert_eq!(pcap.header.magic, MAGIC_IDENTICAL);
        assert!(!pcap.swapped);
        assert_eq!(pcap.header.version_major, 2);
        assert_eq!(pcap.header.version_minor, 4);
        assert_eq!(pcap.header.thiszone, -3600);
        assert_eq!(pcap.header.snaplen, 65_535);
        assert_eq!(pcap.header.network, 1);
        assert_eq!(pcap.network_name(), "ETHERNET");
        assert_eq!(pcap.packet_count(), 3);
        assert_eq!(pcap.packets[0].offset, 24);
        assert_eq!(pcap.packets[0].header.incl_len, 60);
        assert_eq!(pcap.packets[0].header.record_size(), 76);
        assert_eq!(pcap.packets[1].offset, 24 + 16 + 60);
        assert_eq!(pcap.packets[1].header.ts_usec, 999_999);
        assert_eq!(pcap.packets[2].offset, 24 + 16 + 60 + 16 + 42);
        assert_eq!(pcap.file_size, image.len() as u64);
        assert!(!pcap.truncated);
        assert_eq!(pcap.packets[0].header.timestamp_seconds(), 1_700_000_000);
        assert_eq!(pcap.packets[1].header.timestamp_seconds(), 1_700_000_001);

        let mut object = Object::from_buffer(&image, "c.pcap", 0);
        assert_eq!(PcapFile::parse_cache(object.data_mut()).expect("cache"), pcap);
    }

    #[test]
    fn swapped_captures_swap_the_global_header_only() {
        let mut image = global_header(true, 101, 0x100);
        image.extend(packet(7, 8, 4, 4, &[1, 2, 3, 4]));
        let pcap = PcapFile::parse_bytes(&image).expect("parse");
        assert!(pcap.swapped);
        assert_eq!(pcap.header.magic, MAGIC_IDENTICAL, "swapped back into host order");
        assert_eq!(pcap.header.version_major, 2);
        assert_eq!(pcap.header.snaplen, 0x100);
        assert_eq!(pcap.header.network, 101);
        assert_eq!(pcap.header.thiszone, -3600);
        assert_eq!(pcap.network_name(), "RAW");
        // Packet headers are read raw (C++ parity).
        assert_eq!(pcap.packets[0].header.ts_sec, 7);
        assert_eq!(pcap.packets[0].header.orig_len, 4);
        assert_eq!(magic_name(MAGIC_SWAPPED), "Swapped");
        assert_eq!(magic_name(MAGIC_IDENTICAL), "Identical");
        assert_eq!(magic_name(1), "");
    }

    #[test]
    fn walk_advances_by_orig_len_like_the_cpp() {
        // A truncated packet: 10 bytes saved of a 100-byte frame.
        let mut image = global_header(false, 1, 10);
        image.extend(packet(1, 0, 10, 100, &[0; 10]));
        image.extend(packet(2, 0, 10, 100, &[0; 10]));
        let pcap = PcapFile::parse_bytes(&image).expect("parse");
        // The C++ stride is 16 + origLen = 116, so the second record
        // is skipped and the walk lands past the end.
        assert_eq!(pcap.packet_count(), 1);
        assert_eq!(pcap.packets[0].offset, 24);
        assert!(!pcap.truncated, "the walk ended by offset >= size");
    }

    #[test]
    fn truncated_files_stop_cleanly() {
        assert_eq!(PcapFile::parse_bytes(&[]), Err(PcapError::Header));
        assert_eq!(PcapFile::parse_bytes(&global_header(false, 1, 1)[..20]), Err(PcapError::Header));
        // Exactly the header: the C++ CopyToBuffer(24, 0) fails.
        assert_eq!(PcapFile::parse_bytes(&global_header(false, 1, 1)), Err(PcapError::NoData));
        let mut object = Object::from_buffer(&global_header(false, 1, 1), "h.pcap", 0);
        assert_eq!(PcapFile::parse_cache(object.data_mut()), Err(PcapError::NoData));
        // A record header cut short: one packet, then truncated.
        let mut image = global_header(false, 1, 1);
        image.extend(packet(1, 0, 4, 4, &[9; 4]));
        image.extend_from_slice(&[1, 2, 3]);
        let pcap = PcapFile::parse_bytes(&image).expect("parse");
        assert_eq!(pcap.packet_count(), 1);
        assert!(pcap.truncated);
        // A header claiming more payload than present is still listed.
        let mut image = global_header(false, 1, 1);
        image.extend(packet(1, 0, 0x1000, 0x1000, &[9; 4]));
        let pcap = PcapFile::parse_bytes(&image).expect("parse");
        assert_eq!(pcap.packet_count(), 1);
        assert!(!pcap.truncated);
        // Huge origLen: the offset saturates and the loop ends.
        let mut image = global_header(false, 1, 1);
        image.extend(packet(1, 0, 4, u32::MAX, &[9; 4]));
        assert_eq!(PcapFile::parse_bytes(&image).expect("parse").packet_count(), 1);
        assert_eq!(PcapError::NoData.to_string(), "PCAP file has no packet data");
    }

    #[test]
    fn link_type_table_and_timestamps() {
        assert_eq!(link_type_name(0), "NULL_");
        assert_eq!(link_type_name(1), "ETHERNET");
        assert_eq!(link_type_name(113), "LINUX_SLL");
        assert_eq!(link_type_name(292), "ZBOSS_NCP");
        assert_eq!(link_type_name(2), "");
        assert_eq!(LINK_TYPE_NAMES.len(), 132);
        assert_eq!(format_timestamp(0), "1970-01-01 00:00:00");
        assert_eq!(format_timestamp(86_399), "1970-01-01 23:59:59");
        assert_eq!(format_timestamp(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(format_timestamp(1_700_000_000), "2023-11-14 22:13:20");
        assert_eq!(format_timestamp(4_102_444_800), "2100-01-01 00:00:00");
        let header = PacketHeader {
            ts_sec: u32::MAX,
            ts_usec: u32::MAX,
            incl_len: 1,
            orig_len: 1,
        };
        assert_eq!(header.timestamp_seconds(), (u64::from(u32::MAX) * 1_000_000 + u64::from(u32::MAX)) / 1_000_000);
        assert_eq!(read_packet_header(&[0; 15], 0), None);
        assert_eq!(read_global_header(&[0; 23]), None);
    }
}
