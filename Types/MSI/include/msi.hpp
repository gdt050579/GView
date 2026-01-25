#pragma once
// msi.hpp
//
// Portable MSI metadata extractor (CFB reader + SummaryInformation parser).
// - No Windows APIs
// - Requires C++17
//
// Usage:
//   MSI::MSIFile msi(buffer_ptr, buffer_size);
//   if (!msi.IsValid()) ...;
//   auto meta = msi.GetMetadata(); // map<string,string>
//
// Notes:
//   - The Property table scanner is heuristic (search + extract) and not a full table parser.
//   - SummaryInformation parsing implements OLE property-set packet parsing for common types.

#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <optional>
#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace MSI
    {
        /* Basic typed stream result */
        struct Stream {
            std::string name; // UTF-8 name (decoded from directory)
            std::vector<uint8_t> data;
        };

        /* CFB / OLECF reader: exposes stream listing & retrieval */
        class CFBReader
        {
          public:
            CFBReader(const uint8_t* data, size_t size);
            bool Parse(); // parse header, FAT, directory. returns false if not a CFB.

            bool IsValid() const;
            std::vector<std::string> ListStreamNames() const;
            std::optional<Stream> GetStream(const std::string& utf8Name) const;

          private:
            const uint8_t* data_;
            size_t size_;
            bool valid_;

            // parsed fields
            uint32_t sector_size_;
            uint32_t mini_sector_size_;
            uint32_t sector_count_in_header_;
            uint32_t first_directory_sector_;
            uint32_t mini_stream_cutoff_size_;
            uint32_t first_mini_fat_sector_;
            uint32_t num_mini_fat_sectors_;
            uint32_t first_difat_sector_;
            uint32_t num_difat_sectors_;
            std::vector<uint32_t> difat_entries_; // FAT sector indexes
            std::vector<uint32_t> fat_;           // FAT array (sector->next sector)

            // directory entries parsed
            struct DirEntry {
                std::u16string name; // UTF-16
                uint8_t object_type;
                uint32_t starting_sector;
                uint64_t stream_size;
            };
            std::vector<DirEntry> dir_entries_;

            // helper internal parsing functions
            uint32_t ReadU32(size_t off) const;
            uint64_t ReadU64(size_t off) const;
            uint16_t ReadU16(size_t off) const;
            bool ReadHeader();
            bool BuildFAT();
            bool ReadDirectoryStream();
            std::vector<uint8_t> ReadFullStream(const DirEntry& e) const;
            std::string UTF16ToUTF8(const std::u16string& s) const;
        };

        /* MSIFile: high-level object that exposes metadata extraction */
        class MSIFile : public TypeInterface
        {
          public:
            MSIFile(const uint8_t* data, size_t size);

            bool IsValid() const;
            // returns a map of metadata keys/value strings (Title, Author, ProductName (heuristic), ProductVersion, Manufacturer, Comments, etc.)
            std::map<std::string, std::string> GetMetadata();

          private:
            CFBReader reader_;
            bool valid_;

            // parse property set (SummaryInformation) --> fills metadata map
            void ParseSummaryInformation(const std::vector<uint8_t>& blob, std::map<std::string, std::string>& out);

            // heuristic scan for the Property table stream (find "Property" stream and look for ASCII/UTF16 property names)
            void HeuristicScanPropertyStream(const std::vector<uint8_t>& blob, std::map<std::string, std::string>& out);

            // helpers
            static std::string TrimString(const std::string& s);
        };

    } // namespace MSI
} // namespace Type
} // namespace GView