#pragma once

#include "Internal.hpp"

namespace GView
{
namespace View
{
    namespace DissasmViewer
    {
        struct LinePosition
        {
            uint32 line{ 0 };
            uint32 offset{ 0 };

            constexpr LinePosition(uint32 l = 0, uint32 o = 0) : line(l), offset(o) {}

            bool operator==(const LinePosition& other) const
            {
                return line == other.line && offset == other.offset;
            }

            bool operator>(const LinePosition& other) const
            {
                return line > other.line || (line == other.line && offset > other.offset);
            }

            bool operator>=(const LinePosition& other) const
            {
                return line > other.line || (line == other.line && offset >= other.offset);
            }

            bool operator<(const LinePosition& other) const
            {
                return line < other.line || (line == other.line && offset < other.offset);
            }

            bool operator<=(const LinePosition& other) const
            {
                return line < other.line || (line == other.line && offset <= other.offset);
            }
        };

        struct DissasmComments {
            std::map<uint32, std::string> comments;

            void AddOrUpdateComment(uint32 line, std::string comment);

            bool GetComment(uint32 line, std::string& comment) const;
            bool HasComment(uint32 line) const;
            void RemoveComment(uint32 line);
            void AdjustCommentsOffsets(uint32 changedLine, bool isAddedLine);
            // drops the comment of `line` and moves every comment placed after it one line up
            void RemoveLine(uint32 line);

            uint32 GetRequiredSizeForSerialization() const;
            void ToBuffer(std::vector<std::byte>& buffer) const;
            bool LoadFromBuffer(const std::byte*& start, const std::byte* end);
        };

        struct AnnotationContainer {
            using AnnoationCallNameType   = std::string;
            using AnnoationCallValueType  = uint64;
            using AnnoationLineNumberType = uint32;
            using AnnotationDetails       = std::pair<AnnoationCallNameType, AnnoationCallValueType>;
            using AnnotationMap           = std::map<AnnoationLineNumberType, AnnotationDetails>;
            using MapNameLinkType         = std::unordered_map<std::string, std::string>;

            using value_type     = typename AnnotationMap::value_type;
            using iterator       = typename AnnotationMap::iterator;
            using const_iterator = typename AnnotationMap::const_iterator;
            using mapped_type    = typename AnnotationMap::mapped_type;
            using key_type       = typename AnnotationMap::key_type;

            AnnotationMap mappings;
            MapNameLinkType initial_name_to_current_name;
            MapNameLinkType current_name_to_initial_name;

            std::size_t size() const
            {
                return mappings.size();
            }

            // auto begin() const
            //{
            //     return mappings.begin();
            // }

            auto end() const
            {
                return mappings.end();
            }

            std::pair<iterator, bool> insert(const value_type& v)
            {
                return mappings.insert(v);
            }

            template <class P, std::enable_if_t<std::is_constructible_v<value_type, P&&>, int> = 0>
            std::pair<iterator, bool> insert(P&& v)
            {
                return mappings.insert(std::forward<P>(v));
            }

            template <class InputIt>
            void insert(InputIt first, InputIt last)
            {
                mappings.insert(first, last);
            }

            mapped_type& operator[](const key_type& k)
            {
                return mappings[k];
            }
            mapped_type& operator[](key_type&& k)
            {
                return mappings[std::move(k)];
            }

            bool contains(const key_type& k) const
            {
                return mappings.contains(k);
            }

            iterator find(const key_type& k)
            {
                return mappings.find(k);
            }
            const_iterator find(const key_type& k) const
            {
                return mappings.find(k);
            }

            void add_initial_name(const std::string& initial_name)
            {
                initial_name_to_current_name.insert({ initial_name, initial_name });
                current_name_to_initial_name.insert({ initial_name, initial_name });
            }

            bool add_name_change(const std::string& initial_name, const std::string& new_name, AnnoationLineNumberType line)
            {
                if (current_name_to_initial_name.contains(new_name))
                    return false;
                auto name_link = current_name_to_initial_name[initial_name];
                current_name_to_initial_name.erase(initial_name);

                initial_name_to_current_name[name_link] = new_name;
                current_name_to_initial_name[new_name]  = name_link;
                mappings.at(line).first                 = new_name;
                return true;
            }

            bool contains_annotation_name(const std::string& name) const
            {
                return current_name_to_initial_name.contains(name);
            }

            std::optional<AnnoationLineNumberType> get_line_by_annotation_name(const std::string& name) const
            {
                if (!contains_annotation_name(name))
                    return {};
                for (const auto& [line, details] : mappings) {
                    if (details.first == name)
                        return line;
                }
                return {};
            }


            std::string get_name_change(const std::string& initial_name) const
            {
                auto it = initial_name_to_current_name.find(initial_name);
                if (it != initial_name_to_current_name.end())
                    return it->second;
                return {};
            }

            void populate_annotations_from_other_storage(const AnnotationContainer& other)
            {
                mappings.insert(other.mappings.begin(), other.mappings.end());
                initial_name_to_current_name.insert(other.initial_name_to_current_name.begin(), other.initial_name_to_current_name.end());
                current_name_to_initial_name.insert(other.current_name_to_initial_name.begin(), other.current_name_to_initial_name.end());
            }

            uint32 GetRequiredSizeForSerialization() const;
            void ToBuffer(std::vector<std::byte>& buffer) const;
            bool LoadFromBuffer(const std::byte*& start, const std::byte* end);
        };

        constexpr uint32 DISSASM_MAX_LOCAL_VARIABLES_PER_FUNCTION = 512;
        constexpr uint32 DISSASM_MAX_LOCAL_VARIABLE_NAME_SIZE     = 128;

        // A stack slot addressed through the frame register ([ebp - 8] / [rbp + 0x10]) inside a function.
        struct DissasmLocalVariable {
            int32 frameOffset; // signed displacement relative to the frame register: [ebp - 8] -> -8
            uint16 size;       // widest access in bytes, 0 when only its address is taken (lea)
            std::string name;
        };

        // Frame of a function that uses a frame pointer (push ebp; mov ebp, esp). Addresses use the same base as the instructions drawn
        // in the code zone (relative to the first decoded instruction) and as the annotation values.
        struct DissasmFunctionFrame {
            uint64 startAddress;
            uint64 endAddress;                           // exclusive
            std::vector<DissasmLocalVariable> variables; // sorted by frameOffset, unique offsets and names

            DissasmLocalVariable* FindVariable(int32 frameOffset);
            const DissasmLocalVariable* FindVariable(int32 frameOffset) const;
            bool HasVariableNamed(std::string_view name) const;
        };

        struct DissasmLocalVariables {
            std::vector<DissasmFunctionFrame> functions; // sorted by startAddress, ranges never overlap

            bool Empty() const
            {
                return functions.empty();
            }
            const DissasmFunctionFrame* FindFunctionByAddress(uint64 address) const; // function whose [start, end) contains address
            DissasmFunctionFrame* FindFunctionByStart(uint64 startAddress);
            const DissasmFunctionFrame* FindFunctionByStart(uint64 startAddress) const;

            void ToBuffer(std::vector<std::byte>& buffer) const;
            bool LoadFromBuffer(const std::byte*& start, const std::byte* end);
        };

        // Lines that describe a local variable are stored as annotations (text lines) so they follow the existing line bookkeeping
        // (collapsible zones, comments, cache). They are told apart from labels by an empty name (labels can never be renamed to an
        // empty name) and their value packs the owning function start (low 32 bits) and the frame offset (high 32 bits).
        inline AnnotationContainer::AnnoationCallValueType PackLocalVariableAnnotation(uint64 functionStart, int32 frameOffset)
        {
            return (static_cast<uint64>(static_cast<uint32>(frameOffset)) << 32) | (functionStart & 0xFFFFFFFFull);
        }
        inline bool IsLocalVariableAnnotation(const AnnotationContainer::AnnotationDetails& details)
        {
            return details.first.empty();
        }
        inline uint64 GetLocalVariableAnnotationFunction(AnnotationContainer::AnnoationCallValueType value)
        {
            return value & 0xFFFFFFFFull;
        }
        inline int32 GetLocalVariableAnnotationOffset(AnnotationContainer::AnnoationCallValueType value)
        {
            return static_cast<int32>(static_cast<uint32>(value >> 32));
        }

    } // namespace DissasmViewer
} // namespace View
} // namespace GView