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

        // What a comment of the user is attached to: an instruction, a label or a local variable line. Unlike a line, an anchor does not
        // change when lines are added / removed (labels, variables) or hidden (collapsed zones), and it is saved as it is.
        // The addresses are relative to the first decoded instruction of the zone (as DissasmAsmPreCacheLine::address).
        struct DissasmCommentAnchor {
            enum class Kind : uint8 { Instruction = 0, Label = 1, Variable = 2 };
            Kind kind          = Kind::Instruction;
            uint64 address     = 0; // the instruction, the label or the start of the function of the variable
            int32 frameOffset  = 0; // Variable: the frame offset of the variable ([ebp - 8] -> -8)

            auto operator<=>(const DissasmCommentAnchor&) const = default;
        };

        // The comments of the user of a code zone, keyed by their anchors. The anchors that no line has (an analysis that does not find a
        // label / variable any more) keep their comments: they are shown again when the line comes back and they are always saved.
        struct DissasmUserComments {
            std::map<DissasmCommentAnchor, std::string> comments;

            bool Get(const DissasmCommentAnchor& anchor, std::string& comment) const;
            void Set(const DissasmCommentAnchor& anchor, std::string comment);
            bool Remove(const DissasmCommentAnchor& anchor);

            // [count] then count x [kind (uint8)][address (uint64)][frame offset (int32)][text size (uint32)][text]
            void ToBuffer(std::vector<std::byte>& buffer) const;
            bool LoadFromBuffer(const std::byte*& start, const std::byte* end);
        };

        // A cross reference: the instruction at `from` uses the address `to` (both in the address space of the labels: the VA, or the file
        // offset when the plugin has no translation). Computed by the analysis, never saved.
        enum class DissasmXrefKind : uint8 {
            Call,            // call to
            Jump,            // jmp to
            ConditionalJump, // jcc / loop to
            Read,            // reads the data at to (mov eax, [rip + ...])
            Write,           // writes the data at to
            Offset,          // takes the address (lea rcx, [rip + ...] / push offset / mov ecx, offset)
            Switch,          // a case of the jump table of an indirect jmp (switch)
        };
        struct DissasmXref {
            uint64 from;
            uint64 to;
            DissasmXrefKind kind;
        };
        struct DissasmXrefs {
            std::vector<DissasmXref> byTarget; // sorted by target, then by source (Finish)

            void Clear()
            {
                byTarget.clear();
            }
            void Add(uint64 from, uint64 to, DissasmXrefKind kind)
            {
                byTarget.push_back({ from, to, kind });
            }
            // sorts the references (and removes the duplicates) once they are all added
            void Finish();
            // the references to `target`, sorted by their source
            std::pair<std::vector<DissasmXref>::const_iterator, std::vector<DissasmXref>::const_iterator> To(uint64 target) const;
        };
        // "call", "jmp", "read", ... (the short text of the xrefs list)
        std::string_view GetXrefKindName(DissasmXrefKind kind);

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
            int32 stackOffset = 0;            // ARM64: sp - x29 in the body (the [sp, #n] slots); recomputed by the deep scan
            bool usesFrameRegister = true;    // ARM64: false for a function without x29 (offsets from the sp of the entry)
            uint8 frameRegister    = 0;       // 32 bit ARM: r11 (ARM mode) or r7 (Thumb)

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