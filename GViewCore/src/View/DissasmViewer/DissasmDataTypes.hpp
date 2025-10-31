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
            uint32 line;
            uint32 offset;

            bool operator==(const LinePosition& other) const
            {
                return line == other.line && offset == other.offset;
            }

            bool operator>(const LinePosition& other) const
            {
                return line > other.line || line == other.line && offset > other.offset;
            }

            bool operator>=(const LinePosition& other) const
            {
                return line > other.line || line == other.line && offset >= other.offset;
            }

            bool operator<(const LinePosition& other) const
            {
                return line < other.line || line == other.line && offset < other.offset;
            }

            bool operator<=(const LinePosition& other) const
            {
                return line < other.line || line == other.line && offset <= other.offset;
            }
        };

        struct AnnotationContainer {
            using AnnoationCallNameType   = std::string;
            using AnnoationCallValueType  = uint64;
            using AnnoationLineNumberType = uint32;
            using AnnotationDetails       = std::pair<AnnoationCallNameType, AnnoationCallValueType>;
            using AnnotationMap           = std::map<AnnoationLineNumberType, AnnotationDetails>;

            using value_type     = typename AnnotationMap::value_type;
            using iterator       = typename AnnotationMap::iterator;
            using const_iterator = typename AnnotationMap::const_iterator;
            using mapped_type    = typename AnnotationMap::mapped_type;
            using key_type       = typename AnnotationMap::key_type;

            AnnotationMap mappings;
            std::unordered_map<std::string, std::string> initial_name_to_current_name;
            std::unordered_map<std::string, std::string> current_name_to_initial_name;

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

            bool add_name_change(const std::string& initial_name, const std::string& new_name)
            {
                if (current_name_to_initial_name.contains(new_name))
                    return false;
                auto name_link = current_name_to_initial_name[initial_name];
                current_name_to_initial_name.erase(initial_name);

                initial_name_to_current_name[name_link] = new_name;
                current_name_to_initial_name[new_name]  = name_link;
                return true;
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
            void LoadFromBuffer(const std::byte*& start, const std::byte* end);
        };
    } // namespace DissasmViewer
} // namespace View
} // namespace GView