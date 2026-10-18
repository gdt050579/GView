#include "DissasmObjC.hpp"

#include <unordered_map>
#include <unordered_set>

using namespace GView::View::DissasmViewer;

namespace
{
constexpr uint64 OBJC_FAST_DATA_MASK     = 0x00007FFFFFFFFFF8ull; // class_t::data: the class_ro_t, the low bits are flags
constexpr uint32 METHOD_LIST_RELATIVE    = 0x80000000u;          // the entries are 32 bit offsets from their fields
constexpr uint32 METHOD_LIST_DIRECT_SELS = 0x40000000u;          // relative entries whose name offset points to the string (the shared cache)
constexpr uint32 METHOD_LIST_ENTSIZE     = 0x0000FFFCu;
constexpr uint32 MAX_METHODS             = 0x10000;
constexpr uint64 MAX_LIST_ENTRIES        = 0x100000;

class ObjCParser
{
    const ObjCMemory& memory;
    ObjCMetadata& metadata;
    std::unordered_set<uint64> parsedClasses;
    std::unordered_map<uint64, std::string> classNames;

  public:
    ObjCParser(const ObjCMemory& memory, ObjCMetadata& metadata) : memory(memory), metadata(metadata)
    {
    }

    uint64 Pointer(uint64 address) const
    {
        const auto value = memory.readPointer ? memory.readPointer(address) : std::nullopt;
        return value.value_or(0);
    }

    // the class_ro_t of a class_t (data, at +32)
    uint64 ReadOnlyData(uint64 classAddress) const
    {
        return Pointer(classAddress + 32) & OBJC_FAST_DATA_MASK;
    }

    // the name of a class_t (class_ro_t::name, at +24); an imported class: the name of its bind
    std::string ClassName(uint64 classAddress, uint64 pointerAddress)
    {
        if (classAddress == 0) {
            std::string symbol = memory.bindName ? memory.bindName(pointerAddress) : std::string();
            for (const std::string_view prefix : { "_OBJC_CLASS_$_", "OBJC_CLASS_$_" })
                if (symbol.starts_with(prefix))
                    return symbol.substr(prefix.size());
            return symbol;
        }
        if (const auto known = classNames.find(classAddress); known != classNames.end())
            return known->second;
        const uint64 readOnly = ReadOnlyData(classAddress);
        std::string name      = readOnly != 0 ? memory.readString(Pointer(readOnly + 24)) : std::string();
        classNames[classAddress] = name;
        return name;
    }

    // the selector of a method entry
    std::string Selector(uint64 entry, bool relative, bool directSelectors) const
    {
        if (!relative)
            return memory.readString(Pointer(entry));
        const auto offset = memory.readU32(entry);
        if (!offset.has_value())
            return {};
        const uint64 target = entry + static_cast<uint64>(static_cast<int64>(static_cast<int32>(offset.value())));
        return directSelectors ? memory.readString(target) : memory.readString(Pointer(target));
    }

    void ParseMethodList(uint64 list, const std::string& owner, bool isClassMethod, std::string listName)
    {
        if (list == 0 || owner.empty())
            return;
        metadata.structures.emplace_back(list, std::move(listName));
        const auto flags = memory.readU32(list);
        const auto count = memory.readU32(list + 4);
        if (!flags.has_value() || !count.has_value() || count.value() > MAX_METHODS)
            return;
        const bool relative = (flags.value() & METHOD_LIST_RELATIVE) != 0;
        const bool direct   = (flags.value() & METHOD_LIST_DIRECT_SELS) != 0;
        const uint32 size   = flags.value() & METHOD_LIST_ENTSIZE;
        if (size < (relative ? 12u : 24u))
            return;
        for (uint32 index = 0; index < count.value(); index++) {
            const uint64 entry = list + 8 + static_cast<uint64>(index) * size;
            uint64 implementation = 0;
            if (relative) {
                const auto offset = memory.readU32(entry + 8);
                if (!offset.has_value())
                    continue;
                implementation = entry + 8 + static_cast<uint64>(static_cast<int64>(static_cast<int32>(offset.value())));
            } else
                implementation = Pointer(entry + 16);
            const std::string selector = Selector(entry, relative, direct);
            if (implementation == 0 || selector.empty())
                continue;
            metadata.methods.emplace_back(implementation, std::string(isClassMethod ? "+[" : "-[") + owner + " " + selector + "]");
        }
    }

    // the instance methods of a class (class_ro_t::baseMethods, at +32), the class methods of its metaclass (isa)
    void ParseClass(uint64 classAddress)
    {
        if (classAddress == 0 || !parsedClasses.insert(classAddress).second)
            return;
        const std::string name = ClassName(classAddress, 0);
        if (name.empty())
            return;
        metadata.structures.emplace_back(classAddress, "_OBJC_CLASS_$_" + name);
        metadata.structures.emplace_back(ReadOnlyData(classAddress), "__OBJC_CLASS_RO_$_" + name);
        ParseMethodList(Pointer(ReadOnlyData(classAddress) + 32), name, false, "__OBJC_$_INSTANCE_METHODS_" + name);
        const uint64 metaclass = Pointer(classAddress);
        if (metaclass != 0 && metaclass != classAddress && parsedClasses.insert(metaclass).second) {
            metadata.structures.emplace_back(metaclass, "_OBJC_METACLASS_$_" + name);
            metadata.structures.emplace_back(ReadOnlyData(metaclass), "__OBJC_METACLASS_RO_$_" + name);
            ParseMethodList(Pointer(ReadOnlyData(metaclass) + 32), name, true, "__OBJC_$_CLASS_METHODS_" + name);
        }
    }

    // category_t: name, cls, instanceMethods, classMethods (the methods are named -[Class(Category) selector])
    void ParseCategory(uint64 category)
    {
        if (category == 0)
            return;
        const std::string name      = memory.readString(Pointer(category));
        const std::string className = ClassName(Pointer(category + 8), category + 8);
        if (className.empty())
            return;
        const std::string owner  = name.empty() ? className : className + "(" + name + ")";
        const std::string suffix = className + "_$_" + name;
        metadata.structures.emplace_back(category, "__OBJC_$_CATEGORY_" + suffix);
        ParseMethodList(Pointer(category + 16), owner, false, "__OBJC_$_CATEGORY_INSTANCE_METHODS_" + suffix);
        ParseMethodList(Pointer(category + 24), owner, true, "__OBJC_$_CATEGORY_CLASS_METHODS_" + suffix);
    }

    template <typename Callback>
    static void ForEachPointer(const std::vector<ObjCSection>& sections, Callback&& callback)
    {
        for (const auto& section : sections)
            for (uint64 offset = 0; offset + 8 <= section.size && offset / 8 < MAX_LIST_ENTRIES; offset += 8)
                callback(section.address + offset);
    }

    void Parse(const ObjCSections& sections)
    {
        ForEachPointer(sections.classLists, [this](uint64 slot) { ParseClass(Pointer(slot)); });
        ForEachPointer(sections.categoryLists, [this](uint64 slot) { ParseCategory(Pointer(slot)); });
        ForEachPointer(sections.selectorRefs, [this](uint64 slot) {
            const std::string selector = memory.readString(Pointer(slot));
            if (!selector.empty())
                metadata.selectorRefs.emplace_back(slot, selector);
        });
        ForEachPointer(sections.classRefs, [this](uint64 slot) {
            const std::string name = ClassName(Pointer(slot), slot);
            if (!name.empty())
                metadata.classRefs.emplace_back(slot, name);
        });
    }
};

// a name of the listing: the characters of a selector that are not letters, digits or _ become _ (speak:loud: -> speak_loud_)
std::string ToLabelName(std::string_view prefix, std::string_view text)
{
    std::string name(prefix);
    for (const char c : text)
        name.push_back(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$' ? c : '_');
    return name;
}
} // namespace

void GView::View::DissasmViewer::ParseObjCMetadata(const ObjCSections& sections, const ObjCMemory& memory, ObjCMetadata& metadata)
{
    if (!memory.readPointer || !memory.readU32 || !memory.readString)
        return;
    ObjCParser(memory, metadata).Parse(sections);
}

void GView::View::DissasmViewer::ApplyObjCMetadata(SettingsData& settings, Reference<GView::Object> obj)
{
    if (!obj.IsValid() || !settings.offsetTranslateCallback.IsValid())
        return;
    const auto toVA = [&settings](uint64 fileOffset) {
        return settings.offsetTranslateCallback->TranslateFromFileOffset(fileOffset, static_cast<uint32>(DissasmPEConversionType::VA));
    };
    // the lists: the data zones of the Mach-O plugin ("segment,section")
    ObjCSections sections;
    for (const auto& [start, zone] : settings.disassemblyZones) {
        if (!zone.isData || zone.isUninitialized || !zone.name.starts_with("__"))
            continue;
        const auto comma = zone.name.find(',');
        if (comma == std::string::npos)
            continue;
        const std::string_view section = std::string_view(zone.name).substr(comma + 1);
        std::vector<ObjCSection>* list = nullptr;
        if (section == "__objc_classlist" || section == "__objc_nlclslist")
            list = &sections.classLists;
        else if (section == "__objc_catlist" || section == "__objc_nlcatlist")
            list = &sections.categoryLists;
        else if (section == "__objc_selrefs")
            list = &sections.selectorRefs;
        else if (section == "__objc_classrefs" || section == "__objc_superrefs")
            list = &sections.classRefs;
        const uint64 address = toVA(start);
        if (list && address != static_cast<uint64>(-1))
            list->push_back({ address, zone.size });
    }
    if (sections.classLists.empty() && sections.categoryLists.empty() && sections.selectorRefs.empty() && sections.classRefs.empty())
        return;

    const uint64 fileSize   = obj->GetData().GetSize();
    const auto toFileOffset = [&settings, fileSize](uint64 address) -> std::optional<uint64> {
        const uint64 offset = settings.offsetTranslateCallback->TranslateToFileOffset(address, static_cast<uint32>(DissasmPEConversionType::VA));
        return offset < fileSize ? std::optional<uint64>(offset) : std::nullopt;
    };
    // the image base: the VA of the RVA 0 (the memory mappings are keyed by RVAs)
    uint64 imageBase = 0;
    if (const auto first = settings.disassemblyZones.begin(); first != settings.disassemblyZones.end()) {
        const uint64 va  = toVA(first->first);
        const uint64 rva = settings.offsetTranslateCallback->TranslateFromFileOffset(first->first, static_cast<uint32>(DissasmPEConversionType::RVA));
        if (va != static_cast<uint64>(-1) && rva != static_cast<uint64>(-1) && va >= rva)
            imageBase = va - rva;
    }
    ObjCMemory memory;
    memory.readPointer = [&](uint64 address) -> std::optional<uint64> {
        const auto offset = toFileOffset(address);
        if (!offset.has_value())
            return {};
        if (const auto relocated = settings.relocatedPointers.find(offset.value()); relocated != settings.relocatedPointers.end())
            return relocated->second; // a rebase of the chained fixups (0: a bind)
        uint64 value = 0;
        return obj->GetData().Copy<uint64>(offset.value(), value) ? std::optional<uint64>(value) : std::nullopt;
    };
    memory.readU32 = [&](uint64 address) -> std::optional<uint32> {
        const auto offset = toFileOffset(address);
        uint32 value      = 0;
        return offset.has_value() && obj->GetData().Copy<uint32>(offset.value(), value) ? std::optional<uint32>(value) : std::nullopt;
    };
    memory.readString = [&](uint64 address) -> std::string {
        const auto offset = toFileOffset(address);
        if (address == 0 || !offset.has_value())
            return {};
        constexpr uint32 MAX_NAME = 256;
        const auto view = obj->GetData().Get(offset.value(), MAX_NAME, false);
        std::string text;
        for (size_t index = 0; view.IsValid() && index < view.GetLength() && view.GetData()[index] != 0; index++)
            text.push_back(static_cast<char>(view.GetData()[index]));
        return text;
    };
    memory.bindName = [&](uint64 address) -> std::string {
        const auto mapping = settings.memoryMappings.find(address - imageBase);
        return mapping != settings.memoryMappings.end() ? mapping->second.name : std::string();
    };
    ObjCMetadata metadata;
    ParseObjCMetadata(sections, memory, metadata);

    // the methods: function names (a symbol of an unstripped file keeps its own)
    for (const auto& [implementation, name] : metadata.methods) {
        const auto offset = toFileOffset(implementation);
        if (!offset.has_value())
            continue;
        auto& entry = settings.functionEntries[offset.value()];
        if (entry.name.empty())
            entry.name = name;
    }
#ifndef DISSASM_DISABLE_API_CALLS
    const auto addSlot = [&](uint64 address, std::string name) {
        if (address >= imageBase)
            settings.memoryMappings.insert({ address - imageBase, { std::move(name), MemoryMappingType::TextMapping } });
    };
    for (const auto& [slot, selector] : metadata.selectorRefs)
        addSlot(slot, ToLabelName("selRef_", selector));
    for (const auto& [slot, name] : metadata.classRefs)
        addSlot(slot, ToLabelName("classRef_", name));
    for (const auto& [address, name] : metadata.structures)
        if (address != 0)
            addSlot(address, ToLabelName("", name));
#endif
}
