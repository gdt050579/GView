#include "DissasmRtti.hpp"
#include "DissasmCodeZone.hpp"

#include <cstring>
#include <unordered_map>
#include <unordered_set>

using namespace GView::View::DissasmViewer;

namespace
{
constexpr uint64 MAX_RANGE_BYTES  = 32ull * 1024 * 1024;
constexpr uint32 MAX_NAME         = 512;
constexpr int64 MAX_OFFSET_TO_TOP = 0x100000;
constexpr uint32 MAX_BASE_CLASSES = 256;

// a base class of a class: its name and where it is in the object (MSVC: mdisp / pdisp / vdisp; Itanium: the offset, virtual)
struct RttiBaseClass {
    std::string name;
    int64 offset;
    bool isVirtual;
};

// the name of a vtable / locator of a base at an offset (multiple inheritance): {for_Base} (IDA: `vftable'{for `Base'}), the offset
// when no base is known there
std::string BaseSuffix(const std::vector<RttiBaseClass>* bases, int64 offset)
{
    if (offset == 0)
        return {};
    if (bases)
        for (size_t index = 1; index < bases->size(); index++) // the first entry of an MSVC array is the class itself
            if ((*bases)[index].offset == offset && !(*bases)[index].isVirtual)
                return "{for_" + (*bases)[index].name + "}";
    char text[24];
    snprintf(text, sizeof(text), "_%llX", static_cast<unsigned long long>(offset));
    return text;
}

class RttiParser
{
    const RttiInput& input;
    RttiResult& result;
    const uint8 pointerSize;

  public:
    RttiParser(const RttiInput& input, RttiResult& result) : input(input), result(result), pointerSize(input.pointerSize)
    {
    }

    const RttiRange* RangeOf(uint64 address, uint64 size) const
    {
        for (const auto& range : input.ranges)
            if (address >= range.address && address - range.address + size <= range.bytes.size())
                return &range;
        return nullptr;
    }

    std::optional<uint64> Read(uint64 address, uint8 size) const
    {
        const auto* range = RangeOf(address, size);
        if (!range)
            return {};
        uint64 value = 0;
        memcpy(&value, range->bytes.data() + (address - range->address), size);
        return value;
    }

    std::string ReadName(uint64 address) const
    {
        const auto* range = RangeOf(address, 1);
        if (!range)
            return {};
        std::string text;
        for (uint64 position = address - range->address; position < range->bytes.size() && range->bytes[position] != 0 && text.size() < MAX_NAME; position++)
            text.push_back(static_cast<char>(range->bytes[position]));
        return text;
    }

    // the name of a class in the listing: the demangled name without spaces (a template: std::pair<int,int>)
    static std::string LabelName(std::string name)
    {
        std::string label;
        for (const char c : name)
            if (c != ' ')
                label.push_back(c);
        return label;
    }

    // .?AVAnimal@@ / .?AUBird@zoo@@: the class (zoo::Bird), demangled as the vtable of the class (??_7Bird@zoo@@6B@)
    static std::string MsvcClassName(std::string_view descriptor)
    {
        if (descriptor.size() < 6 || !descriptor.starts_with(".?A") || (descriptor[3] != 'V' && descriptor[3] != 'U'))
            return {};
        const std::string mangled = "??_7" + std::string(descriptor.substr(4)) + "6B@";
        String demangled;
        if (GView::Utils::Demangle(mangled, demangled)) {
            std::string text(demangled.GetText(), demangled.Len());
            if (text.starts_with("const "))
                text = text.substr(6);
            if (const auto suffix = text.rfind("::`vftable'"); suffix != std::string::npos)
                return LabelName(text.substr(0, suffix));
        }
        // the plain names: Bird@zoo@@ -> zoo::Bird
        const auto names = descriptor.substr(4, descriptor.find("@@") == std::string_view::npos ? std::string_view::npos : descriptor.find("@@") - 4);
        std::vector<std::string_view> parts;
        for (size_t start = 0; start <= names.size();) {
            const size_t end = std::min(names.find('@', start), names.size());
            if (end > start)
                parts.emplace_back(names.substr(start, end - start));
            start = end + 1;
        }
        std::string name;
        for (auto part = parts.rbegin(); part != parts.rend(); ++part)
            name.append(name.empty() ? "" : "::").append(*part);
        return name;
    }

    // 3Dog / N3zoo4BirdE: the class, demangled as its typeinfo name (_ZTS3Dog)
    static std::string ItaniumClassName(std::string_view mangled)
    {
        if (mangled.empty() || !(std::isdigit(static_cast<unsigned char>(mangled[0])) || mangled[0] == 'N' || mangled[0] == 'S'))
            return {};
        String demangled;
        if (!GView::Utils::Demangle("_ZTS" + std::string(mangled), demangled))
            return {};
        const std::string text(demangled.GetText(), demangled.Len());
        constexpr std::string_view PREFIX = "typeinfo name for ";
        return text.starts_with(PREFIX) ? LabelName(text.substr(PREFIX.size())) : std::string();
    }

    void ParseMsvc()
    {
        const bool is64 = pointerSize == 8;
        std::unordered_map<uint64, std::string> descriptors; // VA -> class
        std::unordered_map<uint64, std::pair<std::string, std::string>> locators; // VA -> the class, the offset of its base (_8)
        // the type descriptors: {pVFTable, spare, ".?AV...@@"}
        for (const auto& range : input.ranges)
            for (uint64 offset = 0; offset + 2ull * pointerSize + 5 <= range.bytes.size(); offset += pointerSize) {
                const uint8* name = range.bytes.data() + offset + 2ull * pointerSize;
                if (name[0] != '.' || name[1] != '?' || name[2] != 'A' || (name[3] != 'V' && name[3] != 'U'))
                    continue;
                const std::string className = MsvcClassName(ReadName(range.address + offset + 2ull * pointerSize));
                if (!className.empty()) {
                    const uint64 address = range.address + offset;
                    descriptors[address] = className;
                    const uint32 nameSize = static_cast<uint32>(ReadName(address + 2ull * pointerSize).size() + 1);
                    result.fields.push_back({ address, pointerSize, DataFieldType::Pointer, "pVFTable" });
                    result.fields.push_back({ address + pointerSize, pointerSize, DataFieldType::Value, "spare" });
                    result.fields.push_back({ address + 2ull * pointerSize, nameSize, DataFieldType::String, "name" });
                }
            }
        if (descriptors.empty())
            return;
        // the complete object locators: x64 {1, offset, cdOffset, rva TypeDescriptor, rva ClassDescriptor, rva self}; x86 {0, offset,
        // cdOffset, TypeDescriptor, ClassDescriptor}
        struct Locator {
            uint64 address;
            std::string className;
            uint32 offset;
            uint64 hierarchy;
        };
        std::vector<Locator> found;
        const DataFieldType reference = is64 ? DataFieldType::RVA : DataFieldType::Pointer;
        const auto toAddress          = [&](uint64 value) { return is64 ? input.imageBase + value : value; };
        for (const auto& range : input.ranges)
            for (uint64 offset = 0; offset + (is64 ? 24 : 20) <= range.bytes.size(); offset += 4) {
                uint32 fields[6] = {};
                memcpy(fields, range.bytes.data() + offset, is64 ? 24 : 20);
                const uint64 address = range.address + offset;
                if (fields[0] != (is64 ? 1u : 0u) || fields[1] > MAX_OFFSET_TO_TOP)
                    continue;
                if (is64 && fields[5] != address - input.imageBase)
                    continue;
                const uint64 descriptor = is64 ? input.imageBase + fields[3] : fields[3];
                const auto known        = descriptors.find(descriptor);
                if (known == descriptors.end())
                    continue;
                found.push_back({ address, known->second, fields[1], toAddress(fields[4]) });
                result.fields.push_back({ address, 4, DataFieldType::Value, "signature" });
                result.fields.push_back({ address + 4, 4, DataFieldType::Value, "offset" });
                result.fields.push_back({ address + 8, 4, DataFieldType::Value, "cdOffset" });
                result.fields.push_back({ address + 12, 4, reference, "pTypeDescriptor" });
                result.fields.push_back({ address + 16, 4, reference, "pClassDescriptor" });
                if (is64)
                    result.fields.push_back({ address + 20, 4, DataFieldType::RVA, "pSelf" });
            }
        // the class hierarchy descriptors {signature, attributes, numBaseClasses, pBaseClassArray}, their arrays of base class descriptors
        // {pTypeDescriptor, numContainedBases, mdisp, pdisp, vdisp, attributes[, pClassDescriptor]}: the bases of the classes and where
        // they are (the first entry: the class itself)
        std::unordered_map<uint64, std::vector<RttiBaseClass>> hierarchies;
        std::unordered_set<uint64> baseDescriptors;
        // the descriptors of the locators, then the ones of the bases (pClassDescriptor: an abstract class has no locator of its own)
        std::vector<std::pair<uint64, std::string>> pending;
        for (const auto& locator : found)
            pending.emplace_back(locator.hierarchy, locator.className);
        for (size_t next = 0; next < pending.size() && next < MAX_BASE_CLASSES * 16; next++) {
            const auto [hierarchy, className] = pending[next];
            if (hierarchies.contains(hierarchy) || !RangeOf(hierarchy, 16))
                continue;
            auto& bases                 = hierarchies[hierarchy];
            const uint32 numBaseClasses = static_cast<uint32>(Read(hierarchy + 8, 4).value_or(0));
            const uint64 array          = toAddress(Read(hierarchy + 12, 4).value_or(0));
            result.names.emplace_back(hierarchy, className + "::RTTI_Class_Hierarchy_Descriptor");
            result.fields.push_back({ hierarchy, 4, DataFieldType::Value, "signature" });
            result.fields.push_back({ hierarchy + 4, 4, DataFieldType::Value, "attributes" });
            result.fields.push_back({ hierarchy + 8, 4, DataFieldType::Value, "numBaseClasses" });
            result.fields.push_back({ hierarchy + 12, 4, reference, "pBaseClassArray" });
            if (numBaseClasses == 0 || numBaseClasses > MAX_BASE_CLASSES || !RangeOf(array, 4ull * numBaseClasses))
                continue;
            if (baseDescriptors.insert(array).second) {
                result.names.emplace_back(array, className + "::RTTI_Base_Class_Array");
                for (uint32 index = 0; index < numBaseClasses; index++)
                    result.fields.push_back({ array + 4ull * index, 4, reference, "pBaseClassDescriptor" });
            }
            for (uint32 index = 0; index < numBaseClasses; index++) {
                const uint64 descriptor = toAddress(Read(array + 4ull * index, 4).value_or(0));
                if (!RangeOf(descriptor, 24))
                    break;
                int32 values[6] = {};
                for (uint32 field = 0; field < 6; field++)
                    values[field] = static_cast<int32>(Read(descriptor + 4ull * field, 4).value_or(0));
                const auto type = descriptors.find(toAddress(static_cast<uint32>(values[0])));
                if (type == descriptors.end())
                    break;
                bases.push_back({ type->second, values[2], values[3] != -1 });
                if (!baseDescriptors.insert(descriptor).second)
                    continue; // shared by the arrays of several classes: named once
                char at[64];
                snprintf(at, sizeof(at), "::RTTI_Base_Class_Descriptor_at_(%d,%d,%d,%u)", values[2], values[3], values[4], static_cast<uint32>(values[5]));
                result.names.emplace_back(descriptor, type->second + at);
                static constexpr const char* FIELDS[] = { "pTypeDescriptor", "numContainedBases", "mdisp", "pdisp", "vdisp", "attributes" };
                for (uint32 field = 0; field < 6; field++)
                    result.fields.push_back({ descriptor + 4ull * field, 4, field == 0 ? reference : DataFieldType::Value, FIELDS[field] });
                if ((values[5] & 0x40) != 0 && RangeOf(descriptor + 24, 4)) { // BCD_HASPCHD
                    result.fields.push_back({ descriptor + 24, 4, reference, "pClassDescriptor" });
                    pending.emplace_back(toAddress(Read(descriptor + 24, 4).value_or(0)), type->second);
                }
            }
        }
        // the names of the locators: a locator of a base at an offset (multiple inheritance) is the one of the vtable {for_Base}
        for (const auto& locator : found) {
            const auto bases        = hierarchies.find(locator.hierarchy);
            const std::string suffix = BaseSuffix(bases != hierarchies.end() ? &bases->second : nullptr, locator.offset);
            locators[locator.address] = { locator.className, suffix };
            result.names.emplace_back(locator.address, locator.className + "::RTTI_Complete_Object_Locator" + suffix);
        }
        for (const auto& [address, name] : descriptors)
            result.names.emplace_back(address, name + "::RTTI_Type_Descriptor");
        // the vtables: the pointer to the locator, then the virtual functions
        for (const auto& range : input.ranges)
            for (uint64 offset = 0; offset + 2ull * pointerSize <= range.bytes.size(); offset += pointerSize) {
                uint64 value = 0;
                memcpy(&value, range.bytes.data() + offset, pointerSize);
                const auto locator = locators.find(value);
                if (locator == locators.end())
                    continue;
                const uint64 vtable = range.address + offset + pointerSize;
                result.names.emplace_back(vtable, locator->second.first + "::vftable" + locator->second.second);
                result.classes.emplace_back(vtable, locator->second.first);
            }
    }

    void ParseItanium()
    {
        std::unordered_map<uint64, std::string> typeinfos; // VA -> class
        std::unordered_map<uint64, uint8> typeinfoKinds;   // VA -> 1: __si_class_type_info, 2: __vmi_class_type_info
        // the typeinfo objects: {vptr (__cxxabiv1::__*class_type_info vtable + 2 pointers), name}
        const auto isTypeInfoClass = [](const std::string& symbol) { return symbol.find("class_type_info") != std::string::npos; };
        for (const auto& range : input.ranges)
            for (uint64 offset = 0; offset + 2ull * pointerSize <= range.bytes.size(); offset += pointerSize) {
                const uint64 address = range.address + offset;
                uint64 vptr          = 0;
                memcpy(&vptr, range.bytes.data() + offset, pointerSize);
                bool isTypeInfo = input.slotName && isTypeInfoClass(input.slotName(address)); // an import / a bind of the slot
                if (!isTypeInfo && vptr >= 2ull * pointerSize && input.slotName)
                    isTypeInfo = isTypeInfoClass(input.slotName(vptr - 2ull * pointerSize)); // a copy of the vtable in the image
                if (!isTypeInfo)
                    continue;
                uint64 namePointer = 0;
                memcpy(&namePointer, range.bytes.data() + offset + pointerSize, pointerSize);
                const std::string mangled   = ReadName(namePointer);
                const std::string className = ItaniumClassName(mangled);
                if (className.empty())
                    continue;
                typeinfos[address] = className;
                // __si_class_type_info: one public base at 0; __vmi_class_type_info: a list of bases
                const std::string kind = input.slotName ? input.slotName(address) + " " + input.slotName(vptr - 2ull * pointerSize) : std::string();
                if (kind.find("vmi_class_type_info") != std::string::npos)
                    typeinfoKinds[address] = 2;
                else if (kind.find("si_class_type_info") != std::string::npos)
                    typeinfoKinds[address] = 1;
                result.names.emplace_back(address, className + "::typeinfo");
                result.names.emplace_back(namePointer, className + "::typeinfo_name");
                result.fields.push_back({ address, pointerSize, DataFieldType::Pointer, "vptr" });
                result.fields.push_back({ address + pointerSize, pointerSize, DataFieldType::Pointer, "name" });
            }
        if (typeinfos.empty())
            return;
        // the bases: __si_class_type_info {vptr, name, base_type}; __vmi_class_type_info {vptr, name, flags, base_count, {base_type,
        // offset_flags (the offset << 8, 1: virtual, 2: public)}...}
        std::unordered_map<std::string, std::vector<RttiBaseClass>> bases; // class -> its bases
        for (const auto& [address, kind] : typeinfoKinds) {
            const auto& className = typeinfos[address];
            const uint64 first    = address + 2ull * pointerSize;
            if (kind == 1) {
                const auto base = Read(first, pointerSize);
                if (!base.has_value())
                    continue;
                result.fields.push_back({ first, pointerSize, DataFieldType::Pointer, "base_type" });
                if (const auto known = typeinfos.find(base.value()); known != typeinfos.end())
                    bases[className].push_back({ known->second, 0, false });
                continue;
            }
            const uint32 count = static_cast<uint32>(Read(first + 4, 4).value_or(0));
            if (count == 0 || count > MAX_BASE_CLASSES || !RangeOf(first + 8, 2ull * pointerSize * count))
                continue;
            result.fields.push_back({ first, 4, DataFieldType::Value, "flags" });
            result.fields.push_back({ first + 4, 4, DataFieldType::Value, "base_count" });
            for (uint32 index = 0; index < count; index++) {
                const uint64 entry = first + 8 + 2ull * pointerSize * index;
                result.fields.push_back({ entry, pointerSize, DataFieldType::Pointer, "base_type" });
                result.fields.push_back({ entry + pointerSize, pointerSize, DataFieldType::Value, "offset_flags" });
                const uint64 flags  = Read(entry + pointerSize, pointerSize).value_or(0);
                const int64 offset  = pointerSize == 8 ? static_cast<int64>(flags) >> 8 : static_cast<int64>(static_cast<int32>(flags)) >> 8;
                const auto known    = typeinfos.find(Read(entry, pointerSize).value_or(0));
                if (known != typeinfos.end())
                    bases[className].push_back({ known->second, offset, (flags & 1) != 0 });
            }
        }
        // the vtables: {offset to top (0, or the negative offset of a secondary vtable), typeinfo, the virtual functions}
        for (const auto& range : input.ranges)
            for (uint64 offset = pointerSize; offset + pointerSize <= range.bytes.size(); offset += pointerSize) {
                uint64 value = 0;
                memcpy(&value, range.bytes.data() + offset, pointerSize);
                const auto typeinfo = typeinfos.find(value);
                if (typeinfo == typeinfos.end())
                    continue;
                uint64 top = 0;
                memcpy(&top, range.bytes.data() + offset - pointerSize, pointerSize);
                const int64 offsetToTop = pointerSize == 8 ? static_cast<int64>(top) : static_cast<int64>(static_cast<int32>(top));
                if (offsetToTop > 0 || offsetToTop < -MAX_OFFSET_TO_TOP)
                    continue;
                // a secondary vtable (multiple inheritance): the one of the base at -offset_to_top, {for_Base}
                const auto classBases  = bases.find(typeinfo->second);
                std::vector<RttiBaseClass> withSelf; // BaseSuffix skips the first entry (the class itself in the MSVC arrays)
                if (classBases != bases.end()) {
                    withSelf.push_back({ typeinfo->second, 0, false });
                    withSelf.insert(withSelf.end(), classBases->second.begin(), classBases->second.end());
                }
                const std::string name = typeinfo->second + "::vtable" + BaseSuffix(withSelf.empty() ? nullptr : &withSelf, -offsetToTop);
                const uint64 vtable = range.address + offset - pointerSize;
                result.names.emplace_back(vtable, name);
                result.classes.emplace_back(vtable, typeinfo->second);
                result.fields.push_back({ vtable, pointerSize, DataFieldType::Value, "offset_to_top" });
                result.fields.push_back({ vtable + pointerSize, pointerSize, DataFieldType::Pointer, "typeinfo" });
            }
    }
};
} // namespace

void GView::View::DissasmViewer::ParseCppRtti(const RttiInput& input, RttiResult& result)
{
    if (input.pointerSize != 4 && input.pointerSize != 8)
        return;
    RttiParser parser(input, result);
    parser.ParseMsvc();
    parser.ParseItanium();
}

void GView::View::DissasmViewer::ApplyCppRtti(SettingsData& settings, Reference<GView::Object> obj)
{
    if (!obj.IsValid() || !settings.offsetTranslateCallback.IsValid() || settings.disassemblyZones.empty())
        return;
    const auto toVA = [&settings](uint64 fileOffset, DissasmPEConversionType type) {
        return settings.offsetTranslateCallback->TranslateFromFileOffset(fileOffset, static_cast<uint32>(type));
    };
    RttiInput input;
    // the pointers of the code: 8 bytes for x64 / ARM64
    for (const auto& [start, zone] : settings.disassemblyZones)
        if (!zone.isData) {
            input.pointerSize = zone.language == DisassemblyLanguage::x64 || zone.language == DisassemblyLanguage::ARM64 ? 8 : 4;
            break;
        }
    {
        const auto& [start, zone] = *settings.disassemblyZones.begin();
        const uint64 va           = toVA(start, DissasmPEConversionType::VA);
        const uint64 rva          = toVA(start, DissasmPEConversionType::RVA);
        if (va != static_cast<uint64>(-1) && rva != static_cast<uint64>(-1) && va >= rva)
            input.imageBase = va - rva;
    }
    const uint64 fileSize = obj->GetData().GetSize();
    uint64 total          = 0;
    for (const auto& [start, zone] : settings.disassemblyZones) {
        if (!zone.isData || zone.isUninitialized || start >= fileSize)
            continue;
        const uint64 va = toVA(start, DissasmPEConversionType::VA);
        const uint64 size = std::min<uint64>({ zone.size, fileSize - start, MAX_RANGE_BYTES });
        if (va == static_cast<uint64>(-1) || size == 0 || total + size > 4 * MAX_RANGE_BYTES)
            continue;
        total += size;
        const auto bytes = obj->GetData().CopyToBuffer(start, static_cast<uint32>(size), false);
        RttiRange range{ va, std::vector<uint8>(bytes.GetData(), bytes.GetData() + bytes.GetLength()) };
        ApplyRelocatedPointers(&settings.relocatedPointers, start, range.bytes.data(), range.bytes.size(), input.pointerSize);
        input.ranges.push_back(std::move(range));
    }
    if (input.ranges.empty())
        return;
    const uint64 imageBase = input.imageBase;
    input.slotName         = [&settings, imageBase](uint64 address) {
        const auto mapping = address >= imageBase ? settings.memoryMappings.find(address - imageBase) : settings.memoryMappings.end();
        return mapping != settings.memoryMappings.end() ? mapping->second.name : std::string();
    };
    RttiResult result;
    ParseCppRtti(input, result);
#ifndef DISSASM_DISABLE_API_CALLS
    // the names of the structures win over the import of their first pointer (the vptr of a typeinfo object, bound to
    // __cxxabiv1::__si_class_type_info)
    for (const auto& [address, name] : result.names)
        if (address >= imageBase)
            settings.memoryMappings[address - imageBase] = { name, MemoryMappingType::TextMapping };
#endif
    for (const auto& field : result.fields)
        settings.dataFields.try_emplace(field.address, DissasmDataField{ field.size, field.type, field.name });
}
