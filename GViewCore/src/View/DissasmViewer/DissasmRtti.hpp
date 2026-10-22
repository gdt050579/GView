#pragma once

#include "DissasmViewer.hpp"

#include <functional>
#include <string>
#include <vector>

namespace GView::View::DissasmViewer
{
// a data zone as the RTTI parser reads it: its VA and its bytes (the pointers that the loader writes already applied)
struct RttiRange {
    uint64 address;
    std::vector<uint8> bytes;
};

struct RttiInput {
    std::vector<RttiRange> ranges;
    uint8 pointerSize = 8;
    uint64 imageBase  = 0; // the VA of the RVA 0 (MSVC x64: the locators and the descriptors are RVAs)
    // the name of a named slot at a VA (an import, a bind, a copy relocation): the Itanium typeinfo objects point to
    // __cxxabiv1::__class_type_info / __si_class_type_info / __vmi_class_type_info, which are imported
    std::function<std::string(uint64 address)> slotName;
};

// a field of a structure of the RTTI (its line, its name)
struct RttiField {
    uint64 address;
    uint32 size;
    DataFieldType type;
    std::string name;
};

struct RttiResult {
    std::vector<RttiField> fields;
    std::vector<std::pair<uint64, std::string>> names;   // VA -> Animal::vftable, Animal::RTTI_Type_Descriptor, zoo::Bird::typeinfo, ...
    std::vector<std::pair<uint64, std::string>> classes; // the VA of a vtable -> its class (zoo::Bird)
};

// The C++ run-time type information of the data:
// - MSVC: the complete object locators (x64: signature 1 and the RVA of itself; x86: signature 0 and a type descriptor), their type
//   descriptors (.?AVAnimal@@, .?AUBird@zoo@@), the vtables that follow a pointer to a locator
// - Itanium (GCC / clang, ELF / Mach-O): the typeinfo objects (a vptr bound to __cxxabiv1::__*class_type_info, a pointer to the mangled
//   name), the vtables ({offset to top, typeinfo, the virtual functions})
// - the bases: MSVC class hierarchy descriptors, their base class arrays and base class descriptors (mdisp / pdisp / vdisp); Itanium
//   __si_class_type_info (base_type) / __vmi_class_type_info (base_type, offset_flags). A vtable of a base at an offset (multiple
//   inheritance) is the one of that base: zoo::Bird::vftable{for_Flyer} (IDA: `vftable'{for `Flyer'}), zoo::Bird::vtable{for_Flyer}
// The names are the demangled class names: Animal::vftable / Animal::RTTI_Complete_Object_Locator / Animal::RTTI_Type_Descriptor /
// Animal::RTTI_Base_Class_Descriptor_at_(0,-1,0,64) (MSVC), Dog::vtable / Dog::typeinfo / Dog::typeinfo_name (Itanium)
void ParseCppRtti(const RttiInput& input, RttiResult& result);

// the data zones of the settings parsed for their run-time type information: the names become named slots (labels of the data zones,
// names of the operands)
void ApplyCppRtti(SettingsData& settings, Reference<GView::Object> obj);

// the name of a type descriptor of MSVC (the type of a catch): .?AVbad_alloc@std@@ -> std::bad_alloc, .PAVCItem@@ / .PEAVCItem@@ ->
// CItem *, .PBVCItem@@ -> CItem const *; the other forms (the basic types) as they are, without the dot
std::string DemangleMsvcTypeName(std::string_view descriptor);
} // namespace GView::View::DissasmViewer
