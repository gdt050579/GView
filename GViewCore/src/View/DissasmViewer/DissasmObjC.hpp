#pragma once

#include "DissasmViewer.hpp"

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace GView::View::DissasmViewer
{
// The memory of an image as the Objective-C metadata parser reads it (VAs)
struct ObjCMemory {
    // a pointer: its value after the fixups (a rebase), 0 / none for a bind (an imported class) or a place outside of the file
    std::function<std::optional<uint64>(uint64 address)> readPointer;
    std::function<std::optional<uint32>(uint64 address)> readU32;
    std::function<std::string(uint64 address)> readString; // a C string (a class name, a selector)
    std::function<std::string(uint64 address)> bindName;   // the symbol bound to a pointer (_OBJC_CLASS_$_NSObject), empty when none
};

struct ObjCSection {
    uint64 address;
    uint64 size;
};

// the lists of the Objective-C 2 runtime (64 bit) in the image
struct ObjCSections {
    std::vector<ObjCSection> classLists;    // __objc_classlist, __objc_nlclslist: pointers to class_t
    std::vector<ObjCSection> categoryLists; // __objc_catlist, __objc_nlcatlist: pointers to category_t
    std::vector<ObjCSection> selectorRefs;  // __objc_selrefs: pointers to the selector names
    std::vector<ObjCSection> classRefs;     // __objc_classrefs, __objc_superrefs: pointers to class_t (or binds of imported classes)
};

struct ObjCMetadata {
    std::vector<std::pair<uint64, std::string>> methods;      // implementation VA -> -[Class selector] / +[Class(Category) selector]
    std::vector<std::pair<uint64, std::string>> selectorRefs; // selector reference VA -> the selector (speak:loud:)
    std::vector<std::pair<uint64, std::string>> classRefs;    // class reference VA -> the class name
    // the structures, named as the compiler names their symbols: _OBJC_CLASS_$_Name, _OBJC_METACLASS_$_Name, __OBJC_CLASS_RO_$_Name,
    // __OBJC_$_INSTANCE_METHODS_Name, __OBJC_$_CATEGORY_Class_$_Category, ...
    std::vector<std::pair<uint64, std::string>> structures;
    // the fields of the structures (class_t, class_ro_t, category_t, the method lists): their lines and names
    struct Field {
        uint64 address;
        uint32 size;
        DataFieldType type;
        std::string name;
    };
    std::vector<Field> fields;
};

// The classes and categories of the lists: the methods of their method lists (the classic ones: {name, types, imp} pointers; the relative
// ones of macOS 11+ / iOS 14+: {name, types, imp} 32 bit offsets, the name through a selector reference), the class methods from the
// metaclass; the selector and class references
void ParseObjCMetadata(const ObjCSections& sections, const ObjCMemory& memory, ObjCMetadata& metadata);

// Mach-O: the data zones of the Objective-C lists ("__DATA_CONST,__objc_classlist", ...) are parsed with the pointers of the fixups
// (relocatedPointers, after ApplyChainedFixups): the methods become function entries (-[Class selector], unless a symbol named them), the
// references and the classes named slots (selRef_speak_loud_, classRef_Animal, _OBJC_CLASS_$_Animal)
void ApplyObjCMetadata(SettingsData& settings, Reference<GView::Object> obj);
} // namespace GView::View::DissasmViewer
