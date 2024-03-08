#pragma once

#include "ast.hpp"

namespace GView::View::DissasmViewer::JClass
{
enum class ConstantKind : uint8 {
    Nothing            = 0,
    Utf8               = 1,
    Integer            = 3,
    Float              = 4,
    Long               = 5,
    Double             = 6,
    Class              = 7,
    String             = 8,
    FieldRef           = 9,
    MethodRef          = 10,
    InterfaceMethodRef = 11,
    NameAndType        = 12,
    MethodHandle       = 15,
    MethodType         = 16,
    InvokeDynamic      = 18
};

struct CONSTANT_Field_Interface_Methodref_info {
    uint16 class_index;
    uint16 name_and_type_index;

    bool read(BufferReader& reader);
};

struct CONSTANT_NameAndType_info {
    uint16 name_index;
    uint16 descriptor_index;

    bool read(BufferReader& reader);
};

struct CONSTANT_Class_info {
    uint16 name_index;

    bool read(BufferReader& reader);
};

struct CONSTANT_Utf8_info {
    uint16 length;
    const char* bytes;

    bool read(BufferReader& reader);
};

struct CONSTANT_String_info {
    uint16 string_index;

    bool read(BufferReader& reader);
};

struct CONSTANT_InvokeDynamic_info {
    uint16 bootstrap_method_attr_index;
    uint16 name_and_type_index;

    bool read(BufferReader& reader);
};

struct CONSTANT_Double_info {
    double value;

    bool read(BufferReader& reader);
};

struct CONSTANT_MethodHandle_info {
    uint8 reference_kind;
    uint16 reference_index;

    bool read(BufferReader& reader);
};

struct CONSTANT_MethodType_info {
    uint16 descriptor_index;

    bool read(BufferReader& reader);
};

struct CONSTANT_Integer_info {
    uint32 value;

    bool read(BufferReader& reader);
};

struct ConstantData {
    ConstantKind kind;
    union {
        CONSTANT_Class_info clazz;
        CONSTANT_NameAndType_info name_and_type;
        CONSTANT_InvokeDynamic_info invoke_dynamic;
        CONSTANT_Field_Interface_Methodref_info field_interface_method;
        CONSTANT_MethodHandle_info method_handle;
        CONSTANT_MethodType_info method_type;
        CONSTANT_String_info string;
        CONSTANT_Utf8_info utf8;
        CONSTANT_Double_info double_;
        CONSTANT_Integer_info integer;
    };
};

struct ExceptionTable {
    uint16 start_pc;
    uint16 end_pc;
    uint16 handler_pc;
    uint16 catch_type;

    bool read(BufferReader& reader);
};

struct AttributeInfo {
    uint16 attribute_name_index;
    BufferView info;
};

struct CodeAttribute {
    uint16 max_stack;
    uint16 max_locals;
    BufferView code;
    vector<ExceptionTable> exception_table;
    vector<AttributeInfo> attributes;
};

struct FieldInfo {
    uint16 access_flags;
    uint16 name_index;
    uint16 descriptor_index;
    vector<AttributeInfo> attributes;
};

struct MethodInfo {
    uint16 access_flags;
    uint16 name_index;
    uint16 descriptor_index;
    vector<AttributeInfo> attributes;
};

class ClassParser
{
  public:
    vector<ConstantData> constant_data;
    vector<FieldInfo> fields;
    vector<MethodInfo> methods;
    vector<AttributeInfo> attributes;

    ClassParser();

    bool parse(BufferReader& reader, vector<ColoredArea>& areas);
    bool parse_constant_pool(BufferReader& reader);
    bool parse_field(BufferReader& reader);
    bool parse_method(BufferReader& reader);

    bool parse_attributes(BufferReader& reader, vector<AttributeInfo>& out);
    bool parse_attribute(BufferReader& reader, AttributeInfo& out);
    bool parse_attribute_code(BufferView buffer, CodeAttribute& code);

    static bool is_valid_constant_pool_tag(uint8 tag);
};

class Demangler
{
    AstContext& ctx;
    const char* start;
    const char* end;

    Type* demangle_class_ref();
    Type* demangle_array_ref();
    Type* demangle();

  public:
    Demangler(AstContext& ctx);
    Type* demangle_field(string_view in);
    Type* demangle_method(string_view in);
};

struct AstCreator {
    ClassParser& class_parser;
    const vector<ConstantData>& constant_data;
    const vector<FieldInfo>& fields;
    const vector<MethodInfo>& methods;
    const vector<AttributeInfo>& attributes;
    AstContext ctx;
    Demangler demangler;

    AstCreator(ClassParser& class_parse);

    Class* create();
    Field* create_field(const FieldInfo& raw_field);
    Method* create_method(const MethodInfo& raw_method);
    bool create_code(BufferView buffer);

    bool get_utf8(string_view& out, uint16 index);

    const ConstantData* get_constant(uint16 index, ConstantKind expect);
};

struct AstPrinter {
    std::string output;
    void print(const Class* clazz);
};
} // namespace GView::View::DissasmViewer::JClass