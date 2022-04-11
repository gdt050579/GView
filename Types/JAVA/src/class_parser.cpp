#include "global.hpp"
#include "ast.hpp"

namespace GView::Java
{

// -------------------------------------------------------- Raw --------------------------------------------------------

enum class ConstantKind : uint8
{
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

struct CONSTANT_Field_Interface_Methodref_info
{
    uint16 class_index;
    uint16 name_and_type_index;

    bool read(BufferReader& reader)
    {
        READB(class_index);
        READB(name_and_type_index);
        return true;
    }
};

struct CONSTANT_NameAndType_info
{
    uint16 name_index;
    uint16 descriptor_index;

    bool read(BufferReader& reader)
    {
        READB(name_index);
        READB(descriptor_index);
        return true;
    }
};

struct CONSTANT_Class_info
{
    uint16 name_index;

    bool read(BufferReader& reader)
    {
        READB(name_index);
        return true;
    }
};

struct CONSTANT_Utf8_info
{
    uint16 length;
    const char* bytes;

    bool read(BufferReader& reader)
    {
        READB(length);
        bytes = reinterpret_cast<const char*>(reader.get());
        SKIP(length);
        return true;
    }
};

struct CONSTANT_String_info
{
    uint16 string_index;

    bool read(BufferReader& reader)
    {
        READB(string_index);
        return true;
    }
};

struct CONSTANT_InvokeDynamic_info
{
    uint16 bootstrap_method_attr_index;
    uint16 name_and_type_index;

    bool read(BufferReader& reader)
    {
        READB(bootstrap_method_attr_index);
        READB(name_and_type_index);
        return true;
    }
};

struct CONSTANT_Double_info
{
    double value;

    bool read(BufferReader& reader)
    {
        uint64 v;
        READB(v);
        value = *reinterpret_cast<double*>(&v);
        return true;
    }
};

struct CONSTANT_MethodHandle_info
{
    uint8 reference_kind;
    uint16 reference_index;

    bool read(BufferReader& reader)
    {
        READB(reference_kind);
        READB(reference_index);
        return true;
    }
};

struct CONSTANT_MethodType_info
{
    uint16 descriptor_index;

    bool read(BufferReader& reader)
    {
        READB(descriptor_index);
        return true;
    }
};

struct ConstantData
{
    ConstantKind kind;
    union
    {
        CONSTANT_Class_info clazz;
        CONSTANT_NameAndType_info name_and_type;
        CONSTANT_InvokeDynamic_info invoke_dynamic;
        CONSTANT_Field_Interface_Methodref_info field_interface_method;
        CONSTANT_MethodHandle_info method_handle;
        CONSTANT_MethodType_info method_type;
        CONSTANT_String_info string;
        CONSTANT_Utf8_info utf8;
        CONSTANT_Double_info double_;
    };
};

struct ExceptionTable
{
    uint16 start_pc;
    uint16 end_pc;
    uint16 handler_pc;
    uint16 catch_type;

    bool read(BufferReader& reader)
    {
        READB(start_pc);
        READB(end_pc);
        READB(handler_pc);
        READB(catch_type);
        return true;
    }
};

struct AttributeInfo
{
    uint16 attribute_name_index;
    BufferView info;
};

struct CodeAttribute
{
    uint16 max_stack;
    uint16 max_locals;
    BufferView code;
    vector<ExceptionTable> exception_table;
    vector<AttributeInfo> attributes;
};

struct FieldInfo
{
    uint16 access_flags;
    uint16 name_index;
    uint16 descriptor_index;
    vector<AttributeInfo> attributes;
};

struct MethodInfo
{
    uint16 access_flags;
    uint16 name_index;
    uint16 descriptor_index;
    vector<AttributeInfo> attributes;
};

// ---------------------------------------------------- ClassParser ----------------------------------------------------

struct ClassParser
{
    BufferReader reader;
    vector<ConstantData> constant_data;
    vector<FieldInfo> fields;
    vector<MethodInfo> methods;
    vector<AttributeInfo> attributes;

    ClassParser(BufferReader reader);

    bool parse();
    bool parse_constant_pool();
    bool parse_field();
    bool parse_method();

    bool parse_attributes(vector<AttributeInfo>& out);
    bool parse_attribute(AttributeInfo& out);
    bool parse_attribute_code(BufferView buffer, CodeAttribute& code);
};

ClassParser::ClassParser(BufferReader reader) : reader(reader)
{
    constant_data.reserve(64);
    constant_data.push_back({ ConstantKind::Nothing });
}

bool ClassParser::parse()
{
    SKIPTYPE(uint32); // magic
    SKIPTYPE(uint16); // minor version
    SKIPTYPE(uint16); // major version
    uint16 constant_pool_count;
    READB(constant_pool_count);

    for (uint16 i = 0; i < constant_pool_count - 1; ++i)
    {
        FCHECK(parse_constant_pool());
    }

    uint16 access_flags;
    READB(access_flags);

    uint16 this_class;
    READB(this_class);

    uint16 super_class;
    READB(super_class);

    uint16 interfaces_count;
    READB(interfaces_count);
    for (uint16 i = 0; i < interfaces_count; ++i)
    {
        unreachable;
    }

    uint16 fields_count;
    READB(fields_count);
    for (uint16 i = 0; i < fields_count; ++i)
    {
        FCHECK(parse_field());
    }

    uint16 methods_count;
    READB(methods_count);
    for (uint16 i = 0; i < methods_count; ++i)
    {
        FCHECK(parse_method());
    }

    return true;
}

static bool is_valid_constant_pool_tag(uint8 tag)
{
    return 1 <= tag && tag <= 18 && tag != 2 && tag != 13 && tag != 14 && tag != 17;
}

bool ClassParser::parse_constant_pool()
{
    uint8 tag;
    READB(tag);

    CHECK(is_valid_constant_pool_tag(tag), false, "bad constant pool tag");

    ConstantData data;
    data.kind         = static_cast<ConstantKind>(tag);
    bool double_entry = false;
    switch (data.kind)
    {
    case ConstantKind::MethodRef:
    case ConstantKind::FieldRef:
    case ConstantKind::InterfaceMethodRef:
        FCHECK(data.field_interface_method.read(reader));
        break;
    case ConstantKind::Class:
        FCHECK(data.clazz.read(reader));
        break;
    case ConstantKind::NameAndType:
        FCHECK(data.name_and_type.read(reader));
        break;
    case ConstantKind::Utf8:
        FCHECK(data.utf8.read(reader));
        break;
    case ConstantKind::String:
        FCHECK(data.string.read(reader));
        break;
    case ConstantKind::InvokeDynamic:
        FCHECK(data.invoke_dynamic.read(reader));
        break;
    case ConstantKind::Double:
        FCHECK(data.double_.read(reader));
        double_entry = true;
        break;
    case ConstantKind::MethodHandle:
        FCHECK(data.method_handle.read(reader));
        break;
    case ConstantKind::MethodType:
        FCHECK(data.method_type.read(reader));
        break;
    default:
        unreachable;
    }

    constant_data.push_back(data);
    if (double_entry)
        constant_data.push_back(data);
    return true;
}

bool ClassParser::parse_field()
{
    FieldInfo field;
    READB(field.access_flags);
    READB(field.name_index);
    READB(field.descriptor_index);
    FCHECK(parse_attributes(field.attributes));

    fields.push_back(field);
    return true;
}

bool ClassParser::parse_method()
{
    MethodInfo method;
    READB(method.access_flags);
    READB(method.name_index);
    READB(method.descriptor_index);
    FCHECK(parse_attributes(method.attributes));

    methods.push_back(method);
    return true;
}

bool ClassParser::parse_attributes(vector<AttributeInfo>& out)
{
    uint16 attributes_count;
    READB(attributes_count);
    for (uint16 i = 0; i < attributes_count; ++i)
    {
        AttributeInfo attribute;
        FCHECK(parse_attribute(attribute));
        out.push_back(attribute);
    }

    return true;
}

bool ClassParser::parse_attribute(AttributeInfo& out)
{
    READB(out.attribute_name_index);
    uint32 attribute_length;
    READB(attribute_length);
    out.info = BufferView{ reader.get(), attribute_length };
    SKIP(attribute_length);

    return true;
}

bool ClassParser::parse_attribute_code(BufferView buffer, CodeAttribute& code)
{
    reader = { buffer.GetData(), buffer.GetLength() };

    READB(code.max_stack);
    READB(code.max_locals);
    uint32 code_length;
    READB(code_length);
    code.code = { reader.get(), code_length };
    SKIP(code_length);
    uint16 exception_table_length;
    READB(exception_table_length);
    for (uint32 i = 0; i < exception_table_length; ++i)
    {
        ExceptionTable exception;
        FCHECK(exception.read(reader));
        code.exception_table.push_back(exception);
    }

    FCHECK(parse_attributes(code.attributes));

    return true;
}

// ---------------------------------------------------- Demangler ----------------------------------------------------

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

Demangler::Demangler(AstContext& ctx) : ctx(ctx)
{
}

Type* Demangler::demangle_class_ref()
{
    const char* string = start;

    while (start < end && *start != ';')
        start++;

    if (*start != ';')
        return nullptr;

    string_view name = { string, static_cast<size_t>(start - string) };
    ++start;

    auto& result = ctx.class_references[name];
    if (result == nullptr)
    {
        auto new_name = reinterpret_cast<char*>(ctx.alloc.alloc(name.size()));
        for (size_t i = 0; i < name.size(); ++i)
            new_name[i] = name[i] == '/' ? '.' : name[i];
        result = ctx.alloc.alloc<ClassReferenceType>(string_view{ new_name, name.size() });
    }

    return result;
}

Type* Demangler::demangle_array_ref()
{
    auto subtype = demangle();
    FCHECKNULL(subtype);
    auto& result = ctx.array_references[subtype];

    if (result == nullptr)
        result = ctx.alloc.alloc<ArrayReferenceType>(subtype);

    return result;
}

Type* Demangler::demangle()
{
    while (start < end)
    {
        auto ch = *start;
        start++;
        switch (ch)
        {
        case 'B':
            return ctx.type_byte;
        case 'S':
            return ctx.type_short;
        case 'I':
            return ctx.type_int;
        case 'J':
            return ctx.type_long;
        case 'F':
            return ctx.type_float;
        case 'D':
            return ctx.type_double;
        case 'Z':
            return ctx.type_bool;
        case 'C':
            return ctx.type_char;
        case 'L':
            return demangle_class_ref();
        case '[':
            return demangle_array_ref();
        default:
            return nullptr;
        }
    }
    return nullptr;
}

Type* Demangler::demangle_field(string_view in)
{
    start = in.data();
    end   = in.data() + in.size();
    return demangle();
}

Type* Demangler::demangle_method(string_view in)
{
    constexpr uint32 MAX_NUMBER_OF_ARGS = 16;

    start = in.data();
    end   = in.data() + in.size();
    if (start == end || *start != '(')
        return nullptr;
    ++start;

    auto args    = ctx.alloc.alloc_array<Type*>(MAX_NUMBER_OF_ARGS);
    uint32 count = 0;
    while (start < end && *start != ')')
    {
        if (count == MAX_NUMBER_OF_ARGS)
            return nullptr;

        auto t = demangle();
        FCHECKNULL(t);
        args[count++] = t;
    }
    ++start;

    if (start == end)
        return nullptr;

    // should all of this be in demangle?
    Type* return_type = *start == 'V' ? ctx.type_void : demangle();
    FCHECKNULL(return_type);

    return ctx.alloc.alloc<MethodType>(return_type, args);
}

// ---------------------------------------------------- AstCreator ----------------------------------------------------

struct AstCreator
{
    ClassParser& class_parser;
    const vector<ConstantData>& constant_data;
    const vector<FieldInfo>& fields;
    const vector<MethodInfo>& methods;
    const vector<AttributeInfo>& attributes;
    AstContext ctx;
    Demangler demangler;

    AstCreator(ClassParser& class_parse);

    bool create();
    Field* create_field(const FieldInfo& raw_field);
    Method* create_method(const MethodInfo& raw_method);
    bool create_code(BufferView buffer);

    bool get_utf8(string_view& out, uint16 index);

    const ConstantData* get_constant(uint16 index, ConstantKind expect);
};

AstCreator::AstCreator(ClassParser& class_parser)
    : class_parser(class_parser), constant_data(class_parser.constant_data), fields(class_parser.fields), methods(class_parser.methods),
      attributes(class_parser.attributes), demangler(ctx)
{
}

bool AstCreator::create()
{
    auto clazz     = ctx.alloc.alloc<Class>();
    clazz->methods = ctx.alloc.alloc_array<Method*>(methods.size());
    uint32 count   = 0;
    for (auto& i : methods)
    {
        auto method = create_method(i);
        FCHECK(method);
        clazz->methods[count++] = method;
    }

    clazz->fields = ctx.alloc.alloc_array<Field*>(fields.size());
    count         = 0;
    for (auto& i : fields)
    {
        auto field = create_field(i);
        FCHECK(field);
        clazz->fields[count++] = field;
    }
    return true;
}

Field* AstCreator::create_field(const FieldInfo& raw_field)
{
    constexpr uint32 ACC_PUBLIC    = 0x0001;
    constexpr uint32 ACC_PRIVATE   = 0x0002;
    constexpr uint32 ACC_PROTECTED = 0x0004;
    constexpr uint32 ACC_STATIC    = 0x0008;
    constexpr uint32 ACC_FINAL     = 0x0010;
    constexpr uint32 ACC_VOLATILE  = 0x0040;
    constexpr uint32 ACC_TRANSIENT = 0x0080;
    constexpr uint32 ACC_SYNTHETIC = 0x1000;
    constexpr uint32 ACC_ENUM      = 0x4000;

    FieldAccessFlags flags;
    flags.acc_public    = raw_field.access_flags & ACC_PUBLIC;
    flags.acc_private   = raw_field.access_flags & ACC_PRIVATE;
    flags.acc_protected = raw_field.access_flags & ACC_PROTECTED;
    flags.acc_static    = raw_field.access_flags & ACC_STATIC;
    flags.acc_final     = raw_field.access_flags & ACC_FINAL;
    flags.acc_volatile  = raw_field.access_flags & ACC_VOLATILE;
    flags.acc_transient = raw_field.access_flags & ACC_TRANSIENT;
    flags.acc_synthetic = raw_field.access_flags & ACC_SYNTHETIC;
    flags.acc_enum      = raw_field.access_flags & ACC_ENUM;

    auto field          = ctx.alloc.alloc<Field>();
    field->access_flags = flags;

    FCHECKNULL(get_utf8(field->name, raw_field.name_index));
    string_view descriptor;
    FCHECKNULL(get_utf8(descriptor, raw_field.descriptor_index));
    field->type = demangler.demangle_field(descriptor);
    FCHECKNULL(field->type);

    field->unknown_attributes = 0;
    for (auto& i : raw_field.attributes)
    {
        string_view name;
        FCHECKNULL(get_utf8(name, i.attribute_name_index));

        field->unknown_attributes++;
    }

    return field;
}

Method* AstCreator::create_method(const MethodInfo& raw_method)
{
    constexpr uint32 ACC_PUBLIC       = 0x0001;
    constexpr uint32 ACC_PRIVATE      = 0x0002;
    constexpr uint32 ACC_PROTECTED    = 0x0004;
    constexpr uint32 ACC_STATIC       = 0x0008;
    constexpr uint32 ACC_FINAL        = 0x0010;
    constexpr uint32 ACC_SYNCHRONIZED = 0x0020;
    constexpr uint32 ACC_BRIDGE       = 0x0040;
    constexpr uint32 ACC_VARARGS      = 0x0080;
    constexpr uint32 ACC_NATIVE       = 0x0100;
    constexpr uint32 ACC_ABSTRACT     = 0x0400;
    constexpr uint32 ACC_STRICT       = 0x0800;
    constexpr uint32 ACC_SYNTHETIC    = 0x1000;

    MethodAccessFlags flags;
    flags.acc_public       = raw_method.access_flags & ACC_PUBLIC;
    flags.acc_private      = raw_method.access_flags & ACC_PRIVATE;
    flags.acc_protected    = raw_method.access_flags & ACC_PROTECTED;
    flags.acc_static       = raw_method.access_flags & ACC_STATIC;
    flags.acc_final        = raw_method.access_flags & ACC_FINAL;
    flags.acc_synchronized = raw_method.access_flags & ACC_SYNCHRONIZED;
    flags.acc_bridge       = raw_method.access_flags & ACC_BRIDGE;
    flags.acc_varargs      = raw_method.access_flags & ACC_VARARGS;
    flags.acc_native       = raw_method.access_flags & ACC_NATIVE;
    flags.acc_abstract     = raw_method.access_flags & ACC_ABSTRACT;
    flags.acc_strict       = raw_method.access_flags & ACC_STRICT;
    flags.acc_synthetic    = raw_method.access_flags & ACC_SYNTHETIC;

    auto method          = ctx.alloc.alloc<Method>();
    method->access_flags = flags;
    FCHECKNULL(get_utf8(method->name, raw_method.name_index));
    string_view descriptor;
    FCHECKNULL(get_utf8(descriptor, raw_method.descriptor_index));
    method->type = demangler.demangle_method(descriptor);
    FCHECKNULL(method->type);

    method->unknown_attributes = 0;
    for (auto& i : raw_method.attributes)
    {
        string_view name;
        FCHECKNULL(get_utf8(name, i.attribute_name_index));

        if (name == "Code")
        {
            FCHECKNULL(create_code(i.info));
        }
        else
            method->unknown_attributes++;
    }

    return method;
}

bool get_opcode(BufferReader& reader, Opcode& out);

bool AstCreator::create_code(BufferView buffer)
{
    CodeAttribute code;
    FCHECK(class_parser.parse_attribute_code(buffer, code));
    BufferReader reader(code.code.GetData(), code.code.GetLength());

    LocalString<4096> string;
    while (reader.has_more())
    {
        auto offset = reader.offset();
        Opcode op;
        FCHECK(get_opcode(reader, op));

        string.AddFormat("%zu. %s", offset, op.name);
        if (op.first_exists)
        {
            string.AddFormat(op.first_unsigned ? "%llu " : "%lld ", op.first);
        }
        if (op.second_exists)
        {
            string.AddFormat(op.second_unsigned ? "%llu " : "%lld ", op.second);
        }
        string.AddChar('\n');
    }

    printf("%.*s\n\n\n", string.Len(), string.GetText());
    return true;
}

bool AstCreator::get_utf8(string_view& out, uint16 index)
{
    auto data = get_constant(index, ConstantKind::Utf8);
    FCHECK(data);
    out = { data->utf8.bytes, data->utf8.length };
    return true;
}

const ConstantData* AstCreator::get_constant(uint16 index, ConstantKind expect)
{
    CHECK(index < constant_data.size(), nullptr, "bad index %u", index);
    auto& ret = constant_data[index];
    CHECK(ret.kind == expect, nullptr, "expected kind %u, found %u", expect, ret.kind);
    return &ret;
}

// ---------------------------------------------------- parse_class ----------------------------------------------------

bool parse_class(BufferView buffer)
{
    ClassParser parser{ { buffer.GetData(), buffer.GetLength() } };
    FCHECK(parser.parse());

    AstCreator creator{ parser };
    return creator.create();
}

} // namespace GView::Java