#include "global.hpp"

namespace GView::Java
{

enum ConstantKind : uint8
{
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

struct ConstantData
{
    ConstantKind kind;
    union
    {
        CONSTANT_Field_Interface_Methodref_info field_interface_method;
        CONSTANT_Class_info clazz;
        CONSTANT_NameAndType_info name_and_type;
        CONSTANT_Utf8_info utf8;
    };
};

struct AttributeInfo
{
    uint16 attribute_name_index;
    BufferView info;
};

struct MethodInfo
{
    uint16 access_flags;
    uint16 name_index;
    uint16 descriptor_index;
    vector<AttributeInfo> attributes;
};

struct ClassParser
{
    BufferReader reader;
    vector<ConstantData> constant_data;
    vector<MethodInfo> methods;
    vector<AttributeInfo> attributes;

    ClassParser(BufferReader reader);

    bool parse();
    bool parse_constant_pool();
    bool parse_method();
    bool parse_attribute(AttributeInfo& out);
};

ClassParser::ClassParser(BufferReader reader) : reader(reader)
{
    constant_data.reserve(64);
}

bool Java::parse_class(BufferView buffer)
{
    ClassParser parser{ { buffer.GetData(), buffer.GetLength() } };
    return parser.parse();
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
        unreachable;
    }

    uint16 methods_count;
    READB(methods_count);
    for (uint16 i = 0; i < methods_count; ++i)
    {
        FCHECK(parse_method());
    }

    uint16 attributes_count;
    READB(attributes_count);
    for (uint16 i = 0; i < attributes_count; ++i)
    {
        AttributeInfo attribute;
        FCHECK(parse_attribute(attribute));
        attributes.push_back(attribute);
    }

    return true;
}

bool ClassParser::parse_constant_pool()
{
    uint8 tag;
    READB(tag);

    ConstantData data;
    data.kind = static_cast<ConstantKind>(tag);
    switch (tag)
    {
    case MethodRef:
    case FieldRef:
    case InterfaceMethodRef:
        FCHECK(data.field_interface_method.read(reader));
        break;
    case Class:
        FCHECK(data.clazz.read(reader));
        break;
    case NameAndType:
        FCHECK(data.name_and_type.read(reader));
        break;
    case Utf8:
        FCHECK(data.utf8.read(reader));
        break;
    default:
        unreachable;
    }

    constant_data.push_back(data);
    return true;
}

bool ClassParser::parse_method()
{
    MethodInfo method;
    READB(method.access_flags);
    READB(method.name_index);
    READB(method.descriptor_index);
    uint16 attributes_count;
    READB(attributes_count);
    for (uint16 i = 0; i < attributes_count; ++i)
    {
        AttributeInfo attribute;
        FCHECK(parse_attribute(attribute));
        method.attributes.push_back(attribute);
    }

    methods.push_back(method);
    return true;
}

bool ClassParser::parse_attribute(AttributeInfo& out)
{
    READB(out.attribute_name_index);
    uint32 attribute_length;
    READB(attribute_length);
    out.info = { reader.get(), attribute_length };
    SKIP(attribute_length);

    return true;
}

} // namespace GView::Java