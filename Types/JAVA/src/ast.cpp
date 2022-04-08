#include "ast.hpp"

namespace GView::Java
{

BuiltinType::BuiltinType(BuiltinTypeKind kind)
{
    this->kind = kind;
}

AstContext::AstContext()
{
    type_byte   = alloc.alloc<BuiltinType>(BuiltinTypeKind::Byte);
    type_short  = alloc.alloc<BuiltinType>(BuiltinTypeKind::Short);
    type_int    = alloc.alloc<BuiltinType>(BuiltinTypeKind::Int);
    type_long   = alloc.alloc<BuiltinType>(BuiltinTypeKind::Long);
    type_float  = alloc.alloc<BuiltinType>(BuiltinTypeKind::Float);
    type_double = alloc.alloc<BuiltinType>(BuiltinTypeKind::Double);
    type_bool   = alloc.alloc<BuiltinType>(BuiltinTypeKind::Bool);
    type_char   = alloc.alloc<BuiltinType>(BuiltinTypeKind::Char);
}

ClassReferenceType::ClassReferenceType(string_view name)
{
    this->name = name;
}

ArrayReferenceType::ArrayReferenceType(Type* subtype)
{
    this->subtype = subtype;
}

} // namespace GView::Java