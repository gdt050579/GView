#include "js.hpp"
#include "ast.hpp"

#include <stack>
#include <variant>

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;
using namespace GView::Type::JS;

std::string_view Emulate::GetName()
{
    return "Emulate";
}
std::string_view Emulate::GetDescription()
{
    return "Emulate code.";
}
bool Emulate::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

class Emulator : public AST::ConstVisitor
{
    struct Value {
        enum class Type {
            Undefined,
            Number,
            String
        } type;

        std::variant<int32, std::u16string> value;
        bool lval;

        Value() : type(Type::Undefined), lval(false)
        {
        }
    };

    std::vector<std::unordered_map<std::u16string_view, Value>> vars;

    Value lastResult;

  public:
    void VisitVarDeclList(const AST::VarDeclList* node)
    {
        for (auto decl : node->decls) {
            decl->AcceptConst(*this);
        }
    }
    void VisitVarDecl(const AST::VarDecl* node)
    {
        GetBlockVars()[node->name] = Value();

        if (node->init) {
            node->init->AcceptConst(*this);

            GetBlockVars()[node->name] = lastResult;
        }

        GetBlockVars()[node->name].lval = true;
    }
    void VisitBlock(const AST::Block* node)
    {
        vars.emplace_back();

        for (auto decl : node->decls) {
            decl->AcceptConst(*this);
        }

        if (vars.size() > 1) {
            vars.pop_back();
        }
    }
    void VisitIfStmt(const AST::IfStmt* node)
    {
        node->cond->AcceptConst(*this);

        auto cond = lastResult;

        if (IsTruthy(cond)) {
            node->stmtTrue->AcceptConst(*this);
        } else if (node->stmtFalse) {
            node->stmtFalse->AcceptConst(*this);
        }
    }
    void VisitWhileStmt(const AST::WhileStmt* node)
    {
        
    }
    void VisitForStmt(const AST::ForStmt* node)
    {
        
    }
    void VisitReturnStmt(const AST::ReturnStmt* node)
    {
        
    }
    void VisitExprStmt(const AST::ExprStmt* node)
    {
        node->expr->AcceptConst(*this);
    }
    void VisitIdentifier(const AST::Identifier* node)
    {
        lastResult = GetVarValue(node->name);
    }
    void VisitUnop(const AST::Unop* node)
    {
        
    }
    void VisitBinop(const AST::Binop* node)
    {
        node->left->AcceptConst(*this);

        if (lastResult.type == Value::Type::Undefined) {
            return;
        }

        auto left = lastResult;

        node->right->AcceptConst(*this);

        if (lastResult.type == Value::Type::Undefined) {
            return;
        }

        auto right = lastResult;

        if (left.lval) {
            if (node->type >= TokenType::Operator_Assignment && node->type <= TokenType::Operator_LogicNullishAssignment) {
                EvalAssignment(node->left, right, node->type);
                return;
            }
        }

        Eval(left, right, node->type);
    }
    void VisitTernary(const AST::Ternary* node)
    {
        
    }
    void VisitCall(const AST::Call* node)
    {
        
    }
    void VisitLambda(const AST::Lambda* node)
    {
        
    }
    void VisitGrouping(const AST::Grouping* node)
    {
        
    }
    void VisitCommaList(const AST::CommaList* node)
    {
        
    }
    void VisitMemberAccess(const AST::MemberAccess* node)
    {
        
    }
    void VisitNumber(const AST::Number* node)
    {
        lastResult.type = Value::Type::Number;
        lastResult.value = node->value;
    }
    void VisitString(const AST::String* node)
    {
        lastResult.type  = Value::Type::String;
        lastResult.value = node->value;
    }

    Value GetVarValue(std::u16string_view name)
    {
        for (auto it = vars.rbegin(); it != vars.rend(); ++it) {
            if (it->find(name) != it->end()) {
                return (*it)[name];
            }
        }

        return Value();
    }

    std::unordered_map<std::u16string_view, Value>* GetVarScope(std::u16string_view name)
    {
        for (auto it = vars.rbegin(); it != vars.rend(); ++it) {
            if (it->find(name) != it->end()) {
                return &(*it);
            }
        }

        return nullptr;
    }

    private:
    std::unordered_map<std::u16string_view, Value>& GetBlockVars()
    {
        return vars[vars.size() - 1];
    }

    bool IsTruthy(Value& val) {
        switch (val.type) {
        case Value::Type::Number: {
            return std::get<int32>(val.value) != 0;
        }
        case Value::Type::String: {
            return std::get<std::u16string>(val.value).size() > 0;
        }
        }

        return false;
    }

    void EvalAssignment(AST::Identifier* lval, Value right, uint32 op)
    {
        auto left = GetVarValue(lval->name);

        uint32 extra = 0;
        lastResult   = right;

        switch (op) {
        case TokenType::Operator_PlusAssignment: {
            extra = TokenType::Operator_Plus;
            break;
        }
        case TokenType::Operator_MinusAssignment: {
            extra = TokenType::Operator_Minus;
            break;
        }
        case TokenType::Operator_MupliplyAssignment: {
            extra = TokenType::Operator_Multiply;
            break;
        }
        case TokenType::Operator_DivisionAssignment: {
            extra = TokenType::Operator_Division;
            break;
        }
        case TokenType::Operator_ModuloAssignment: {
            extra = TokenType::Operator_Modulo;
            break;
        }
        case TokenType::Operator_ExponentiationAssignment: {
            extra = TokenType::Operator_Exponential;
            break;
        }
        case TokenType::Operator_LeftShiftAssignment: {
            extra = TokenType::Operator_LeftShift;
            break;
        }
        case TokenType::Operator_RightShiftAssignment: {
            extra = TokenType::Operator_RightShift;
            break;
        }
        case TokenType::Operator_UnsignedRightShiftAssignment: {
            extra = TokenType::Operator_SignRightShift;
            break;
        }
        case TokenType::Operator_AndAssignment: {
            extra = TokenType::Operator_AND;
            break;
        }
        case TokenType::Operator_XorAssignment: {
            extra = TokenType::Operator_XOR;
            break;
        }
        case TokenType::Operator_OrAssignment: {
            extra = TokenType::Operator_OR;
            break;
        }
        case TokenType::Operator_LogicANDAssignment: {
            extra = TokenType::Operator_LogicAND;
            break;
        }
        case TokenType::Operator_LogicORAssignment: {
            extra = TokenType::Operator_LogicOR;
            break;
        }
        }

        if (extra != 0) {
            auto& leftVal = std::get<std::u16string>(left.value);

            switch (right.type) {
            case Value::Type::Number: {
                Eval(leftVal, std::get<int32>(right.value), extra);
                break;
            }
            case Value::Type::String:
                {
                Eval(leftVal, std::get<std::u16string>(right.value), extra);
                break;
            }
            }
        }

        if (lastResult.type == Value::Type::Undefined) {
            return;
        }

        auto scope = GetVarScope(lval->name);

        if (!scope) {
            lastResult.type = Value::Type::Undefined;
            return;
        }

        (*scope)[lval->name] = lastResult;
        (*scope)[lval->name].lval = true;
    }

    void EvalAssignment(AST::Expr* lval, Value right, uint32 op)
    {
        switch (lval->GetExprType()) {
        case AST::ExprType::Identifier: {
            EvalAssignment((AST::Identifier*) lval, right, op);
            return;
        }
        }

        lastResult.type = Value::Type::Undefined;
    }

    void Eval(int32 left, int32 right, uint32 op)
    {
        int32 result = 0;

        switch (op) {
        case TokenType::Operator_LogicOR: {
            result = left || right;
            break;
        }
        case TokenType::Operator_LogicAND: {
            result = left && right;
            break;
        }
        case TokenType::Operator_OR: {
            result = left | right;
            break;
        }
        case TokenType::Operator_XOR: {
            result = left ^ right;
            break;
        }
        case TokenType::Operator_AND: {
            result = left & right;
            break;
        }
        case TokenType::Operator_Equal:
        case TokenType::Operator_StrictEqual: {
            result = left == right;
            break;
        }
        case TokenType::Operator_Different:
        case TokenType::Operator_StrictDifferent: {
            result = left != right;
            break;
        }
        case TokenType::Operator_Smaller: {
            result = left < right;
            break;
        }
        case TokenType::Operator_SmallerOrEQ: {
            result = left <= right;
            break;
        }
        case TokenType::Operator_Bigger: {
            result = left > right;
            break;
        }
        case TokenType::Operator_BiggerOrEq: {
            result = left >= right;
            break;
        }
        case TokenType::Operator_LeftShift: {
            result = left << right;
            break;
        }
        case TokenType::Operator_RightShift: {
            result = left >> right;
            break;
        }
        case TokenType::Operator_SignRightShift: {
            result = left >> right;
            break;
        }
        case TokenType::Operator_Plus: {
            result = left + right;
            break;
        }
        case TokenType::Operator_Minus: {
            result = left - right;
            break;
        }
        case TokenType::Operator_Multiply: {
            result = left * right;
            break;
        }
        case TokenType::Operator_Division: {
            if (right == 0) {
                lastResult = Value();
                return;
            }
            result = left / right;
            break;
        }
        case TokenType::Operator_Modulo: {
            if (right == 0) {
                lastResult = Value();
                return;
            }
            result = left & right;
            break;
        }
        case TokenType::Operator_Exponential: {
            result = (int32) pow(left, right);
            break;
        }
        default: {
            lastResult = Value();
            return;
        }
        }

        lastResult.type = Value::Type::Number;
        lastResult.value = result;
    }

    void Eval(int32 left, std::u16string_view right, uint32 op)
    {
        switch (op) {
        case TokenType::Operator_Plus: {
            AppCUI::Utils::UnicodeStringBuilder builder;
            AppCUI::Utils::NumericFormatter fmt;

            builder.Add(fmt.ToDec(left));
            builder.Add(right);

            std::u16string result;
            builder.ToString(result);

            lastResult.type = Value::Type::String;
            lastResult.value = result;
            return;
        }
        }

        lastResult.type = Value::Type::Undefined;
    }

    void Eval(std::u16string_view left, int32 right, uint32 op)
    {
        switch (op) {
        case TokenType::Operator_Plus: {
            AppCUI::Utils::UnicodeStringBuilder builder;
            AppCUI::Utils::NumericFormatter fmt;

            builder.Add(left);
            builder.Add(fmt.ToDec(right));

            std::u16string result;
            builder.ToString(result);

            lastResult.type  = Value::Type::String;
            lastResult.value = result;
            return;
        }
        }

        lastResult.type = Value::Type::Undefined;
    }

    void Eval(std::u16string_view left, std::u16string_view right, uint32 op)
    {
        switch (op) {
        case TokenType::Operator_Plus: {
            lastResult.type = Value::Type::String;
            lastResult.value = std::u16string();

            std::get<std::u16string>(lastResult.value) += left;
            std::get<std::u16string>(lastResult.value) += right;
            return;
        }
        }

        lastResult.type = Value::Type::Undefined;
    }

    void Eval(Value& left, Value& right, uint32 op)
    {
        switch (left.type) {
        case Value::Type::Number: {
            switch (right.type) {
            case Value::Type::Number: {
                Eval(std::get<int32>(left.value), std::get<int32>(right.value), op);
                return;
            }
            case Value::Type::String: {
                Eval(std::get<int32>(left.value), std::get<std::u16string>(right.value), op);
                return;
            }
            }
            break;
        }
        case Value::Type::String: {
            switch (right.type) {
            case Value::Type::Number: {
                Eval(std::get<std::u16string>(left.value), std::get<int32>(right.value), op);
                return;
            }
            case Value::Type::String: {
                Eval(std::get<std::u16string>(left.value), std::get<std::u16string>(right.value), op);
                return;
            }
            }
            break;
        }
        }

        lastResult = Value();
    }
};

GView::View::LexicalViewer::PluginAfterActionRequest Emulate::Execute(GView::View::LexicalViewer::PluginData& data)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    // return PluginAfterActionRequest::None;

    Emulator emulator;

    // TODO: instance should also handle the action for the script block
    i.script->AcceptConst(emulator);

    auto val = emulator.GetVarValue(u"z");

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins