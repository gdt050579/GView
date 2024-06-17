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
  public:
    struct Value {
        enum class Type { Undefined, Number, String } type;

        std::variant<int32, std::u16string> value;
        bool lval;

        Value() : type(Type::Undefined), lval(false)
        {
        }
    };

    private:

    std::vector<std::unordered_map<std::u16string_view, Value>> vars;

    Value lastResult;

    uint32 limit;

  public:
    Emulator(uint32 limit) : limit(limit)
    {
    }

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
        uint32 it = 0;

        do {
            node->cond->AcceptConst(*this);

            auto cond = lastResult;

            if (IsTruthy(cond)) {
                node->stmt->AcceptConst(*this);
            } else {
                break;
            }

            ++it;
        } while (it < limit);
    }
    void VisitForStmt(const AST::ForStmt* node)
    {
        if (node->decl) {
            node->decl->AcceptConst(*this);
        }

        uint32 it = 0;

        do {
            if (node->cond) {
                node->cond->AcceptConst(*this);

                auto cond = lastResult;

                if (!IsTruthy(cond)) {
                    break;
                }
            }

            node->stmt->AcceptConst(*this);

            if (node->inc) {
                node->inc->AcceptConst(*this);
            }

            ++it;
        } while (it < limit);
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
        auto callee = node->callee;

        if (callee->GetExprType() == AST::ExprType::MemberAccess) {
            auto access = (AST::MemberAccess*) callee;

            auto objIsId    = (access->obj->GetExprType() == AST::ExprType::Identifier);
            auto memberIsId = (access->member->GetExprType() == AST::ExprType::Identifier);

            if (memberIsId) {
                auto member = (AST::Identifier*) access->member;

                if (objIsId) {
                    auto obj = (AST::Identifier*) access->obj;

                    if (obj->name == u"String") {
                        if (member->name == u"fromCharCode") {
                            if (node->args.size() == 1) {
                                node->args[0]->AcceptConst(*this);

                                if (lastResult.type == Value::Type::Number) {
                                    EvalStringFromCharCode(std::get<int32>(lastResult.value));
                                    return;
                                }
                            }
                        }
                    }
                }

                access->obj->AcceptConst(*this);

                auto left = lastResult;

                // TODO: arr
                switch (left.type) {
                case Value::Type::String: {
                    auto val = std::get<std::u16string>(left.value);

                    if (member->name == u"charCodeAt") {
                        if (node->args.size() == 1) {
                            node->args[0]->AcceptConst(*this);

                            EvalStringCharCodeAt(val, std::get<int32>(lastResult.value));
                        }
                    }
                    break;
                }
                case Value::Type::Undefined: {
                    return;
                }
                }
            }
        }

        // TODO: visit callee and call the function
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
        node->obj->AcceptConst(*this);

        auto obj = lastResult;

        if (obj.type == Value::Type::Undefined) {
            lastResult = Value();
            return;
        }

        if (node->member->GetExprType() == AST::ExprType::Identifier) {
            auto member = (AST::Identifier*) node->member;

            if (member->name == u"length") {
                if (obj.type != Value::Type::String) {
                    lastResult = Value();
                    return;
                }

                EvalStringLength(std::get<std::u16string>(obj.value));
                return;
            }
        }

        node->member->AcceptConst(*this);

        auto member = lastResult;

        if (member.type == Value::Type::Undefined) {
            lastResult = Value();
            return;
        }

        // TODO: support for arrays
        lastResult = Value();
    }
    void VisitNumber(const AST::Number* node)
    {
        lastResult.type  = Value::Type::Number;
        lastResult.value = node->value;
    }
    void VisitString(const AST::String* node)
    {
        lastResult.type  = Value::Type::String;
        lastResult.value                = node->value;

        // Process escape sequences
        ProcessString(std::get<std::u16string>(lastResult.value));
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

    bool IsTruthy(Value& val)
    {
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

    // TODO: use them from GView Core
    bool IsHex(char16 ch)
    {
        return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f');
    }

    char16 HexCharToValue(char16 ch)
    {
        if (ch >= '0' && ch <= '9')
            return (ch - '0');
        if (ch >= 'A' && ch <= 'F')
            return (ch + 10 - 'A');
        if (ch >= 'a' && ch <= 'f')
            return (ch + 10 - 'a');
        return 0;
    }

    void ProcessString(std::u16string& str)
    {
        for (auto i = 0u; i < str.size(); i++) {
            if (str[i] != '\\')
                continue;
            if (str[i + 1] == 'x' && IsHex(str[i + 2]) && IsHex(str[i + 3])) {
                str[i] = HexCharToValue(str[i + 2]) * 0x10 + HexCharToValue(str[i + 3]);
                str.erase(i + 1, 3);
                continue;
            }
            if (str[i + 1] == 'u' && IsHex(str[i + 2]) && IsHex(str[i + 3]) && IsHex(str[i + 4]) && IsHex(str[i + 5])) {
                str[i] =
                      HexCharToValue(str[i + 2]) * 0x1000 + HexCharToValue(str[i + 3]) * 0x100 + HexCharToValue(str[i + 4]) * 0x10 + HexCharToValue(str[i + 5]);
                str.erase(i + 1, 5);
                continue;
            }
        }
    }

    void EvalStringLength(std::u16string_view str)
    {
        lastResult.type = Value::Type::Number;
        lastResult.value = (int32) str.size();
        lastResult.lval  = false;
    }

    void EvalStringFromCharCode(int32 arg)
    {
        std::u16string result;
        result += (char16_t) arg;

        lastResult.type  = Value::Type::String;
        lastResult.value = result;
        lastResult.lval  = false;
    }

    void EvalStringCharCodeAt(std::u16string_view callee, int32 arg)
    {
        if (arg >= callee.size()) {
            return;
        }

        auto chr = callee[arg];

        lastResult.type  = Value::Type::Number;
        lastResult.value = (int32) chr;
        lastResult.lval  = false;
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
            switch (left.type) {
            case Value::Type::Number: {
                switch (right.type) {
                case Value::Type::Number: {
                    Eval(std::get<int32>(left.value), std::get<int32>(right.value), extra);
                    break;
                }
                case Value::Type::String: {
                    Eval(std::get<int32>(left.value), std::get<std::u16string>(right.value), extra);
                    break;
                }
                }
                break;
            }
            case Value::Type::String: {
                switch (right.type) {
                case Value::Type::Number: {
                    Eval(std::get<std::u16string>(left.value), std::get<int32>(right.value), extra);
                    break;
                }
                case Value::Type::String: {
                    Eval(std::get<std::u16string>(left.value), std::get<std::u16string>(right.value), extra);
                    break;
                }
                }
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

        (*scope)[lval->name]      = lastResult;
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
            result = left % right;
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

        lastResult.type  = Value::Type::Number;
        lastResult.value = result;
        lastResult.lval  = false;
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

            lastResult.type  = Value::Type::String;
            lastResult.value = result;
            lastResult.lval  = false;
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
            lastResult.lval  = false;
            return;
        }
        }

        lastResult.type = Value::Type::Undefined;
    }

    void Eval(std::u16string_view left, std::u16string_view right, uint32 op)
    {
        switch (op) {
        case TokenType::Operator_Plus: {
            lastResult.type  = Value::Type::String;
            lastResult.value = std::u16string();
            lastResult.lval  = false;

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

class EmulateWindow : public AppCUI::Controls::Window
{
    const int BUTTON_ID_EXECUTE = 1;

    Reference<NumericSelector> limit;
    Reference<TextField> target;

  public:
    EmulateWindow() : Window("Emulate", "d:c,w:30,h:11", WindowFlags::ProcessReturn)
    {
        Factory::Button::Create(this, "Execute", "x:10,y:7,w:11", BUTTON_ID_EXECUTE);

        limit = Factory::NumericSelector::Create(this, 1, 50, 10, "x:5,y:2,w:19,h:5");
        Factory::Label::Create(this, "Max Iterations", "x:5,y:1,w:20,h:5");

        target = Factory::TextField::Create(this, "", "x:5,y:5,w:19,h:1");
        Factory::Label::Create(this, "Target Variable", "x:5,y:4,w:20,h:5");
    }

    bool OnEvent(Reference<Control>, Event eventType, int controlID) override
    {
        switch (eventType) {
        case Event::WindowClose: {
            Exit(Dialogs::Result::Cancel);
            return true;
        }
        case Event::ButtonClicked: {
            if (controlID == BUTTON_ID_EXECUTE) {
                Exit(Dialogs::Result::Ok);
                return true;
            }
            break;
        }
        case Event::WindowAccept: {
            Exit(Dialogs::Result::Ok);
            return true;
        }
        }

        return false;
    }

    uint32 GetLimit()
    {
        return limit->GetValue();
    }

    std::u16string GetTarget()
    {
        std::u16string result;
        target->GetText().ToString(result);

        return result;
    }
};

GView::View::LexicalViewer::PluginAfterActionRequest Emulate::Execute(GView::View::LexicalViewer::PluginData& data)
{
    EmulateWindow dlg;
    auto result = static_cast<AppCUI::Dialogs::Result>(dlg.Show());

    if (result != Dialogs::Result::Ok) {
        return PluginAfterActionRequest::None;
    }

    auto limit = dlg.GetLimit();
    auto target = dlg.GetTarget();

    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    // return PluginAfterActionRequest::None;

    Emulator emulator(limit);

    // TODO: instance should also handle the action for the script block
    i.script->AcceptConst(emulator);

    auto val = emulator.GetVarValue(target);

    std::u16string title = u"Value of ";
    title += target;

    std::u16string value;

    switch (val.type) {
    case Emulator::Value::Type::Undefined: {
        value = u"undefined";
        break;
    }
    case Emulator::Value::Type::String: {
        value = std::get<std::u16string>(val.value);
        break;
    }
    case Emulator::Value::Type::Number: {
        auto n = std::get<int32>(val.value);

        AppCUI::Utils::UnicodeStringBuilder builder;
        AppCUI::Utils::NumericFormatter fmt;

        builder.Add(fmt.ToDec(n));

        builder.ToString(value);

        break;
    }
    default: {
        value = u"?";
        break;
    }
    }

    AppCUI::Dialogs::MessageBox::ShowNotification(title, value);

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins