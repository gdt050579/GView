#include "js.hpp"
#include "ast.hpp"
#include "Transformers/DynamicPropagator.hpp"

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;

std::string_view UnrollLoop::GetName()
{
    return "Unroll Loop";
}
std::string_view UnrollLoop::GetDescription()
{
    return "Unroll loop with a fixed amount of iterations.";
}
bool UnrollLoop::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    // Only on 'for' tokens.
    auto end = std::min<>(data.tokens.Len(), data.endIndex);

    return (end - data.startIndex >= 1 && data.tokens[data.startIndex].GetTypeID(TokenType::None) == TokenType::Keyword_For);
}

typedef uint32 (*BinopIncFn)(uint32, uint32);

uint32 EvalPlusAssignment(uint32 left, uint32 right)
{
    return left + right;
}

uint32 EvalMinusAssignment(uint32 left, uint32 right)
{
    return left - right;
}

uint32 EvalMultiplyAssignment(uint32 left, uint32 right)
{
    return left * right;
}

uint32 EvalDivideAssignment(uint32 left, uint32 right)
{
    return left / right;
}

uint32 EvalModuloAssignment(uint32 left, uint32 right)
{
    return left % right;
}

typedef uint32 (*UnopIncFn)(uint32);

uint32 EvalIncrement(uint32 left)
{
    return left++;
}

uint32 EvalDecrement(uint32 left)
{
    return left--;
}

typedef bool (*ComparisonFn)(uint32, uint32);

bool EvalLess(uint32 left, uint32 right)
{
    return left < right;
}

bool EvalLessEqual(uint32 left, uint32 right)
{
    return left <= right;
}

bool EvalGreater(uint32 left, uint32 right)
{
    return left > right;
}

bool EvalGreaterEqual(uint32 left, uint32 right)
{
    return left >= right;
}

bool AlwaysTrue(uint32 left, uint32 right)
{
    return true;
}

class LoopUnroller : public AST::Plugin
{
    uint32 offset;
    uint32 limit;

  public:
    LoopUnroller(uint32 offset, uint32 limit) : offset(offset), limit(limit)
    {
    }

    AST::Action OnEnterForStmt(AST::ForStmt* node, AST::Stmt*& replacement)
    {
        if (node->sourceOffset != offset) {
            return AST::Action::None;
        }

        auto list = node->decl;

        if (list->GetDeclType() != AST::DeclType::Var) {
            return AST::Action::None;
        }

        auto decls = ((AST::VarDeclList*) list)->decls;

        if (decls.empty()) {
            return AST::Action::None;
        }

        auto decl = (AST::VarDecl*) decls[0];

        if (decl->init == nullptr) {
            return AST::Action::None;
        }

        if (decl->init->GetExprType() != AST::ExprType::Constant) {
            return AST::Action::None;
        }

        auto init = (AST::Constant*) decl->init;

        if (init->GetConstType() != AST::ConstType::Number) {
            return AST::Action::None;
        }

        auto start = ((AST::Number*) init)->value;

        ComparisonFn comparison;
        uint32 condValue = 0;

        if (node->cond == nullptr) {
            comparison = AlwaysTrue;
        } else {
            if (node->cond->GetExprType() != AST::ExprType::Binop) {
                return AST::Action::None;
            }

            auto binop = (AST::Binop*) node->cond;

            if (binop->left->GetExprType() != AST::ExprType::Identifier) {
                return AST::Action::None;
            }

            if (((AST::Identifier*) binop->left)->name != decl->name) {
                return AST::Action::None;
            }

            switch (binop->type) {
            case TokenType::Operator_Smaller:
                comparison = EvalLess;
                break;
            case TokenType::Operator_SmallerOrEQ:
                comparison = EvalLessEqual;
                break;
            case TokenType::Operator_Bigger:
                comparison = EvalGreater;
                break;
            case TokenType::Operator_BiggerOrEq:
                comparison = EvalGreaterEqual;
                break;
            default:
                return AST::Action::None;
            }

            if (binop->right->GetExprType() != AST::ExprType::Constant) {
                return AST::Action::None;
            }

            if (((AST::Constant*) binop->right)->GetConstType() != AST::ConstType::Number) {
                return AST::Action::None;
            }

            condValue = ((AST::Number*) binop->right)->value;
        }

        if (node->inc == nullptr) {
            return AST::Action::None;
        }

        switch (node->inc->GetExprType()) {
        case AST::ExprType::Binop: {
            auto binop = (AST::Binop*) node->inc;

            if (binop->left->GetExprType() != AST::ExprType::Identifier) {
                return AST::Action::None;
            }

            if (((AST::Identifier*) binop->left)->name != decl->name) {
                return AST::Action::None;
            }

            BinopIncFn inc;

            switch (binop->type) {
            case TokenType::Operator_PlusAssignment:
                inc = EvalPlusAssignment;
                break;
            case TokenType::Operator_MinusAssignment:
                inc = EvalMinusAssignment;
                break;
            case TokenType::Operator_MupliplyAssignment:
                inc = EvalMultiplyAssignment;
                break;
            case TokenType::Operator_DivisionAssignment:
                inc = EvalDivideAssignment;
                break;
            case TokenType::Operator_ModuloAssignment:
                inc = EvalModuloAssignment;
                break;
            default:
                return AST::Action::None;
            }

            if (binop->right->GetExprType() != AST::ExprType::Constant) {
                return AST::Action::None;
            }

            if (((AST::Constant*) binop->right)->GetConstType() != AST::ConstType::Number) {
                return AST::Action::None;
            }

            auto incValue = ((AST::Number*) binop->right)->value;

            auto iterator = start;

            auto block = new AST::Block;

            for (uint32 i = 0; i < limit; ++i) {
                if (!comparison(iterator, condValue)) {
                    break;
                }

                auto inner = node->stmt->Clone();
                Transformers::DynamicPropagator propagator;

                auto val = new AST::Number(iterator);

                propagator.AddVar(decl->name, val);

                AST::PluginVisitor visitor(&propagator, nullptr);

                AST::Node* rep;
                inner->Accept(visitor, rep);

                block->decls.emplace_back(inner);

                delete val;

                iterator = inc(iterator, incValue);
            }

            replacement = block;
            return AST::Action::Replace;
        }
        case AST::ExprType::Unop: {
            auto unop = (AST::Unop*) node->inc;

            if (unop->expr->GetExprType() != AST::ExprType::Identifier) {
                return AST::Action::None;
            }

            if (((AST::Identifier*) unop->expr)->name != decl->name) {
                return AST::Action::None;
            }

            UnopIncFn inc;

            switch (unop->type) {
            case TokenType::Operator_Increment:
                inc = EvalIncrement;
                break;
            case TokenType::Operator_Decrement:
                inc = EvalDecrement;
                break;
            default:
                return AST::Action::None;
            }

            auto iterator = start;

            auto block = new AST::Block;

            for (uint32 i = 0; i < limit; ++i) {
                if (!comparison(iterator, condValue)) {
                    break;
                }

                auto inner = node->stmt->Clone();
                Transformers::DynamicPropagator propagator;

                auto val = new AST::Number(iterator);

                propagator.AddVar(decl->name, val);

                AST::PluginVisitor visitor(&propagator, nullptr);

                AST::Node* rep;
                inner->Accept(visitor, rep);

                block->decls.emplace_back(inner);

                delete val;

                iterator = inc(iterator);
            }

            replacement = block;
            return AST::Action::Replace;
        }
        default: {
            return AST::Action::None;
        }
        }

        return AST::Action::None;
    }
};

class UnrollLoopWindow : public AppCUI::Controls::Window
{
    const int BUTTON_ID_EXECUTE = 1;

    Reference<NumericSelector> limit;
  public:
    UnrollLoopWindow() : Window("Unroll Loop", "d:c,w:30,h:8", WindowFlags::ProcessReturn)
    {
        Factory::Button::Create(this, "Execute", "x:10,y:4,w:11", BUTTON_ID_EXECUTE);

        limit = Factory::NumericSelector::Create(this, 1, 50, 10, "x:5,y:2,w:19,h:5");
        Factory::Label::Create(this, "Max Iterations", "x:5,y:1,w:20,h:5");
    }

    bool OnEvent(Reference<Control>, Event eventType, int controlID) override
    {
        if (eventType == Event::WindowClose) {
            Exit(Dialogs::Result::Cancel);
            return true;
        }

        if (eventType == Event::ButtonClicked) {
            if (controlID == BUTTON_ID_EXECUTE) {
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
};

GView::View::LexicalViewer::PluginAfterActionRequest UnrollLoop::Execute(GView::View::LexicalViewer::PluginData& data)
{
    UnrollLoopWindow dlg;
    auto result = static_cast<AppCUI::Dialogs::Result>(dlg.Show());

    if (result != Dialogs::Result::Ok) {
        return PluginAfterActionRequest::None;
    }

    auto limit = dlg.GetLimit();

    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    // return PluginAfterActionRequest::None;

    auto start = data.tokens[data.startIndex].GetTokenStartOffset();

    if (!start.has_value()) {
        return PluginAfterActionRequest::None;
    }

    LoopUnroller unroller(start.value(), limit);
    AST::PluginVisitor visitor(&unroller, &data.editor);

    // TODO: instance should also handle the action for the script block
    AST::Node* _rep;
    i.script->Accept(visitor, _rep);

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins
//GView::View::LexicalViewer::PluginAfterActionRequest UnrollLoop::Execute(GView::View::LexicalViewer::PluginData& data)
//{
//    auto start = data.startIndex + 1; // for ( ...
//                                      // 0   1 2
//
//    auto index = start;
//    AppCUI::uint32 type;
//
//#define ADVANCE()                                                                                                                                              \
//    do {                                                                                                                                                       \
//        ++index;                                                                                                                                               \
//        if (index >= data.tokens.Len()) {                                                                                                                      \
//            return PluginAfterActionRequest::None;                                                                                                             \
//        }                                                                                                                                                      \
//        type = data.tokens[index].GetTypeID(TokenType::None);                                                                                                  \
//    } while (false)
//    // ADVANCE
//
//#define EXPECT(typ)                                                                                                                                            \
//    do {                                                                                                                                                       \
//        if (type != TokenType::typ) {                                                                                                                          \
//            return PluginAfterActionRequest::None;                                                                                                             \
//        }                                                                                                                                                      \
//    } while (false)
//    // EXPECT
//
//    ADVANCE();
//
//    // var/let
//    if (type == TokenType::DataType_Var || type == TokenType::DataType_Let) {
//        ADVANCE();
//    }
//
//    // i
//    EXPECT(Word);
//
//    auto iteratorName = data.tokens[index];
//
//    ADVANCE();
//
//    // =
//    EXPECT(Operator_Assignment);
//
//    ADVANCE();
//
//    // start
//    EXPECT(Number);
//
//    AppCUI::Utils::String iteratorStartStr;
//    iteratorStartStr.Set(data.tokens[index].GetText());
//
//    auto iteratorStartOpt = AppCUI::Utils::Number::ToInt32(iteratorStartStr);
//
//    if (!iteratorStartOpt.has_value()) {
//        return PluginAfterActionRequest::None;
//    }
//
//    auto iteratorStart = iteratorStartOpt.value();
//
//    ADVANCE();
//
//    // ;
//    EXPECT(Semicolumn);
//
//    ADVANCE();
//
//    // i
//    EXPECT(Word);
//
//    if (iteratorName.GetText() != data.tokens[index].GetText()) {
//        return PluginAfterActionRequest::None;
//    }
//
//    ADVANCE();
//
//    // <
//    EXPECT(Operator_Smaller);
//
//    ADVANCE();
//
//    // end
//    EXPECT(Number);
//
//    AppCUI::Utils::String iteratorEndStr;
//    iteratorEndStr.Set(data.tokens[index].GetText());
//
//    auto iteratorEndOpt = AppCUI::Utils::Number::ToInt32(iteratorEndStr);
//
//    if (!iteratorEndOpt.has_value()) {
//        return PluginAfterActionRequest::None;
//    }
//
//    auto iteratorEnd = iteratorEndOpt.value();
//
//    ADVANCE();
//
//    // ;
//    EXPECT(Semicolumn);
//
//    ADVANCE();
//
//    // i
//    EXPECT(Word);
//
//    if (iteratorName.GetText() != data.tokens[index].GetText()) {
//        return PluginAfterActionRequest::None;
//    }
//
//    ADVANCE();
//
//    // ++
//    EXPECT(Operator_Increment);
//
//    ADVANCE();
//
//    // )
//    EXPECT(ExpressionClose);
//
//    ADVANCE();
//
//    bool block = false;
//    auto bodyStartIndex = index;
//
//    if (type == TokenType::BlockOpen) {
//        block = true;
//        ADVANCE();
//    }
//
//    auto blockStart = data.tokens[index];
//    auto blockEnd   = blockStart;
//
//    std::vector<AppCUI::uint32> iteratorApparitions;
//
//    while (index < data.tokens.Len()) {
//        if (block) {
//            if (type == TokenType::BlockClose) {
//                // Not including '}'
//                blockEnd = data.tokens[index - 1];
//                break;
//            }
//        } else {
//            if (type == TokenType::Semicolumn) {
//                // Including ';'
//                blockEnd = data.tokens[index];
//                break;
//            }
//        }
//
//        if (type == TokenType::Word && data.tokens[index].GetText() == iteratorName.GetText()) {
//            auto apparitionOp = data.tokens[index].GetTokenStartOffset();
//
//            if (!apparitionOp.has_value()) {
//                return PluginAfterActionRequest::None;
//            }
//
//            iteratorApparitions.push_back(apparitionOp.value());
//        }
//
//        ++index;
//        type = data.tokens[index].GetTypeID(TokenType::None);
//    }
//
//    if (index == data.tokens.Len()) {
//        return PluginAfterActionRequest::None;
//    }
//
//    if (iteratorEnd < iteratorStart) {
//        return PluginAfterActionRequest::None;
//    }
//
//    auto blockStartOpt = blockStart.GetTokenStartOffset();
//    auto blockEndOpt   = blockEnd.GetTokenEndOffset();
//
//    if (!blockStartOpt.has_value() || !blockEndOpt.has_value()) {
//        return PluginAfterActionRequest::None;
//    }
//
//    auto iterationBlockSize = (blockEndOpt.value() - blockStartOpt.value());
//
//    // TODO: ask the user if they still want to unroll
//    // Heuristic: the resulting code should have less than 5000 characters
//    if ((iteratorEnd - iteratorStart) * iterationBlockSize > 10 * 500) {
//        return PluginAfterActionRequest::None;
//    }
//
//    auto unrollOffset = 0;
//
//    // Start unrolling
//    while (iteratorStart < iteratorEnd) {
//        // Convert iterator value from number to u16string
//        AppCUI::Utils::UnicodeStringBuilder builder;
//
//        auto n = iteratorStart;
//
//        do {
//            builder.AddChar('0' + (n % 10));
//            n /= 10;
//        } while (n != 0);
//
//        std::u16string itString;
//        builder.ToString(itString);
//
//        std::reverse(itString.begin(), itString.end());
//
//        auto written   = 0; // Index relative to for block start
//        auto apparitionBase    = blockStartOpt.value();
//
//        // Unroll
//        for (auto apparition : iteratorApparitions) {
//            std::u16string_view before(blockStart.GetText().data() + written, apparition - apparitionBase);
//
//            // Before iterator apparition
//            data.editor.Insert(blockStartOpt.value() + unrollOffset, before);
//            unrollOffset += apparition - apparitionBase;
//            written += apparition - apparitionBase;
//
//            // Iterator apparition
//            data.editor.Insert(blockStartOpt.value() + unrollOffset, itString);
//            unrollOffset += itString.size();
//            written += iteratorName.GetText().size(); // We replaced the iterator name with the value
//
//            apparitionBase = apparition + 1;
//        }
//
//        // Flush text after the final apparition
//        if (iterationBlockSize - written > 0) {
//            std::u16string_view end(blockStart.GetText().data() + written, iterationBlockSize - written);
//
//            data.editor.Insert(blockStartOpt.value() + unrollOffset, end);
//            unrollOffset += iterationBlockSize - written;
//        }
//
//        ++iteratorStart;
//    }
//
//    // Remove original for body, including ending '}'
//    data.editor.Delete(blockStartOpt.value() + unrollOffset, iterationBlockSize);
//
//    auto originalStartOpt = data.tokens[data.startIndex].GetTokenStartOffset();
//
//    if (!originalStartOpt.has_value()) {
//        return PluginAfterActionRequest::None;
//    }
//
//    // Remove original for
//    auto originalBodyOpt = data.tokens[bodyStartIndex].GetTokenStartOffset();
//
//    if (!originalBodyOpt.has_value()) {
//        return PluginAfterActionRequest::None;
//    }
//
//    data.editor.Delete(originalStartOpt.value(), originalBodyOpt.value() - originalStartOpt.value());
//
//    return PluginAfterActionRequest::Rescan;
//}
//} // namespace GView::Type::JS::Plugins