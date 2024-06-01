#include "ast.hpp"

namespace GView
{
namespace Type
{
    namespace JS
    {
        namespace AST
        {
            AppCUI::Utils::String ToString(std::u16string_view view)
            {
                AppCUI::Utils::String str;
                str.Set(view);

                return str;
            }

            void Instance::Create(TokensList& tokens)
            {
                tokenOffset = 0;

                auto start = 0;
                auto end   = tokens.Len();

                Parser parser(tokens, end);

                script = parser.ParseBlock();
            }

            Instance::~Instance()
            {
                delete script;
            }

            void Node::SetSource(Token start, Token end)
            {
                auto startOffset = start.GetTokenStartOffset();

                if (startOffset.has_value()) {
                    sourceStart = startOffset.value();
                }

                auto endOffset = end.GetTokenEndOffset();

                if (endOffset.has_value()) {
                    sourceSize = endOffset.value() - sourceStart;
                }
            }

            void Node::SetSourceEnd(Token end)
            {
                auto endOffset = end.GetTokenEndOffset();

                if (endOffset.has_value()) {
                    sourceSize = endOffset.value() - sourceStart;
                }
            }

            void Node::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;
            }

            std::string Node::GenSourceCode()
            {
                return "<NOTHING>";
            }

            VarDeclList::VarDeclList(uint32 type) : type(type)
            {
            }

            VarDeclList::~VarDeclList()
            {
                for (auto decl : decls) {
                    delete decl;
                }
            }

            void VarDeclList::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                for (auto decl : decls) {
                    decl->AdjustSourceStart(offset);
                }
            }

            Action VarDeclList::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitVarDeclList(this, (Decl*&) replacement);
            }

            void VarDeclList::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitVarDeclList(this);
            }

            VarDecl::VarDecl(u16string_view name, Expr* init) : name(name), init(init)
            {
            }

            VarDecl::~VarDecl()
            {
                delete init;
            }

            void VarDecl::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                init->AdjustSourceStart(offset);
            }

            Action VarDecl::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitVarDecl(this, (Decl*&) replacement);
            }

            void VarDecl::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitVarDecl(this);
            }

            Block::~Block()
            {
                for (auto d : decls) {
                    delete d;
                }
            }

            void Block::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                for (auto decl : decls) {
                    decl->AdjustSourceStart(offset);
                }
            }

            Action Block::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitBlock(this, (Block*&) replacement);
            }

            void Block::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitBlock(this);
            }

            IfStmt::~IfStmt()
            {
                delete cond;
                delete stmtTrue;
                delete stmtFalse;
            }

            IfStmt::IfStmt(Expr* cond, Stmt* stmtTrue, Stmt* stmtFalse) : cond(cond), stmtTrue(stmtTrue), stmtFalse(stmtFalse)
            {
            }

            void IfStmt::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                cond->AdjustSourceStart(offset);
                stmtTrue->AdjustSourceStart(offset);

                if (stmtFalse) {
                    stmtFalse->AdjustSourceStart(offset);
                }
            }

            Action IfStmt::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitIfStmt(this, (Stmt*&) replacement);
            }

            void IfStmt::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitIfStmt(this);
            }

            WhileStmt::WhileStmt(Expr* cond, Stmt* stmt) : cond(cond), stmt(stmt)
            {
            }

            WhileStmt ::~WhileStmt()
            {
                delete cond;
                delete stmt;
            }

            void WhileStmt::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                cond->AdjustSourceStart(offset);
                stmt->AdjustSourceStart(offset);
            }

            Action WhileStmt::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitWhileStmt(this, (Stmt*&) replacement);
            }

            void WhileStmt::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitWhileStmt(this);
            }

            ForStmt::~ForStmt()
            {
                delete decl;
                delete cond;
                delete inc;
                delete stmt;
            }

            ForStmt::ForStmt(VarDeclList* decl, Expr* cond, Expr* inc, Stmt* stmt) : decl(decl), cond(cond), inc(inc), stmt(stmt)
            {
            }

            void ForStmt::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                if (decl) {
                    decl->AdjustSourceStart(offset);
                }

                if (cond) {
                    cond->AdjustSourceStart(offset);
                }

                if (inc) {
                    inc->AdjustSourceStart(offset);
                }

                stmt->AdjustSourceStart(offset);
            }

            Action ForStmt::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitForStmt(this, (Stmt*&) replacement);
            }

            void ForStmt::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitForStmt(this);
            }

            ExprStmt::~ExprStmt()
            {
                delete expr;
            }

            ExprStmt::ExprStmt(Expr* expr) : expr(expr)
            {
            }

            void ExprStmt::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                if (expr) {
                    expr->AdjustSourceStart(offset);
                }
            }

            Action ExprStmt::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitExprStmt(this, (Stmt*&) replacement);
            }

            void ExprStmt::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitExprStmt(this);
            }

            Identifier::Identifier(u16string_view name) : name(name)
            {
            }

            ExprType Identifier::GetExprType()
            {
                return ExprType::Identifier;
            }

            void Identifier::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;
            }

            Action Identifier::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitIdentifier(this, (Expr*&) replacement);
            }

            void Identifier::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitIdentifier(this);
            }

            Unop::Unop(uint32 type, Expr* expr) : type(type), expr(expr)
            {
            }

            Unop::~Unop()
            {
                delete expr;
            }

            ExprType Unop::GetExprType()
            {
                return ExprType::Unop;
            }

            void Unop::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                expr->AdjustSourceStart(offset);
            }

            Action Unop::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitUnop(this, (Expr*&) replacement);
            }

            void Unop::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitUnop(this);
            }

            Binop::Binop(uint32 type, Expr* left, Expr* right) : type(type), left(left), right(right)
            {
            }

            Binop::~Binop()
            {
                delete left;
                delete right;
            }

            ExprType Binop::GetExprType()
            {
                return ExprType::Binop;
            }

            void Binop::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                left->AdjustSourceStart(offset);
                right->AdjustSourceStart(offset);
            }

            Action Binop::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitBinop(this, (Expr*&) replacement);
            }

            void Binop::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitBinop(this);
            }

            Ternary::Ternary(Expr* cond, Expr* exprTrue, Expr* exprFalse) : cond(cond), exprTrue(exprTrue), exprFalse(exprFalse)
            {
            }

            Ternary::~Ternary()
            {
                delete cond;
                delete exprTrue;
                delete exprFalse;
            }

            ExprType Ternary::GetExprType()
            {
                return ExprType::Ternary;
            }

            void Ternary::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                cond->AdjustSourceStart(offset);
                exprTrue->AdjustSourceStart(offset);
                exprFalse->AdjustSourceStart(offset);
            }

            Action Ternary::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitTernary(this, (Expr*&) replacement);
            }

            void Ternary::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitTernary(this);
            }

            Call::Call(Expr* callee, std::vector<Expr*> args) : callee(callee), args(args)
            {
            }

            Call::~Call()
            {
                delete callee;

                for (auto arg : args) {
                    delete arg;
                }
            }

            ExprType Call::GetExprType()
            {
                return ExprType::Call;
            }

            void Call::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                callee->AdjustSourceStart(offset);

                for (auto arg : args) {
                    arg->AdjustSourceStart(offset);
                }
            }

            Action Call::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitCall(this, (Expr*&) replacement);
            }

            void Call::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitCall(this);
            }

            Lambda::Lambda(std::vector<Identifier*> params, Stmt* body) : params(params), body(body)
            {
            }

            Lambda::~Lambda()
            {
                delete body;

                for (auto param : params) {
                    delete param;
                }
            }

            ExprType Lambda::GetExprType()
            {
                return ExprType::Lambda;
            }

            void Lambda::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                for (auto param : params) {
                    param->AdjustSourceStart(offset);
                }
            }

            Action Lambda::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitLambda(this, (Expr*&) replacement);
            }

            void Lambda::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitLambda(this);
            }

            Grouping::Grouping(Expr* expr) : expr(expr)
            {
            }

            Grouping::~Grouping()
            {
                delete expr;
            }

            ExprType Grouping::GetExprType()
            {
                return ExprType::Grouping;
            }

            void Grouping::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                expr->AdjustSourceStart(offset);
            }

            Action Grouping::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitGrouping(this, (Expr*&) replacement);
            }

            void Grouping::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitGrouping(this);
            }

            CommaList::~CommaList()
            {
                for (auto expr : list) {
                    delete expr;
                }
            }

            CommaList::CommaList(std::vector<Expr*> list) : list(list)
            {
            }

            ExprType CommaList::GetExprType()
            {
                return ExprType::CommaList;
            }

            void CommaList::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                for (auto expr : list) {
                    expr->AdjustSourceStart(offset);
                }
            }

            Action CommaList::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitCommaList(this, (Expr*&) replacement);
            }

            void CommaList::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitCommaList(this);
            }

            MemberAccess::~MemberAccess()
            {
                delete obj;
                delete member;
            }

            MemberAccess::MemberAccess(Expr* obj, Expr* member) : obj(obj), member(member)
            {
            }

            ExprType MemberAccess::GetExprType()
            {
                return ExprType::MemberAccess;
            }

            void MemberAccess::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;

                obj->AdjustSourceStart(offset);
                member->AdjustSourceStart(offset);
            }

            Action MemberAccess::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitMemberAccess(this, (Expr*&) replacement);
            }

            void MemberAccess::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitMemberAccess(this);
            }

            ExprType Constant::GetExprType()
            {
                return ExprType::Constant;
            }

            Number::Number(int32 value) : value(value)
            {
            }

            void Number::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;
            }

            Action Number::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitNumber(this, (Expr*&) replacement);
            }

            void Number::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitNumber(this);
            }

            std::string Number::GenSourceCode()
            {
                std::string str;
                auto n = value;

                do {
                    str += '0' + (n % 10);
                    n /= 10;
                } while (n != 0);

                std::reverse(str.begin(), str.end());

                return str;
            }

            ConstType Number::GetConstType()
            {
                return ConstType::Number;
            }

            AST::String::String(u16string_view value) : value(value)
            {
            }

            void AST::String::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset;
            }

            Action AST::String::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitString(this, (Expr*&) replacement);
            }

            ConstType String::GetConstType()
            {
                return ConstType::String;
            }

            void AST::String::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitString(this);
            }

            void ConstVisitor::VisitVarDeclList(const VarDeclList* node)
            {
            }
            void ConstVisitor::VisitVarDecl(const VarDecl* node)
            {
            }
            void ConstVisitor::VisitBlock(const Block* node)
            {
            }
            void ConstVisitor::VisitIfStmt(const IfStmt* nodet)
            {
            }
            void ConstVisitor::VisitWhileStmt(const WhileStmt* node)
            {
            }
            void ConstVisitor::VisitForStmt(const ForStmt* node)
            {
            }
            void ConstVisitor::VisitExprStmt(const ExprStmt* node)
            {
            }
            void ConstVisitor::VisitIdentifier(const Identifier* node)
            {
            }
            void ConstVisitor::VisitUnop(const Unop* node)
            {
            }
            void ConstVisitor::VisitBinop(const Binop* node)
            {
            }
            void ConstVisitor::VisitTernary(const Ternary* node)
            {
            }
            void ConstVisitor::VisitCall(const Call* node)
            {
            }
            void ConstVisitor::VisitLambda(const Lambda* node)
            {
            }
            void ConstVisitor::VisitGrouping(const Grouping* node)
            {
            }
            void ConstVisitor::VisitCommaList(const CommaList* node)
            {
            }
            void ConstVisitor::VisitMemberAccess(const MemberAccess* node)
            {
            }
            void ConstVisitor::VisitNumber(const Number* node)
            {
            }
            void ConstVisitor::VisitString(const AST::String* node)
            {
            }

            Action Visitor::VisitVarDeclList(VarDeclList* node, Decl*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitVarDecl(VarDecl* node, Decl*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitBlock(Block* node, Block*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitIfStmt(IfStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitWhileStmt(WhileStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitForStmt(ForStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitExprStmt(ExprStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitIdentifier(Identifier* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitUnop(Unop* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitBinop(Binop* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitTernary(Ternary* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitCall(Call* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitLambda(Lambda* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitGrouping(Grouping* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitCommaList(CommaList* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitMemberAccess(MemberAccess* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitNumber(Number* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Visitor::VisitString(AST::String* node, Expr*& replacement)
            {
                return Action::None;
            }

            Action Plugin::OnEnterVarDeclList(VarDeclList* node, Decl*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterVarDecl(VarDecl* node, Decl*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterBlock(Block* node, Block*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterIfStmt(IfStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterWhileStmt(WhileStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterForStmt(ForStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterExprStmt(ExprStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterIdentifier(Identifier* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterUnop(Unop* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterBinop(Binop* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterTernary(Ternary* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterCall(Call* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterLambda(Lambda* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterGrouping(Grouping* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterCommaList(CommaList* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterMemberAccess(MemberAccess* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterNumber(Number* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnEnterString(AST::String* node, Expr*& replacement)
            {
                return Action::None;
            }

            Action Plugin::OnExitVarDeclList(VarDeclList* nod, Decl*& replacemente)
            {
                return Action::None;
            }
            Action Plugin::OnExitVarDecl(VarDecl* node, Decl*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitBlock(Block* node, Block*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitIfStmt(IfStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitWhileStmt(WhileStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitForStmt(ForStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitExprStmt(ExprStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitIdentifier(Identifier* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitUnop(Unop* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitBinop(Binop* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitTernary(Ternary* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitCall(Call* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitLambda(Lambda* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitGrouping(Grouping* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitCommaList(CommaList* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitMemberAccess(MemberAccess* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitNumber(Number* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action Plugin::OnExitString(AST::String* node, Expr*& replacement)
            {
                return Action::None;
            }

            PluginVisitor::PluginVisitor(Plugin* plugin, TextEditor* editor) : plugin(plugin), tokenOffset(0), editor(editor)
            {
            }

            Action PluginVisitor::VisitVarDeclList(VarDeclList* node, Decl*& replacement)
            {
                return Action::None;
            }
            Action PluginVisitor::VisitVarDecl(VarDecl* node, Decl*& replacement)
            {
                return Action::None;
            }
            Action PluginVisitor::VisitBlock(Block* node, Block*& replacement)
            {
                auto action = plugin->OnEnterBlock(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                for (auto stmt : node->decls) {
                    Node* rep;
                    auto action = stmt->Accept(*this, rep);

                    switch (action) {
                    case Action::_UpdateChild: {
                        node->sourceSize += tokenOffset;
                        break;
                    }
                    default: {
                        break;
                    }
                    }
                }

                action = plugin->OnExitBlock(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                return Action::None;
            }
            Action PluginVisitor::VisitIfStmt(IfStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            Action PluginVisitor::VisitWhileStmt(WhileStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            Action PluginVisitor::VisitForStmt(ForStmt* node, Stmt*& replacement)
            {
                return Action::None;
            }
            void PluginVisitor::ReplaceNode(Node* parent, Node* child, Node* replacement)
            {
                auto oldSize = child->sourceSize;

                // Generate new code
                auto newSource = replacement->GenSourceCode();
                auto newSize   = newSource.size();

                int32 diffSize = newSize - oldSize;

                // Update new node source range
                replacement->sourceStart = child->sourceStart;
                replacement->sourceSize  = newSize;

                // Update parent source range
                parent->sourceSize += diffSize;

                // Replace in editor
                editor->Delete(child->sourceStart, child->sourceSize);
                editor->Insert(child->sourceStart, newSource);

                // Adjust offset for the nodes that follow
                tokenOffset += diffSize;

                // Replace node
                delete child;
            }

            void PluginVisitor::AdjustSize(Node* node)
            {
                node->sourceSize += tokenOffset;
            }

            Action PluginVisitor::VisitExprStmt(ExprStmt* node, Stmt*& replacement)
            {
                // Update node source start if any nodes before it were modified
                AdjustSize(node);
                node->expr->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterExprStmt(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                Node* rep;
                action = node->expr->Accept(*this, rep);

                switch (action) {
                case Action::Replace: {
                    ReplaceNode(node, node->expr, rep);
                    node->expr = (Expr*) rep;

                    return Action::_UpdateChild;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node);
                    break;
                }
                default: {
                    break;
                }
                }

                return plugin->OnExitExprStmt(node, replacement);
            }
            Action PluginVisitor::VisitIdentifier(Identifier* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action PluginVisitor::VisitUnop(Unop* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action PluginVisitor::VisitBinop(Binop* node, Expr*& replacement)
            {
                auto action = plugin->OnEnterBinop(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                Node* rep;
                action = node->left->Accept(*this, rep);

                switch (action) {
                case Action::Replace: {
                    ReplaceNode(node, node->left, rep);
                    node->left = (Expr*) rep;

                    node->left->AdjustSourceStart(tokenOffset);

                    break;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node);
                    node->left->AdjustSourceStart(tokenOffset);
                    break;
                }
                default: {
                    break;
                }
                }

                action = node->right->Accept(*this, rep);

                switch (action) {
                case Action::Replace: {
                    ReplaceNode(node, node->right, rep);
                    node->right = (Expr*) rep;
                    break;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node);
                    break;
                }
                default: {
                    break;
                }
                }

                bool shouldUpdate = replacement != nullptr;

                action = plugin->OnExitBinop(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (shouldUpdate) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitTernary(Ternary* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action PluginVisitor::VisitCall(Call* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action PluginVisitor::VisitLambda(Lambda* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action PluginVisitor::VisitGrouping(Grouping* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action PluginVisitor::VisitCommaList(CommaList* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action PluginVisitor::VisitMemberAccess(MemberAccess* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action PluginVisitor::VisitNumber(Number* node, Expr*& replacement)
            {
                return Action::None;
            }
            Action PluginVisitor::VisitString(AST::String* node, Expr*& replacement)
            {
                return Action::None;
            }

            DumpVisitor::DumpVisitor(const char* file)
            {
                this->file = std::ofstream(file);
            }

            DumpVisitor::~DumpVisitor()
            {
            }

#define DUMP(type)                                                                                                                                             \
    do {                                                                                                                                                       \
        file << "{\"type\": \"" type "\", \"source\": {\"start\": " << node->sourceStart << ", \"size\": " << node->sourceSize << "}";                         \
    } while (false)

#define DUMP_MEMBER(member)                                                                                                                                    \
    do {                                                                                                                                                       \
        if (node->member) {                                                                                                                                    \
            node->member->AcceptConst(*this);                                                                                                                  \
        } else {                                                                                                                                               \
            file << "null";                                                                                                                                    \
        }                                                                                                                                                      \
    } while (false)

#define DUMP_LIST(member)                                                                                                                                      \
    do {                                                                                                                                                       \
        bool first = true;                                                                                                                                     \
                                                                                                                                                               \
        for (auto decl : node->member) {                                                                                                                       \
            if (first) {                                                                                                                                       \
                first = false;                                                                                                                                 \
            } else {                                                                                                                                           \
                file << ", ";                                                                                                                                  \
            }                                                                                                                                                  \
            if (decl) {                                                                                                                                        \
                decl->AcceptConst(*this);                                                                                                                      \
            } else {                                                                                                                                           \
                file << "null";                                                                                                                                \
            }                                                                                                                                                  \
        }                                                                                                                                                      \
    } while (false)

            void DumpVisitor::VisitVarDeclList(const VarDeclList* node)
            {
                DUMP("VarDeclList");

                file << ", \"varType\": " << node->type << ", \"list\": [";

                DUMP_LIST(decls);

                file << "]}";
            }
            void DumpVisitor::VisitVarDecl(const VarDecl* node)
            {
                DUMP("VarDecl");

                file << ", \"name\": \"" << ToString(node->name).GetText() << "\", \"init\": ";

                DUMP_MEMBER(init);

                file << "}";
            }
            void DumpVisitor::VisitBlock(const Block* node)
            {
                DUMP("Block");

                file << ", \"decls\": [";

                DUMP_LIST(decls);

                file << "]}";
            }
            void DumpVisitor::VisitIfStmt(const IfStmt* node)
            {
                DUMP("IfStmt");

                file << ", \"cond\": ";

                DUMP_MEMBER(cond);

                file << ", \"stmtTrue\": ";

                DUMP_MEMBER(stmtTrue);

                file << ", \"stmtFalse\": ";

                DUMP_MEMBER(stmtFalse);

                file << "}";
            }
            void DumpVisitor::VisitWhileStmt(const WhileStmt* node)
            {
                DUMP("WhileStmt");

                file << ", \"cond\": ";

                DUMP_MEMBER(cond);

                file << ", \"stmt\": ";

                DUMP_MEMBER(stmt);

                file << "}";
            }
            void DumpVisitor::VisitForStmt(const ForStmt* node)
            {
                DUMP("ForStmt");

                file << ", \"decl\": ";

                DUMP_MEMBER(decl);

                file << ", \"cond\": ";

                DUMP_MEMBER(cond);

                file << ", \"inc\": ";

                DUMP_MEMBER(inc);

                file << ", \"stmt\": ";

                DUMP_MEMBER(stmt);

                file << "}";
            }
            void DumpVisitor::VisitExprStmt(const ExprStmt* node)
            {
                DUMP("ExprStmt");

                file << ", \"expr\": ";

                DUMP_MEMBER(expr);

                file << "}";
            }
            void DumpVisitor::VisitIdentifier(const Identifier* node)
            {
                DUMP("Identifier");

                file << ", \"name\": \"" << ToString(node->name).GetText();

                file << "\"}";
            }
            void DumpVisitor::VisitUnop(const Unop* node)
            {
                DUMP("Unop");

                file << ", \"op\": " << node->type << ", \"expr\": ";

                DUMP_MEMBER(expr);

                file << "}";
            }
            void DumpVisitor::VisitBinop(const Binop* node)
            {
                DUMP("Binop");

                file << ", \"op\": " << node->type << ", \"left\": ";

                DUMP_MEMBER(left);

                file << ", \"right\": ";

                DUMP_MEMBER(right);

                file << "}";
            }
            void DumpVisitor::VisitTernary(const Ternary* node)
            {
                DUMP("Ternary");

                file << ", \"cond\": ";

                DUMP_MEMBER(cond);

                file << ", \"exprTrue\": ";

                DUMP_MEMBER(exprTrue);

                file << ", \"exprFalse\": ";

                DUMP_MEMBER(exprFalse);

                file << "}";
            }
            void DumpVisitor::VisitCall(const Call* node)
            {
                DUMP("Call");

                file << ", \"callee\": ";

                DUMP_MEMBER(callee);

                file << ", \"args\": [";

                DUMP_LIST(args);

                file << "]}";
            }
            void DumpVisitor::VisitLambda(const Lambda* node)
            {
                DUMP("Lambda");

                file << ", \"params\": ";

                DUMP_LIST(params);

                file << ", \"body\": ";

                DUMP_MEMBER(body);

                file << "}";
            }
            void DumpVisitor::VisitGrouping(const Grouping* node)
            {
                DUMP("Grouping");

                file << ", \"expr\": ";

                DUMP_MEMBER(expr);

                file << "}";
            }
            void DumpVisitor::VisitCommaList(const CommaList* node)
            {
                DUMP("CommaList");

                file << ", \"list\": ";

                DUMP_LIST(list);

                file << "}";
            }
            void DumpVisitor::VisitMemberAccess(const MemberAccess* node)
            {
                DUMP("MemberAccess");

                file << ", \"obj\": ";

                DUMP_MEMBER(obj);

                file << ", \"member\": ";

                DUMP_MEMBER(member);

                file << "}";
            }
            void DumpVisitor::VisitNumber(const Number* node)
            {
                DUMP("Number");

                file << ", \"value\": " << node->value;

                file << "}";
            }
            void DumpVisitor::VisitString(const AST::String* node)
            {
                DUMP("String");

                file << ", \"value\": \"" << ToString(node->value).GetText();

                file << "\"}";
            }

            Parser::Parser(TokensList& tokens, int32 end) : tokens(tokens), start(0), end(end), current(0)
            {
            }

#define SKIP_COMMENTS()                                                                                                                                        \
    while (GetCurrentType() == TokenType::Comment) {                                                                                                           \
        ++current;                                                                                                                                             \
    }

#define ADVANCE_NOCHECK()                                                                                                                                      \
    do {                                                                                                                                                       \
        ++current;                                                                                                                                             \
    } while (GetCurrentType() == TokenType::Comment)

#define ADVANCE()                                                                                                                                              \
    do {                                                                                                                                                       \
        ++current;                                                                                                                                             \
        if (current == end) {                                                                                                                                  \
            return nullptr;                                                                                                                                    \
        }                                                                                                                                                      \
    } while (GetCurrentType() == TokenType::Comment)

#define EXPECT(type)                                                                                                                                           \
    do {                                                                                                                                                       \
        if (GetCurrentType() != type)                                                                                                                          \
            return nullptr;                                                                                                                                    \
    } while (false)

            Block* Parser::ParseBlock()
            {
                SKIP_COMMENTS();

                auto sourceStart = GetCurrent();

                if (GetCurrentType() == TokenType::BlockOpen) {
                    ADVANCE();
                }

                auto block = new Block();

                auto last = current;

                while (current < end) {
                    if (GetCurrentType() == TokenType::BlockClose) {
                        ADVANCE_NOCHECK();
                        break;
                    }

                    block->decls.emplace_back(ParseDecl());

                    if (last == current) {
                        AppCUI::Dialogs::MessageBox::ShowError("Error", "AST could not be fully parsed.");
                        return block;
                    }

                    last = current;
                }

                block->SetSource(sourceStart, GetPrevious());
                return block;
            }

            Decl* Parser::ParseDecl()
            {
                auto type = GetCurrentType();

                if (type != TokenType::DataType_Var && type != TokenType::DataType_Let) {
                    return ParseStmt();
                }

                auto sourceStart = GetCurrent();

                auto decl = ParseVarDecl();

                if (GetCurrentType() == TokenType::Semicolumn) {
                    ADVANCE_NOCHECK();

                    // Include ';'
                    decl->SetSourceEnd(GetPrevious());
                }

                return decl;
            }

            VarDeclList* Parser::ParseVarDecl()
            {
                auto sourceStart = GetCurrent();
                auto type        = GetCurrentType();

                auto list = new VarDeclList(type);

                while (current < end) {
                    ADVANCE(); // var/let/comma

                    auto nodeStart = GetCurrent();

                    Expr* expr = nullptr;

                    auto name = GetCurrent().GetText();

                    ADVANCE();

                    type = GetCurrentType();

                    if (type == TokenType::Operator_Assignment) {
                        ADVANCE();

                        // Don't parse commas
                        expr = ParseAssignmentAndMisc();
                    }

                    auto decl = new VarDecl(name, expr);
                    decl->SetSource(nodeStart, GetPrevious());

                    list->decls.emplace_back(decl);

                    if (GetCurrentType() != TokenType::Comma) {
                        break;
                    }
                }

                list->SetSource(sourceStart, GetPrevious());

                return list;
            }

            Stmt* Parser::ParseStmt()
            {
                switch (GetCurrentType()) {
                case TokenType::Keyword_If:
                    return ParseIfStmt();
                case TokenType::Keyword_While:
                    return ParseWhileStmt();
                case TokenType::Keyword_For:
                    return ParseForStmt();
                case TokenType::BlockOpen: {
                    return ParseBlock();
                }
                default:
                    auto sourceStart = GetCurrent();
                    auto expr        = ParseExprStmt();

                    if (GetCurrentType() == TokenType::Semicolumn) {
                        ADVANCE_NOCHECK();

                        // Include ';'
                        expr->SetSourceEnd(GetPrevious());
                    }

                    return expr;
                }
            }

            IfStmt* Parser::ParseIfStmt()
            {
                auto sourceStart = GetCurrent();

                ADVANCE();
                EXPECT(TokenType::ExpressionOpen);
                ADVANCE();

                auto expr = ParseExpr();

                EXPECT(TokenType::ExpressionClose);
                ADVANCE();

                auto stmtTrue = ParseStmt();

                Stmt* stmtFalse = nullptr;

                if (GetCurrentType() == TokenType::Keyword_Else) {
                    ADVANCE();
                    stmtFalse = ParseStmt();
                }

                auto ifStmt = new IfStmt(expr, stmtTrue, stmtFalse);
                ifStmt->SetSource(sourceStart, GetPrevious());

                return ifStmt;
            }

            WhileStmt* Parser::ParseWhileStmt()
            {
                auto sourceStart = GetCurrent();

                ADVANCE();
                EXPECT(TokenType::ExpressionOpen);

                auto expr = ParseExpr();

                EXPECT(TokenType::ExpressionClose);
                ADVANCE();

                auto stmt = ParseStmt();

                auto whileStmt = new WhileStmt(expr, stmt);
                whileStmt->SetSource(sourceStart, GetPrevious());

                return whileStmt;
            }

            ForStmt* Parser::ParseForStmt()
            {
                auto sourceStart = GetCurrent();

                ADVANCE();
                EXPECT(TokenType::ExpressionOpen);
                ADVANCE();

                VarDeclList* decl = nullptr;
                Expr* cond        = nullptr;
                Expr* inc         = nullptr;

                if (GetCurrentType() != TokenType::Semicolumn) {
                    decl = ParseVarDecl();

                    EXPECT(TokenType::Semicolumn);
                    ADVANCE();
                }

                if (GetCurrentType() != TokenType::Semicolumn) {
                    cond = ParseExpr();

                    EXPECT(TokenType::Semicolumn);
                    ADVANCE();
                }

                if (GetCurrentType() != TokenType::ExpressionClose) {
                    inc = ParseExpr();
                }

                EXPECT(TokenType::ExpressionClose);
                ADVANCE();

                auto stmt = ParseStmt();

                auto forStmt = new ForStmt(decl, cond, inc, stmt);
                forStmt->SetSource(sourceStart, GetPrevious());

                return forStmt;
            }

            ExprStmt* Parser::ParseExprStmt()
            {
                auto sourceStart = GetCurrent();

                auto node = new ExprStmt(ParseExpr());
                node->SetSource(sourceStart, GetPrevious());

                return node;
            }

            Expr* Parser::ParseExpr()
            {
                return ParseComma();
            }

            Expr* Parser::ParseComma()
            {
                auto sourceStart = GetCurrent();
                auto node        = ParseAssignmentAndMisc();

                while (current < end) {
                    auto type = GetCurrentType();

                    if (type != TokenType::Comma) {
                        return node;
                    }

                    ADVANCE();

                    node = new Binop(type, node, ParseAssignmentAndMisc());
                    node->SetSource(sourceStart, GetPrevious());
                }

                return node;
            }

            Expr* Parser::ParseAssignmentAndMisc()
            {
                auto sourceStart = GetCurrent();
                auto node        = ParseLogicalOr();

                while (current < end) {
                    auto type = GetCurrentType();

                    switch (type) {
                    case TokenType::Operator_Assignment:
                    case TokenType::Operator_PlusAssignment:
                    case TokenType::Operator_MinusAssignment:
                    case TokenType::Operator_ExponentiationAssignment:
                    case TokenType::Operator_MupliplyAssignment:
                    case TokenType::Operator_DivisionAssignment:
                    case TokenType::Operator_ModuloAssignment:
                    case TokenType::Operator_LeftShiftAssignment:
                    case TokenType::Operator_RightShiftAssignment:
                    case TokenType::Operator_UnsignedRightShiftAssignment:
                    case TokenType::Operator_AndAssignment:
                    case TokenType::Operator_XorAssignment:
                    case TokenType::Operator_OrAssignment:
                    case TokenType::Operator_LogicANDAssignment:
                    case TokenType::Operator_LogicORAssignment:
                    case TokenType::Operator_LogicNullishAssignment: {
                        ADVANCE();
                        node = new Binop(type, node, ParseLogicalOr());
                        node->SetSource(sourceStart, GetPrevious());
                        break;
                    }
                    case TokenType::Operator_Condition: {
                        ADVANCE();
                        auto exprTrue = ParseExpr();

                        if (GetCurrentType() != TokenType::Operator_TWO_POINTS) {
                            return node;
                        }

                        auto exprFalse = ParseExpr();

                        node = new Ternary(node, exprTrue, exprFalse);
                        node->SetSource(sourceStart, GetPrevious());
                        break;
                    }
                    case TokenType::Operator_ArrowFunction: {
                        ADVANCE();

                        std::vector<Identifier*> params;

                        // TODO: function () {}
                        switch (node->GetExprType()) {
                        case ExprType::Identifier: {
                            params.emplace_back((Identifier*) node);
                            break;
                        }
                        case ExprType::Grouping: {
                            auto list = ((Grouping*) node)->expr;

                            switch (list->GetExprType()) {
                            case ExprType::Identifier: { // id =>
                                params.emplace_back((Identifier*) list);
                                break;
                            }
                            case ExprType::CommaList: { // (id1, id2) =>
                                for (auto expr : ((CommaList*) list)->list) {
                                    if (expr->GetExprType() != ExprType::Identifier) {
                                        return node; // err
                                    }

                                    params.emplace_back((Identifier*) expr);
                                }
                                break;
                            }
                            }
                        }
                        }

                        auto body = ParseStmt();
                        node      = new Lambda(params, body);
                        node->SetSource(sourceStart, GetPrevious());

                        break;
                    }
                    default:
                        return node;
                    }
                }

                return node;
            }

            Expr* Parser::ParseLogicalOr()
            {
                auto sourceStart = GetCurrent();
                auto node        = ParseLogicalAnd();

                while (current < end) {
                    auto type = GetCurrentType();

                    if (type != TokenType::Operator_LogicOR) {
                        return node;
                    }

                    ADVANCE();

                    node = new Binop(type, node, ParseLogicalAnd());
                    node->SetSource(sourceStart, GetPrevious());
                }

                return node;
            }

            Expr* Parser::ParseLogicalAnd()
            {
                auto sourceStart = GetCurrent();
                auto node        = ParseBitwiseOr();

                while (current < end) {
                    auto type = GetCurrentType();

                    if (type != TokenType::Operator_LogicAND) {
                        return node;
                    }

                    ADVANCE();

                    node = new Binop(type, node, ParseBitwiseOr());
                    node->SetSource(sourceStart, GetPrevious());
                }

                return node;
            }

            Expr* Parser::ParseBitwiseOr()
            {
                auto sourceStart = GetCurrent();
                auto node        = ParseBitwiseXor();

                while (current < end) {
                    auto type = GetCurrentType();

                    if (type != TokenType::Operator_OR) {
                        return node;
                    }

                    ADVANCE();

                    node = new Binop(type, node, ParseBitwiseXor());
                    node->SetSource(sourceStart, GetPrevious());
                }

                return node;
            }

            Expr* Parser::ParseBitwiseXor()
            {
                auto sourceStart = GetCurrent();
                auto node        = ParseBitwiseAnd();

                while (current < end) {
                    auto type = GetCurrentType();

                    if (type != TokenType::Operator_XOR) {
                        return node;
                    }

                    ADVANCE();

                    node = new Binop(type, node, ParseBitwiseAnd());
                    node->SetSource(sourceStart, GetPrevious());
                }

                return node;
            }

            Expr* Parser::ParseBitwiseAnd()
            {
                auto sourceStart = GetCurrent();
                auto node        = ParseEquality();

                while (current < end) {
                    auto type = GetCurrentType();

                    if (type != TokenType::Operator_AND) {
                        return node;
                    }

                    ADVANCE();

                    node = new Binop(type, node, ParseEquality());
                    node->SetSource(sourceStart, GetPrevious());
                }

                return node;
            }

            Expr* Parser::ParseEquality()
            {
                auto sourceStart = GetCurrent();
                auto node        = ParseRelational();

                while (current < end) {
                    auto type = GetCurrentType();

                    switch (type) {
                    case TokenType::Operator_Equal:
                    case TokenType::Operator_StrictEqual:
                    case TokenType::Operator_Different:
                    case TokenType::Operator_StrictDifferent: {
                        ADVANCE();

                        node = new Binop(type, node, ParseRelational());
                        node->SetSource(sourceStart, GetPrevious());
                        break;
                    }
                    default: {
                        return node;
                    }
                    }
                }

                return node;
            }

            Expr* Parser::ParseRelational()
            {
                auto sourceStart = GetCurrent();
                auto node        = ParseBitwiseShift();

                while (current < end) {
                    auto type = GetCurrentType();

                    switch (type) {
                    case TokenType::Operator_Smaller:
                    case TokenType::Operator_SmallerOrEQ:
                    case TokenType::Operator_Bigger:
                    case TokenType::Operator_BiggerOrEq: {
                        ADVANCE();

                        node = new Binop(type, node, ParseBitwiseShift());
                        node->SetSource(sourceStart, GetPrevious());
                        break;
                    }
                    default: {
                        return node;
                    }
                    }
                }

                return node;
            }

            Expr* Parser::ParseBitwiseShift()
            {
                auto sourceStart = GetCurrent();
                auto node        = ParseAdditive();

                while (current < end) {
                    auto type = GetCurrentType();

                    switch (type) {
                    case TokenType::Operator_LeftShift:
                    case TokenType::Operator_RightShift:
                    case TokenType::Operator_SignRightShift: {
                        ADVANCE();

                        node = new Binop(type, node, ParseAdditive());
                        node->SetSource(sourceStart, GetPrevious());
                        break;
                    }
                    default: {
                        return node;
                    }
                    }
                }

                return node;
            }

            Expr* Parser::ParseAdditive()
            {
                auto sourceStart = GetCurrent();
                auto node        = ParseMultiplicative();

                while (current < end) {
                    auto type = GetCurrentType();

                    switch (type) {
                    case TokenType::Operator_Plus:
                    case TokenType::Operator_Minus: {
                        ADVANCE();

                        node = new Binop(type, node, ParseMultiplicative());
                        node->SetSource(sourceStart, GetPrevious());
                        break;
                    }
                    default: {
                        return node;
                    }
                    }
                }

                return node;
            }

            Expr* Parser::ParseMultiplicative()
            {
                auto sourceStart = GetCurrent();
                auto node        = ParseExponentiation();

                while (current < end) {
                    auto type = GetCurrentType();

                    switch (type) {
                    case TokenType::Operator_Multiply:
                    case TokenType::Operator_Division:
                    case TokenType::Operator_Modulo: {
                        ADVANCE();

                        node = new Binop(type, node, ParseExponentiation());
                        node->SetSource(sourceStart, GetPrevious());
                        break;
                    }
                    default: {
                        return node;
                    }
                    }
                }

                return node;
            }

            Expr* Parser::ParseExponentiation()
            {
                auto sourceStart = GetCurrent();
                auto node        = ParsePrefix();

                while (current < end) {
                    auto type = GetCurrentType();

                    if (type != TokenType::Operator_Exponential) {
                        return node;
                    }

                    ADVANCE();
                    node = new Binop(type, node, ParsePrefix());
                    node->SetSource(sourceStart, GetPrevious());
                }

                return node;
            }

            Expr* Parser::ParsePrefix()
            {
                auto sourceStart = GetCurrent();
                auto type        = GetCurrentType();

                switch (type) {
                case TokenType::Operator_Increment:
                case TokenType::Operator_Decrement:
                case TokenType::Operator_LogicalNOT:
                case TokenType::Operator_NOT:
                case TokenType::Operator_Plus:
                case TokenType::Operator_Minus:
                case TokenType::Keyword_Typeof: {
                    ADVANCE();
                    auto node = new Unop(type, ParsePostfix());
                    node->SetSource(sourceStart, GetPrevious());

                    return node;
                }
                default:
                    return ParsePostfix();
                }
            }

            Expr* Parser::ParsePostfix()
            {
                auto sourceStart = GetCurrent();

                auto node = ParseCall();
                auto type = GetCurrentType();

                switch (type) {
                case TokenType::Operator_Increment:
                case TokenType::Operator_Decrement: {
                    ADVANCE();
                    auto unop = new Unop(type, node);
                    unop->SetSource(sourceStart, GetPrevious());

                    return unop;
                }
                default:
                    return node;
                }
            }

            // TODO: new
            Expr* Parser::ParseCall()
            {
                auto sourceStart = GetCurrent();
                auto node        = ParseGrouping();

                while (current < end) {
                    auto type = GetCurrentType();

                    switch (type) {
                    case TokenType::Operator_MemberAccess: {
                        ADVANCE();

                        node = new MemberAccess(node, ParseIdentifier());
                        node->SetSource(sourceStart, GetPrevious());
                        break;
                    }
                    case TokenType::ArrayOpen: {
                        ADVANCE();

                        node = new MemberAccess(node, ParseExpr());

                        EXPECT(TokenType::ArrayClose);
                        ADVANCE();

                        node->SetSource(sourceStart, GetPrevious());

                        break;
                    }
                    case TokenType::ExpressionOpen: {
                        ADVANCE();

                        std::vector<Expr*> args;

                        while (current < end && GetCurrentType() != TokenType::ExpressionClose) {
                            type = GetCurrentType();

                            args.emplace_back(ParseAssignmentAndMisc());

                            if (GetCurrentType() == TokenType::Comma) {
                                ADVANCE();
                            }
                        }

                        ADVANCE(); // )

                        node = new Call(node, args);
                        node->SetSource(sourceStart, GetPrevious());
                        break;
                    }
                    default: {
                        return node;
                    }
                    }
                }

                return node;
            }

            Expr* Parser::ParseGrouping()
            {
                auto sourceStart = GetCurrent();
                auto type        = GetCurrentType();

                if (type == TokenType::ExpressionOpen) {
                    ADVANCE();

                    auto expr = ParseExpr();

                    EXPECT(TokenType::ExpressionClose);
                    ADVANCE();

                    auto node = new Grouping(expr);
                    node->SetSource(sourceStart, GetPrevious());

                    return node;
                }

                return ParsePrimary();
            }

            Expr* Parser::ParsePrimary()
            {
                auto sourceStart = GetCurrent();
                auto type        = GetCurrentType();

                switch (type) {
                default: {
                    if (type < TokenType::Keyword_Clearinterval || type > TokenType::DataType_Long) {
                        return nullptr;
                    }

                    // If it's a keyword like 'console', treat it like an identifier
                    [[fallthrough]];
                }
                case TokenType::Word: {
                    auto id = GetCurrent().GetText();

                    ADVANCE();

                    auto node = new Identifier(id);
                    node->SetSource(sourceStart, GetPrevious());

                    return node;
                }
                case TokenType::Number: {
                    AppCUI::Utils::String valStr;
                    valStr.Set(GetCurrent().GetText());

                    auto valNumOpt = AppCUI::Utils::Number::ToInt32(valStr);

                    if (!valNumOpt.has_value()) {
                        return nullptr;
                    }

                    ADVANCE();

                    auto node = new Number(valNumOpt.value());
                    node->SetSource(sourceStart, GetPrevious());

                    return node;
                }
                case TokenType::String: {
                    auto str = GetCurrent().GetText();

                    ADVANCE();

                    auto node = new String(u16string_view(str.data() + 1, str.size() - 2));
                    node->SetSource(sourceStart, GetPrevious());

                    return node;
                }
                }
            }

            Expr* Parser::ParseIdentifier()
            {
                auto sourceStart = GetCurrent();
                if (GetCurrentType() != TokenType::Word) {
                    return nullptr;
                }

                auto id = GetCurrent().GetText();

                ADVANCE();

                auto node = new Identifier(id);
                node->SetSource(sourceStart, GetPrevious());

                return node;
            }

            Token Parser::GetCurrent()
            {
                return tokens[current];
            }

            Token Parser::GetPrevious()
            {
                return tokens[current - 1];
            }

            uint32 Parser::GetCurrentType()
            {
                return tokens[current].GetTypeID(TokenType::None);
            }
        } // namespace AST
    }     // namespace JS
} // namespace Type
} // namespace GView