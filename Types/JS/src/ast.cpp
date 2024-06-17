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
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;
            }

            void Node::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;
            }

            std::u16string Node::GenSourceCode()
            {
                std::u16string str;
                str += '?';

                return str;
            }

            FunDecl::FunDecl(std::u16string_view name) : name(name), block(nullptr), nameSize(name.size()), nameOffset(0)
            {
            }

            FunDecl::~FunDecl()
            {
                for (auto param : params) {
                    delete param;
                }

                delete block;
            }

            void FunDecl::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                for (auto param : params) {
                    param->AdjustSourceStart(offset);
                }

                block->AdjustSourceStart(offset);
            }

            void FunDecl::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                for (auto param : params) {
                    param->AdjustSourceOffset(offset);
                }

                block->AdjustSourceOffset(offset);
            }

            Action FunDecl::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitFunDecl(this, (Decl*&) replacement);
            }

            void FunDecl::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitFunDecl(this);
            }

            DeclType FunDecl::GetDeclType()
            {
                return DeclType::Function;
            }

            void FunDecl::SetName(std::u16string& str)
            {
                name     = str;
                nameSize = str.size();
            }

            FunDecl* FunDecl::Clone()
            {
                auto clone = new FunDecl(name);

                for (auto& param : params) {
                    clone->params.emplace_back(param->Clone());
                }

                clone->block = block->Clone();

                return clone;
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
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                for (auto decl : decls) {
                    decl->AdjustSourceStart(offset);
                }
            }

            void VarDeclList::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                for (auto decl : decls) {
                    decl->AdjustSourceOffset(offset);
                }
            }

            std::u16string VarDeclList::GenSourceCode()
            {
                std::u16string result;

                switch (type) {
                case TokenType::DataType_Let: {
                    result += u"let ";
                    break;
                }
                case TokenType::DataType_Var: {
                    result += u"var ";
                    break;
                }
                case TokenType::Keyword_Const: {
                    result += u"const ";
                    break;
                }
                }

                bool first = true;

                for (auto decl : decls) {
                    if (first) {
                        first = false;
                    }
                    else {
                        result += u", ";
                    }

                    result += decl->GenSourceCode();
                }

                result += u';';

                return result;
            }

            Action VarDeclList::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitVarDeclList(this, (Decl*&) replacement);
            }

            void VarDeclList::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitVarDeclList(this);
            }

            VarDeclList* VarDeclList::Clone()
            {
                auto clone = new VarDeclList(type);

                for (auto& decl : decls) {
                    clone->decls.emplace_back(decl->Clone());
                }

                return clone;
            }

            DeclType VarDeclList::GetDeclType()
            {
                return DeclType::Var;
            }

            VarDecl::VarDecl(u16string_view name, Expr* init) : name(name), init(init), nameSize(name.size())
            {
            }

            VarDecl::~VarDecl()
            {
                delete init;
            }

            void VarDecl::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                if (init) {
                    init->AdjustSourceStart(offset);
                }
            }

            void VarDecl::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                if (init) {
                    init->AdjustSourceOffset(offset);
                }
            }

            std::u16string VarDecl::GenSourceCode()
            {
                std::u16string result;

                result += name;

                if (init != nullptr) {
                    result += u" = ";
                    result += init->GenSourceCode();
                }

                return result;
            }

            Action VarDecl::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitVarDecl(this, (Decl*&) replacement);
            }

            void VarDecl::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitVarDecl(this);
            }

            DeclType VarDecl::GetDeclType()
            {
                return DeclType::Var;
            }

            void VarDecl::SetName(std::u16string& str)
            {
                name     = str;
                nameSize = str.size();
            }

            VarDecl* VarDecl::Clone()
            {
                auto expr  = (init ? init->Clone() : nullptr);

                auto clone = new VarDecl(name, expr);

                return clone;
            }

            AST::DeclType Stmt::GetDeclType()
            {
                return AST::DeclType::Stmt;
            }

            Block::~Block()
            {
                for (auto d : decls) {
                    delete d;
                }
            }

            void Block::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                for (auto decl : decls) {
                    decl->AdjustSourceStart(offset);
                }
            }

            void Block::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                for (auto decl : decls) {
                    decl->AdjustSourceOffset(offset);
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

            std::u16string Block::GenSourceCode() {
                std::u16string result;
                result += u"{";

                for (auto decl : decls) {
                    result += decl->GenSourceCode();
                }

                result += u"}";

                return result;
            }

            StmtType Block::GetStmtType()
            {
                return StmtType::Block;
            }

            Block* Block::Clone()
            {
                auto clone = new Block();

                for (auto& decl : decls) {
                    clone->decls.emplace_back(decl->Clone());
                }

                return clone;
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
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                cond->AdjustSourceStart(offset);
                stmtTrue->AdjustSourceStart(offset);

                if (stmtFalse) {
                    stmtFalse->AdjustSourceStart(offset);
                }
            }

            void IfStmt::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                cond->AdjustSourceOffset(offset);
                stmtTrue->AdjustSourceOffset(offset);

                if (stmtFalse) {
                    stmtFalse->AdjustSourceOffset(offset);
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

            StmtType IfStmt::GetStmtType()
            {
                return StmtType::If;
            }

            IfStmt* IfStmt::Clone()
            {
                auto condClone = cond->Clone();
                auto stmtTrueClone  = stmtTrue->Clone();
                auto stmtFalseClone = stmtFalse ? stmtFalse->Clone() : nullptr;

                auto clone = new IfStmt(condClone, stmtTrueClone, stmtFalseClone);

                return clone;
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
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                cond->AdjustSourceStart(offset);
                stmt->AdjustSourceStart(offset);
            }

            void WhileStmt::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                cond->AdjustSourceOffset(offset);
                stmt->AdjustSourceOffset(offset);
            }

            Action WhileStmt::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitWhileStmt(this, (Stmt*&) replacement);
            }

            void WhileStmt::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitWhileStmt(this);
            }

            StmtType WhileStmt::GetStmtType()
            {
                return StmtType::While;
            }

            WhileStmt* WhileStmt::Clone()
            {
                auto clone = new WhileStmt(cond->Clone(), stmt->Clone());

                return clone;
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
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

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

            void ForStmt::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                if (decl) {
                    decl->AdjustSourceOffset(offset);
                }

                if (cond) {
                    cond->AdjustSourceOffset(offset);
                }

                if (inc) {
                    inc->AdjustSourceOffset(offset);
                }

                stmt->AdjustSourceOffset(offset);
            }

            Action ForStmt::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitForStmt(this, (Stmt*&) replacement);
            }

            void ForStmt::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitForStmt(this);
            }

            StmtType ForStmt::GetStmtType()
            {
                return StmtType::For;
            }

            ForStmt* ForStmt::Clone()
            {
                auto declClone = decl ? decl->Clone() : nullptr;
                auto condClone = cond ? cond->Clone() : nullptr;
                auto incClone = inc ? inc->Clone() : nullptr;
                auto stmtClone = stmt->Clone();

                auto clone = new ForStmt(declClone, condClone, incClone, stmtClone);

                return clone;
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
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                if (expr) {
                    expr->AdjustSourceStart(offset);
                }
            }

            void ExprStmt::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                if (expr) {
                    expr->AdjustSourceOffset(offset);
                }
            }

            std::u16string ExprStmt::GenSourceCode()
            {
                std::u16string result;

                if (expr != nullptr) {
                    result += expr->GenSourceCode();
                }

                result += u';';

                return result;
            }

            Action ExprStmt::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitExprStmt(this, (Stmt*&) replacement);
            }

            void ExprStmt::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitExprStmt(this);
            }

            StmtType ExprStmt::GetStmtType()
            {
                return StmtType::Expr;
            }

            ExprStmt* ExprStmt::Clone()
            {
                auto exprClone = expr ? expr->Clone() : nullptr;

                auto clone = new ExprStmt(exprClone);

                return clone;
            }

            ReturnStmt::~ReturnStmt()
            {
                if (expr) {
                    delete expr;
                }
            }

            ReturnStmt::ReturnStmt(Expr* expr) : expr(expr)
            {
            }

            void ReturnStmt::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                if (expr) {
                    expr->AdjustSourceStart(offset);
                }
            }

            void ReturnStmt::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                if (expr) {
                    expr->AdjustSourceOffset(offset);
                }
            }

            Action ReturnStmt::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitReturnStmt(this, (Stmt*&) replacement);
            }

            void ReturnStmt::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitReturnStmt(this);
            }

            StmtType ReturnStmt::GetStmtType()
            {
                return StmtType::Return;
            }

            ReturnStmt* ReturnStmt::Clone()
            {
                auto exprClone = expr ? expr->Clone() : nullptr;

                auto clone = new ReturnStmt(exprClone);

                return clone;
            }

            Identifier::Identifier(u16string_view name) : name(name), nameSize(name.size())
            {
            }

            ExprType Identifier::GetExprType()
            {
                return ExprType::Identifier;
            }

            void Identifier::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;
            }

            void Identifier::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;
            }

            std::u16string Identifier::GenSourceCode()
            {
                return name;
            }

            Action Identifier::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitIdentifier(this, (Expr*&) replacement);
            }

            void Identifier::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitIdentifier(this);
            }

            void Identifier::SetName(std::u16string& str)
            {
                name     = str;
                nameSize = str.size();
            }

            Identifier* Identifier::Clone()
            {
                auto clone = new Identifier(name);

                return clone;
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
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                expr->AdjustSourceStart(offset);
            }

            void Unop::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                expr->AdjustSourceOffset(offset);
            }

            Action Unop::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitUnop(this, (Expr*&) replacement);
            }

            void Unop::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitUnop(this);
            }

            Unop* Unop::Clone()
            {
                auto clone = new Unop(type, expr->Clone());

                return clone;
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
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                left->AdjustSourceStart(offset);
                right->AdjustSourceStart(offset);
            }

            void Binop::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                left->AdjustSourceOffset(offset);
                right->AdjustSourceOffset(offset);
            }

            std::u16string Binop::GenSourceCode() {
                std::u16string str;

                str += left->GenSourceCode();

                switch (type) {
                case TokenType::Operator_LogicOR: {
                    str += u" || ";
                    break;
                }
                case TokenType::Operator_LogicAND: {
                    str += u" && ";
                    break;
                }
                case TokenType::Operator_OR: {
                    str += u" | ";
                    break;
                }
                case TokenType::Operator_XOR: {
                    str += u" ^ ";
                    break;
                }
                case TokenType::Operator_AND: {
                    str += u" & ";
                    break;
                }
                case TokenType::Operator_Equal: {
                    str += u" == ";
                    break;
                }
                case TokenType::Operator_StrictEqual: {
                    str += u" === ";
                    break;
                }
                case TokenType::Operator_Different: {
                    str += u" != ";
                    break;
                }
                case TokenType::Operator_StrictDifferent: {
                    str += u" !== ";
                    break;
                }
                case TokenType::Operator_Smaller: {
                    str += u" < ";
                    break;
                }
                case TokenType::Operator_SmallerOrEQ: {
                    str += u" <= ";
                    break;
                }
                case TokenType::Operator_Bigger: {
                    str += u" > ";
                    break;
                }
                case TokenType::Operator_BiggerOrEq: {
                    str += u" >= ";
                    break;
                }
                case TokenType::Operator_LeftShift: {
                    str += u" << ";
                    break;
                }
                case TokenType::Operator_RightShift: {
                    str += u" >> ";
                    break;
                }
                case TokenType::Operator_SignRightShift: {
                    str += u" >>> ";
                    break;
                }
                case TokenType::Operator_Plus: {
                    str += u" + ";
                    break;
                }
                case TokenType::Operator_Minus: {
                    str += u" - ";
                    break;
                }
                case TokenType::Operator_Multiply: {
                    str += u" * ";
                    break;
                }
                case TokenType::Operator_Division: {
                    str += u" / ";
                    break;
                }
                case TokenType::Operator_Modulo: {
                    str += u" % ";
                    break;
                }
                case TokenType::Operator_Exponential: {
                    str += u" ** ";
                    break;
                }
                default: {
                    str += ' ? ';
                    break;
                }
                }

                str += right->GenSourceCode();

                return str;
            }

            Action Binop::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitBinop(this, (Expr*&) replacement);
            }

            void Binop::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitBinop(this);
            }

            Binop* Binop::Clone()
            {
                auto clone = new Binop(type, left->Clone(), right->Clone());

                return clone;
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
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                cond->AdjustSourceStart(offset);
                exprTrue->AdjustSourceStart(offset);
                exprFalse->AdjustSourceStart(offset);
            }

            void Ternary::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                cond->AdjustSourceOffset(offset);
                exprTrue->AdjustSourceOffset(offset);
                exprFalse->AdjustSourceOffset(offset);
            }

            Action Ternary::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitTernary(this, (Expr*&) replacement);
            }

            void Ternary::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitTernary(this);
            }

            Ternary* Ternary::Clone()
            {
                auto clone = new Ternary(cond->Clone(), exprTrue->Clone(), exprFalse->Clone());

                return clone;
            }

            Call::Call(Expr* callee, std::vector<Expr*> args) : callee(callee), args(args)
            {
            }

            Call::~Call()
            {
                delete callee;

                for (auto arg : args) {
                    if (arg != nullptr) {
                        delete arg;
                    }
                }
            }

            ExprType Call::GetExprType()
            {
                return ExprType::Call;
            }

            void Call::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                callee->AdjustSourceStart(offset);

                for (auto arg : args) {
                    arg->AdjustSourceStart(offset);
                }
            }

            void Call::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                callee->AdjustSourceOffset(offset);

                for (auto arg : args) {
                    arg->AdjustSourceOffset(offset);
                }
            }

            std::u16string Call::GenSourceCode()
            {
                std::u16string result;

                result += callee->GenSourceCode();
                result += u'(';

                bool first = true;

                for (auto arg : args) {
                    if (first) {
                        first = false;
                    } else {
                        result += u", ";
                    }

                    result += arg->GenSourceCode();
                }

                result += u')';

                return result;
            }

            Action Call::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitCall(this, (Expr*&) replacement);
            }

            void Call::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitCall(this);
            }

            Call* Call::Clone()
            {
                std::vector<Expr*> argsClone;

                for (auto& arg : args) {
                    argsClone.emplace_back(arg->Clone());
                }

                auto clone = new Call(callee->Clone(), argsClone);

                return clone;
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
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                for (auto param : params) {
                    param->AdjustSourceStart(offset);
                }
            }

            void Lambda::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                for (auto param : params) {
                    param->AdjustSourceOffset(offset);
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

            Lambda* Lambda::Clone()
            {
                std::vector<Identifier*> paramsClone;

                for (auto& param : params) {
                    paramsClone.emplace_back(param->Clone());
                }

                auto clone = new Lambda(params, body->Clone());

                return clone;
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
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                expr->AdjustSourceStart(offset);
            }

            void Grouping::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                expr->AdjustSourceOffset(offset);
            }

            Action Grouping::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitGrouping(this, (Expr*&) replacement);
            }

            void Grouping::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitGrouping(this);
            }

            Grouping* Grouping::Clone()
            {
                auto exprClone = expr ? expr->Clone() : nullptr;

                auto clone = new Grouping(exprClone);

                return clone;
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
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                for (auto expr : list) {
                    expr->AdjustSourceStart(offset);
                }
            }

            void CommaList::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                for (auto expr : list) {
                    expr->AdjustSourceOffset(offset);
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

            CommaList* CommaList::Clone()
            {
                std::vector<Expr*> listClone;

                for (auto& expr : list) {
                    listClone.emplace_back(expr->Clone());
                }

                auto clone = new CommaList(listClone);

                return clone;
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
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;

                obj->AdjustSourceStart(offset);
                member->AdjustSourceStart(offset);
            }

            void MemberAccess::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;

                obj->AdjustSourceOffset(offset);
                member->AdjustSourceOffset(offset);
            }

            std::u16string MemberAccess::GenSourceCode()
            {
                std::u16string result;
                
                result += obj->GenSourceCode();

                if (member->GetExprType() == ExprType::Identifier) {
                    result += u'.';
                    result += member->GenSourceCode();
                } else {
                    result += u'[';
                    result += member->GenSourceCode();
                    result += u']';
                }

                return result;
            }

            Action MemberAccess::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitMemberAccess(this, (Expr*&) replacement);
            }

            void MemberAccess::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitMemberAccess(this);
            }

            MemberAccess* MemberAccess::Clone()
            {
                auto clone = new MemberAccess(obj->Clone(), member->Clone());

                return clone;
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
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;
            }

            void Number::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;
            }

            Action Number::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitNumber(this, (Expr*&) replacement);
            }

            void Number::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitNumber(this);
            }

            std::u16string Number::GenSourceCode()
            {
                std::u16string str;
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

            Number* Number::Clone()
            {
                auto clone = new Number(value);

                return clone;
            }

            AST::String::String(u16string_view value) : value(value)
            {
            }

            void AST::String::AdjustSourceStart(int32 offset)
            {
                sourceStart += offset - sourceOffset;
                sourceOffset = offset;
            }

            void AST::String::AdjustSourceOffset(int32 offset)
            {
                sourceOffset = offset;
            }

            Action AST::String::Accept(Visitor& visitor, Node*& replacement)
            {
                return visitor.VisitString(this, (Expr*&) replacement);
            }

            std::u16string String::GenSourceCode()
            {
                std::u16string str;
                str += '\"';
                str += value;
                str += '\"';

                return str;
            }

            ConstType String::GetConstType()
            {
                return ConstType::String;
            }

            void AST::String::AcceptConst(ConstVisitor& visitor)
            {
                visitor.VisitString(this);
            }

            AST::String* AST::String::Clone()
            {
                auto clone = new AST::String(value);

                return clone;
            }

            void ConstVisitor::VisitFunDecl(const FunDecl* node)
            {
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
            void ConstVisitor::VisitReturnStmt(const ReturnStmt* node)
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

            Action Visitor::VisitFunDecl(FunDecl* node, Decl*& replacement)
            {
                return Action::None;
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
            Action Visitor::VisitReturnStmt(ReturnStmt* node, Stmt*& replacement)
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

            Action Plugin::OnEnterFunDecl(FunDecl* node, Decl*& replacement)
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
            Action Plugin::OnEnterReturnStmt(ReturnStmt* node, Stmt*& replacement)
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

            Action Plugin::OnExitFunDecl(FunDecl* node, Decl*& replacement)
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
            Action Plugin::OnExitReturnStmt(ReturnStmt* node, Stmt*& replacement)
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

            void PluginVisitor::UpdateNode(Node* parent, FunDecl* child)
            {
                auto oldSize = child->nameSize;
                auto newSize = child->name.size();

                int32 diffSize = newSize - oldSize;

                // Update parent source range
                parent->sourceSize += diffSize;

                // Replace in editor
                editor->Delete(child->nameOffset, child->nameSize);
                editor->Insert(child->nameOffset, child->name);

                child->nameSize = newSize;
                child->sourceSize += diffSize;

                // Adjust offset for the nodes that follow
                tokenOffset += diffSize;

                // The new node should not be re-adjusted in the future
                child->AdjustSourceOffset(tokenOffset);
            }

            void PluginVisitor::UpdateNode(Node* parent, VarDecl* child)
            {
                auto oldSize = child->nameSize;
                auto newSize = child->name.size();

                int32 diffSize = newSize - oldSize;

                // Update parent source range
                parent->sourceSize += diffSize;

                // Replace in editor
                editor->Delete(child->sourceStart, child->nameSize);
                editor->Insert(child->sourceStart, child->name);

                child->nameSize = newSize;
                child->sourceSize += diffSize;

                // Adjust offset for the nodes that follow
                tokenOffset += diffSize;

                // The new node should not be re-adjusted in the future
                child->AdjustSourceOffset(tokenOffset);
            }

            void PluginVisitor::UpdateNode(Node* parent, Identifier* child)
            {
                auto oldSize = child->nameSize;
                auto newSize = child->name.size();

                int32 diffSize = newSize - oldSize;

                // Update parent source range
                parent->sourceSize += diffSize;

                // Replace in editor
                editor->Delete(child->sourceStart, child->nameSize);
                editor->Insert(child->sourceStart, child->name);

                child->nameSize = newSize;
                child->sourceSize += diffSize;

                // Adjust offset for the nodes that follow
                tokenOffset += diffSize;

                // The new node should not be re-adjusted in the future
                child->AdjustSourceOffset(tokenOffset);
            }

            void PluginVisitor::UpdateNode(Node* parent, Expr* child)
            {
                if (child->GetExprType() == AST::ExprType::Identifier) {
                    UpdateNode(parent, (Identifier*) child);
                } else {
                    UpdateNode(parent, (Node*) child);
                }
            }

            void PluginVisitor::UpdateNode(Node* parent, Decl* child)
            {
                if (child->GetDeclType() == AST::DeclType::Function) {
                    UpdateNode(parent, (FunDecl*) child);
                } else {
                    UpdateNode(parent, (Node*) child);
                }
            }

            void PluginVisitor::UpdateNode(Node* parent, Node* child)
            {
                auto newSource = child->GenSourceCode();
                auto newSize   = newSource.size();

                int32 diffSize = newSize - child->sourceSize;

                // Update parent source range
                parent->sourceSize += diffSize;

                // Replace in editor
                editor->Delete(child->sourceStart, child->sourceSize);
                editor->Insert(child->sourceStart, newSource);

                // Adjust offset for the nodes that follow
                tokenOffset += diffSize;

                // The new node should not be re-adjusted in the future
                child->AdjustSourceOffset(tokenOffset);
            }

            // Since a child can have its children changed before being replaced,
            //
            // oldChildSize (before visiting the child and its children)
            // isn't the same as
            // child->source size (after visiting the child, but before replacement)
            void PluginVisitor::ReplaceNode(Node* parent, Node* child, uint32 oldChildSize, Node* replacement)
            {
                if (editor == nullptr) {
                    return; // AST-only replacement
                }

                auto replacedSize = child->sourceSize;

                // Source can either be a view or a new string
                std::u16string newSource;

                if (replacement->sourceSize != 0) {
                    // The replacement is a child of the child which already has everything set up
                    newSource = std::u16string(&(*editor)[replacement->sourceStart], replacement->sourceSize);
                } else {
                    // Generate new source
                    newSource               = replacement->GenSourceCode();
                    replacement->sourceSize = newSource.size();
                }

                int32 diffSize = replacement->sourceSize - oldChildSize;

                // Update new node source range
                replacement->AdjustSourceStart(child->sourceStart - replacement->sourceStart);

                // Update parent source range
                parent->sourceSize += diffSize;

                // Replace in editor
                editor->Delete(child->sourceStart, child->sourceSize);
                editor->Insert(child->sourceStart, newSource);

                // Adjust offset for the nodes that follow
                tokenOffset += (replacement->sourceSize - replacedSize);

                // The new node should not be re-adjusted in the future
                replacement->AdjustSourceOffset(tokenOffset);

                // Replace node
                delete child;
            }

            void PluginVisitor::RemoveNode(Node* parent, Node* child)
            {
                // Update parent size
                parent->sourceSize -= child->sourceSize;

                // Delete in editor
                editor->Delete(child->sourceStart, child->sourceSize);

                // Adjust offset for the nodes that follow
                tokenOffset -= child->sourceSize;

                // Delete node
                delete child;
            }

            void PluginVisitor::AdjustSize(Node* node, int32 offset)
            {
                node->sourceSize += offset;
            }

            PluginVisitor::PluginVisitor(Plugin* plugin, TextEditor* editor) : plugin(plugin), tokenOffset(0), editor(editor)
            {
            }

            Action PluginVisitor::VisitFunDecl(FunDecl* node, Decl*& replacement)
            {
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterFunDecl(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;
                Node* rep;

                auto it = node->params.begin();

                while (it != node->params.end()) {
                    auto size = (*it)->sourceSize;

                    // TODO: check if null
                    action = (*it)->Accept(*this, rep);

                    switch (action) {
                    case Action::Update: {
                        UpdateNode(node, *it);

                        dirty = true;
                        break;
                    }
                    case Action::Replace: {
                        ReplaceNode(node, *it, size, rep);
                        *it = (Identifier*) rep;

                        dirty = true;
                        break;
                    }
                    case Action::Replace_Revisit: {
                        ReplaceNode(node, *it, size, rep);
                        *it = (Identifier*) rep;

                        dirty = true;
                        continue; // Don't increment it
                    }
                    case Action::Remove: {
                        RemoveNode(node, *it);

                        it = node->params.erase(it);

                        if (it == node->params.begin()) {
                            // If the first child is deleted, update the parent start offset
                            node->AdjustSourceStart(tokenOffset);
                        }

                        dirty = true;
                        continue;
                    }
                    case Action::_UpdateChild: {
                        AdjustSize(node, (*it)->sourceSize - size);
                        break;
                    }
                    default: {
                        break;
                    }
                    }

                    it++;
                }

                if (node->block) {
                    auto size = node->block->sourceSize;

                    action = node->block->Accept(*this, rep);

                    switch (action) {
                    case Action::Update: {
                        UpdateNode(node, node->block);

                        dirty = true;
                        break;
                    }
                    case Action::Replace:
                    case Action::Replace_Revisit: {
                        ReplaceNode(node, node->block, size, rep);
                        node->block = (Block*) rep;

                        dirty = true;
                        break;
                    }
                    case Action::Remove: {
                        RemoveNode(node, node->block);
                        node->block = nullptr;

                        dirty = true;
                        break;
                    }
                    case Action::_UpdateChild: {
                        AdjustSize(node, node->block->sourceSize - size);
                        break;
                    }
                    default: {
                        break;
                    }
                    }
                }

                action = plugin->OnExitFunDecl(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitVarDeclList(VarDeclList* node, Decl*& replacement)
            {
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterVarDeclList(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;
                Node* rep;

                auto it = node->decls.begin();

                while (it != node->decls.end()) {
                    auto size = (*it)->sourceSize;

                    // TODO: check if null
                    action = (*it)->Accept(*this, rep);

                    switch (action) {
                    case Action::Update: {
                        UpdateNode(node, *it);

                        dirty = true;
                        break;
                    }
                    case Action::Replace: {
                        ReplaceNode(node, *it, size, rep);
                        *it = (VarDecl*) rep;

                        dirty = true;
                        break;
                    }
                    case Action::Replace_Revisit: {
                        ReplaceNode(node, *it, size, rep);
                        *it = (VarDecl*) rep;

                        dirty = true;
                        continue; // Don't increment it
                    }
                    case Action::Remove: {
                        RemoveNode(node, *it);

                        it = node->decls.erase(it);

                        if (it == node->decls.begin()) {
                            // If the first child is deleted, update the parent start offset
                            node->AdjustSourceStart(tokenOffset);
                        }

                        dirty = true;
                        continue;
                    }
                    case Action::_UpdateChild: {
                        AdjustSize(node, (*it)->sourceSize - size);
                        break;
                    }
                    default: {
                        break;
                    }
                    }

                    it++;
                }

                action = plugin->OnExitVarDeclList(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitVarDecl(VarDecl* node, Decl*& replacement)
            {
                // Update node source start if any nodes before it were modified
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterVarDecl(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;

                if (node->init) {
                    auto size = node->init->sourceSize;

                    Node* rep;
                    action = node->init->Accept(*this, rep);

                    switch (action) {
                    case Action::Update: {
                        UpdateNode(node, node->init);

                        dirty = true;
                        break;
                    }
                    case Action::Replace:
                    case Action::Replace_Revisit: {
                        ReplaceNode(node, node->init, size, rep);
                        node->init = (Expr*) rep;

                        dirty = true;
                        break;
                    }
                    case Action::Remove: {
                        RemoveNode(node, node->init);
                        node->init = nullptr;

                        dirty = true;
                        break;
                    }
                    case Action::_UpdateChild: {
                        AdjustSize(node, node->init->sourceSize - size);
                        break;
                    }
                    default: {
                        break;
                    }
                    }
                }

                action = plugin->OnExitVarDecl(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitBlock(Block* node, Block*& replacement)
            {
                // Update node source start if any nodes before it were modified
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterBlock(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;

                // Since children can change, the block has to keep updating its size
                auto offset = tokenOffset;

                auto it = node->decls.begin();

                while (it != node->decls.end()) {
                    auto size = (*it)->sourceSize;

                    Node* rep;
                    auto action = (*it)->Accept(*this, rep);

                    switch (action) {
                    case Action::Update: {
                        UpdateNode(node, *it);

                        dirty = true;
                        break;
                    }
                    case Action::Replace: {
                        ReplaceNode(node, *it, size, rep);
                        *it = (Stmt*) rep;

                        dirty = true;
                        break;
                    }
                    case Action::Replace_Revisit: {
                        ReplaceNode(node, *it, size, rep);
                        *it = (Stmt*) rep;

                        dirty = true;
                        continue; // Don't increment it
                    }
                    case Action::Remove: {
                        RemoveNode(node, *it);

                        it = node->decls.erase(it);

                        if (it == node->decls.begin()) {
                            // If the first child is deleted, update the parent start offset
                            node->AdjustSourceStart(tokenOffset);
                        }

                        dirty = true;
                        continue;
                    }
                    case Action::_UpdateChild: {
                        node->sourceSize += (tokenOffset - offset);
                        offset = tokenOffset;

                        dirty = true;
                        break;
                    }
                    default: {
                        break;
                    }
                    }

                    it++;
                }

                action = plugin->OnExitBlock(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                if (dirty) {
                    return Action::_UpdateChild;
                }

                return Action::None;
            }
            Action PluginVisitor::VisitIfStmt(IfStmt* node, Stmt*& replacement)
            {
                // Update node source start if any nodes before it were modified
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterIfStmt(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;

                // If a child changes, the other children should also change relative to that
                // auto offset = tokenOffset;
                auto size = node->cond->sourceSize;

                Node* rep;
                action = node->cond->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->cond);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->cond, size, rep);
                    node->cond = (Expr*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->cond);

                    node->cond = nullptr;

                    dirty = true;
                    break;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->cond->sourceSize - size);

                    dirty = true;
                    break;
                }
                default: {
                    break;
                }
                }

                if (node->stmtTrue) {
                    // node->stmtTrue->AdjustSourceStart(node->cond->sourceOffset + node->cond->sourceSize - size);
                    node->stmtTrue->AdjustSourceStart(tokenOffset);
                }

                if (node->stmtFalse) {
                    // node->stmtFalse->AdjustSourceStart(node->cond->sourceOffset + node->cond->sourceSize - size);
                    node->stmtFalse->AdjustSourceStart(tokenOffset);
                }

                if (node->stmtTrue) {
                    size = node->stmtTrue->sourceSize;

                    action = node->stmtTrue->Accept(*this, rep);

                    switch (action) {
                    case Action::Update: {
                        UpdateNode(node, node->stmtTrue);

                        dirty = true;
                        break;
                    }
                    case Action::Replace:
                    case Action::Replace_Revisit: {
                        ReplaceNode(node, node->stmtTrue, size, rep);
                        node->stmtTrue = (Stmt*) rep;

                        if (node->stmtFalse) {
                            node->stmtFalse->AdjustSourceStart(tokenOffset);
                        }

                        dirty = true;
                        break;
                    }
                    case Action::Remove: {
                        RemoveNode(node, node->stmtTrue);

                        node->stmtTrue = nullptr;

                        dirty = true;
                        break;
                    }
                    case Action::_UpdateChild: {
                        AdjustSize(node, node->stmtTrue->sourceSize - size);

                        if (node->stmtFalse) {
                            node->stmtFalse->AdjustSourceStart(tokenOffset);
                        }
                        break;
                    }
                    default: {
                        break;
                    }
                    }
                }

                if (node->stmtFalse) {
                    size = node->stmtFalse->sourceSize;

                    action = node->stmtFalse->Accept(*this, rep);

                    switch (action) {
                    case Action::Update: {
                        UpdateNode(node, node->stmtFalse);

                        dirty = true;
                        break;
                    }
                    case Action::Replace:
                    case Action::Replace_Revisit: {
                        ReplaceNode(node, node->stmtFalse, size, rep);
                        node->stmtFalse = (Stmt*) rep;

                        dirty = true;
                        break;
                    }
                    case Action::Remove: {
                        RemoveNode(node, node->stmtFalse);

                        node->stmtFalse = nullptr;

                        dirty = true;
                        break;
                    }
                    case Action::_UpdateChild: {
                        AdjustSize(node, node->stmtFalse->sourceSize - size);
                        break;
                    }
                    default: {
                        break;
                    }
                    }
                }

                action = plugin->OnExitIfStmt(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitWhileStmt(WhileStmt* node, Stmt*& replacement)
            {
                // Update node source start if any nodes before it were modified
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterWhileStmt(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;

                // If a child changes, the other children should also change relative to that
                // auto offset = tokenOffset;
                auto size = node->cond->sourceSize;

                Node* rep;
                action = node->cond->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->cond);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->cond, size, rep);
                    node->cond = (Expr*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->cond);

                    node->cond = nullptr;

                    dirty = true;
                    break;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->cond->sourceSize - size);

                    dirty = true;
                    break;
                }
                default: {
                    break;
                }
                }

                if (node->stmt) {
                    node->stmt->AdjustSourceStart(tokenOffset);
                }

                size = node->stmt->sourceSize;

                action = node->stmt->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->stmt);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->stmt, size, rep);
                    node->stmt = (Stmt*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->stmt);

                    node->stmt = nullptr;

                    dirty = true;
                    break;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->stmt->sourceSize - size);

                    break;
                }
                default: {
                    break;
                }
                }

                action = plugin->OnExitWhileStmt(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitForStmt(ForStmt* node, Stmt*& replacement)
            {
                // Update node source start if any nodes before it were modified
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterForStmt(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;

                // If a child changes, the other children should also change relative to that
                // auto offset = tokenOffset;
                auto size = node->cond->sourceSize;

                Node* rep;
                action = node->decl->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->decl);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->decl, size, rep);
                    node->decl = (VarDeclList*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->decl);

                    node->decl = nullptr;

                    dirty = true;
                    break;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->decl->sourceSize - size);

                    dirty = true;
                    break;
                }
                default: {
                    break;
                }
                }

                if (node->cond) {
                    node->cond->AdjustSourceStart(tokenOffset);
                }

                if (node->inc) {
                    node->inc->AdjustSourceStart(tokenOffset);
                }

                if (node->stmt) {
                    node->stmt->AdjustSourceStart(tokenOffset);
                }

                if (node->cond) {
                    size = node->cond->sourceSize;

                    action = node->cond->Accept(*this, rep);

                    switch (action) {
                    case Action::Update: {
                        UpdateNode(node, node->cond);

                        dirty = true;
                        break;
                    }
                    case Action::Replace:
                    case Action::Replace_Revisit: {
                        ReplaceNode(node, node->cond, size, rep);
                        node->cond = (Expr*) rep;

                        dirty = true;
                        break;
                    }
                    case Action::Remove: {
                        RemoveNode(node, node->cond);

                        node->cond = nullptr;

                        dirty = true;
                        break;
                    }
                    case Action::_UpdateChild: {
                        AdjustSize(node, node->cond->sourceSize - size);

                        break;
                    }
                    default: {
                        break;
                    }
                    }

                    if (node->inc) {
                        node->inc->AdjustSourceStart(tokenOffset);
                    }

                    if (node->stmt) {
                        node->stmt->AdjustSourceStart(tokenOffset);
                    }
                }

                if (node->inc) {
                    size = node->inc->sourceSize;

                    action = node->inc->Accept(*this, rep);

                    switch (action) {
                    case Action::Update: {
                        UpdateNode(node, node->inc);

                        dirty = true;
                        break;
                    }
                    case Action::Replace:
                    case Action::Replace_Revisit: {
                        ReplaceNode(node, node->inc, size, rep);
                        node->inc = (Expr*) rep;

                        dirty = true;
                        break;
                    }
                    case Action::Remove: {
                        RemoveNode(node, node->inc);

                        node->inc = nullptr;

                        dirty = true;
                        break;
                    }
                    case Action::_UpdateChild: {
                        AdjustSize(node, node->inc->sourceSize - size);

                        break;
                    }
                    default: {
                        break;
                    }
                    }

                    if (node->stmt) {
                        node->stmt->AdjustSourceStart(tokenOffset);
                    }
                }

                if (node->stmt) {
                    size = node->stmt->sourceSize;

                    action = node->stmt->Accept(*this, rep);

                    switch (action) {
                    case Action::Update: {
                        UpdateNode(node, node->stmt);

                        dirty = true;
                        break;
                    }
                    case Action::Replace:
                    case Action::Replace_Revisit: {
                        ReplaceNode(node, node->stmt, size, rep);
                        node->stmt = (Stmt*) rep;

                        dirty = true;
                        break;
                    }
                    case Action::Remove: {
                        RemoveNode(node, node->stmt);

                        node->stmt = nullptr;

                        dirty = true;
                        break;
                    }
                    case Action::_UpdateChild: {
                        AdjustSize(node, node->stmt->sourceSize - size);
                        break;
                    }
                    default: {
                        break;
                    }
                    }
                }

                action = plugin->OnExitForStmt(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }

            Action PluginVisitor::VisitReturnStmt(ReturnStmt* node, Stmt*& replacement)
            {
                // Update node source start if any nodes before it were modified
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterReturnStmt(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;

                if (node->expr) {
                    auto size = node->expr->sourceSize;

                    Node* rep;
                    action = node->expr->Accept(*this, rep);

                    switch (action) {
                    case Action::Update: {
                        UpdateNode(node, node->expr);

                        dirty = true;
                        break;
                    }
                    case Action::Replace:
                    case Action::Replace_Revisit: {
                        ReplaceNode(node, node->expr, size, rep);
                        node->expr = (Expr*) rep;

                        dirty = true;
                        break;
                    }
                    case Action::Remove: {
                        RemoveNode(node, node->expr);

                        node->expr = nullptr;

                        dirty = true;
                        break;
                    }
                    case Action::_UpdateChild: {
                        AdjustSize(node, node->expr->sourceSize - size);
                        break;
                    }
                    default: {
                        break;
                    }
                    }
                }

                action = plugin->OnExitReturnStmt(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }

            Action PluginVisitor::VisitExprStmt(ExprStmt* node, Stmt*& replacement)
            {
                // Update node source start if any nodes before it were modified
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterExprStmt(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;

                auto size = node->expr->sourceSize;

                Node* rep;
                action = node->expr->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->expr);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->expr, size, rep);
                    node->expr = (Expr*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->expr);

                    node->expr = nullptr;

                    // Update the parent start offset
                    node->AdjustSourceStart(tokenOffset);

                    dirty = true;
                    break;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->expr->sourceSize - size);
                    break;
                }
                default: {
                    break;
                }
                }

                action = plugin->OnExitExprStmt(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitIdentifier(Identifier* node, Expr*& replacement)
            {
                // Update node source start if any nodes before it were modified
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterIdentifier(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                action = plugin->OnExitIdentifier(node, replacement);
                return action;
            }
            Action PluginVisitor::VisitUnop(Unop* node, Expr*& replacement)
            {
                // Update node source start if any nodes before it were modified
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterUnop(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;

                auto size = node->expr->sourceSize;

                Node* rep;
                action = node->expr->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->expr);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->expr, size, rep);
                    node->expr = (Expr*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->expr);

                    node->expr = nullptr;

                    return Action::Remove;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->expr->sourceSize - size);
                    break;
                }
                default: {
                    break;
                }
                }

                action = plugin->OnExitUnop(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitBinop(Binop* node, Expr*& replacement)
            {
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterBinop(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;
                auto size  = node->left->sourceSize;

                Node* rep;
                action = node->left->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->left);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->left, size, rep);
                    node->left = (Expr*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->left);

                    node->left = nullptr;

                    // A binary operator without a left doesn't make sense; delete it
                    return Action::Remove;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->left->sourceSize - size);
                    break;
                }
                default: {
                    break;
                }
                }

                if (node->right) {
                    node->right->AdjustSourceStart(tokenOffset);
                }

                size = node->right->sourceSize;

                // TODO: check if null
                action = node->right->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->right);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->right, size, rep);
                    node->right = (Expr*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->right);

                    node->right = nullptr;

                    // A binary operator without a right doesn't make sense; delete it
                    return Action::Remove;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->right->sourceSize - size);
                    break;
                }
                default: {
                    break;
                }
                }

                action = plugin->OnExitBinop(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitTernary(Ternary* node, Expr*& replacement)
            {
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterTernary(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;
                auto size  = node->cond->sourceSize;

                Node* rep;
                action = node->cond->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->cond);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->cond, size, rep);
                    node->cond = (Expr*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->cond);

                    node->cond = nullptr;

                    // A ternary operator without a condition doesn't make sense; delete it
                    return Action::Remove;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->cond->sourceSize - size);
                    break;
                }
                default: {
                    break;
                }
                }

                if (node->exprTrue) {
                    node->exprTrue->AdjustSourceStart(tokenOffset);
                }

                if (node->exprFalse) {
                    node->exprFalse->AdjustSourceStart(tokenOffset);
                }

                size = node->exprTrue->sourceSize;

                // TODO: check if null
                action = node->exprTrue->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->exprTrue);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->exprTrue, size, rep);
                    node->exprTrue = (Expr*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->exprTrue);

                    node->exprTrue = nullptr;

                    // A binary operator without a true expr doesn't make sense; delete it
                    return Action::Remove;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->exprTrue->sourceSize - size);
                    break;
                }
                default: {
                    break;
                }
                }

                if (node->exprFalse) {
                    node->exprFalse->AdjustSourceStart(tokenOffset);
                }

                size = node->exprFalse->sourceSize;

                // TODO: check if null
                action = node->exprFalse->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->exprFalse);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->exprFalse, size, rep);
                    node->exprFalse = (Expr*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->exprFalse);

                    node->exprFalse = nullptr;

                    // A binary operator without a false expr doesn't make sense; delete it
                    return Action::Remove;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->exprFalse->sourceSize - size);
                    break;
                }
                default: {
                    break;
                }
                }

                action = plugin->OnExitTernary(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitCall(Call* node, Expr*& replacement)
            {
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterCall(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;
                auto size  = node->callee->sourceSize;

                Node* rep;
                action = node->callee->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->callee);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->callee, size, rep);
                    node->callee = (Expr*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->callee);

                    node->callee = nullptr;

                    // A call without a callee doesn't make sense; delete it
                    return Action::Remove;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->callee->sourceSize - size);
                    break;
                }
                default: {
                    break;
                }
                }

                auto it = node->args.begin();

                while (it != node->args.end()) {
                    size = (*it)->sourceSize;

                    // TODO: check if null
                    action = (*it)->Accept(*this, rep);

                    switch (action) {
                    case Action::Update: {
                        UpdateNode(node, *it);

                        dirty = true;
                        break;
                    }
                    case Action::Replace:
                    case Action::Replace_Revisit: {
                        ReplaceNode(node, *it, size, rep);
                        (*it) = (Expr*) rep;

                        dirty = true;
                        break;
                    }
                    case Action::Remove: {
                        RemoveNode(node, *it);

                        it = node->args.erase(it);

                        dirty = true;
                        continue;
                    }
                    case Action::_UpdateChild: {
                        AdjustSize(node, (*it)->sourceSize - size);
                        break;
                    }
                    default: {
                        break;
                    }
                    }

                    it++;
                }

                action = plugin->OnExitCall(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitLambda(Lambda* node, Expr*& replacement)
            {
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterLambda(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;
                Node* rep;

                auto it = node->params.begin();

                while (it != node->params.end()) {
                    auto size = (*it)->sourceSize;

                    // TODO: check if null
                    action = (*it)->Accept(*this, rep);

                    switch (action) {
                    case Action::Update: {
                        UpdateNode(node, *it);

                        dirty = true;
                        break;
                    }
                    case Action::Replace:
                    case Action::Replace_Revisit: { // No point in revisiting an identifier
                        ReplaceNode(node, *it, size, rep);
                        *it = (Identifier*) rep;

                        dirty = true;
                        break;
                    }
                    case Action::Remove: {
                        RemoveNode(node, *it);

                        auto first = (node->sourceStart == (*it)->sourceStart);

                        it = node->params.erase(it);

                        if (first) {
                            node->AdjustSourceStart(tokenOffset);
                        }

                        dirty = true;
                        continue;
                    }
                    case Action::_UpdateChild: {
                        AdjustSize(node, (*it)->sourceSize - size);
                        break;
                    }
                    default: {
                        break;
                    }
                    }

                    it++;
                }

                auto size = node->body->sourceSize;

                action = node->body->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->body);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->body, size, rep);
                    node->body = (Stmt*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->body);

                    node->body = nullptr;

                    dirty = true;
                    break;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->body->sourceSize - size);
                    break;
                }
                default: {
                    break;
                }
                }

                action = plugin->OnExitLambda(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitGrouping(Grouping* node, Expr*& replacement)
            {
                // Update node source start if any nodes before it were modified
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterGrouping(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;

                auto size = node->expr->sourceSize;

                Node* rep;
                action = node->expr->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->expr);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->expr, size, rep);
                    node->expr = (Expr*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->expr);

                    node->expr = nullptr;

                    // A grouping without an expr doesn't make sense; delete it
                    return Action::Remove;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->expr->sourceSize - size);
                    break;
                }
                default: {
                    break;
                }
                }

                action = plugin->OnExitGrouping(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitCommaList(CommaList* node, Expr*& replacement)
            {
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterCommaList(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;
                Node* rep;

                auto it = node->list.begin();

                while (it != node->list.end()) {
                    auto size = (*it)->sourceSize;

                    // TODO: check if null
                    action = (*it)->Accept(*this, rep);

                    switch (action) {
                    case Action::Update: {
                        UpdateNode(node, *it);

                        dirty = true;
                        break;
                    }
                    case Action::Replace:
                    case Action::Replace_Revisit: {
                        ReplaceNode(node, *it, size, rep);
                        (*it) = (Expr*) rep;

                        dirty = true;
                        break;
                    }
                    case Action::Remove: {
                        RemoveNode(node, *it);

                        auto first = (node->sourceStart == (*it)->sourceStart);

                        it = node->list.erase(it);

                        if (first) {
                            node->AdjustSourceStart(tokenOffset);
                        }

                        dirty = true;
                        break;
                    }
                    case Action::_UpdateChild: {
                        AdjustSize(node, (*it)->sourceSize - size);
                        break;
                    }
                    default: {
                        break;
                    }
                    }
                }

                action = plugin->OnExitCommaList(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitMemberAccess(MemberAccess* node, Expr*& replacement)
            {
                // Update node source start if any nodes before it were modified
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterMemberAccess(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                auto dirty = false;

                auto size = node->obj->sourceSize;

                Node* rep;
                action = node->obj->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->obj);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->obj, size, rep);
                    node->obj = (Expr*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->obj);

                    node->obj = nullptr;

                    // A member access without an obj doesn't make sense; delete it
                    return Action::Remove;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->obj->sourceSize - size);
                    break;
                }
                default: {
                    break;
                }
                }

                if (node->member) {
                    node->member->AdjustSourceStart(tokenOffset);
                }

                size = node->member->sourceSize;

                action = node->member->Accept(*this, rep);

                switch (action) {
                case Action::Update: {
                    UpdateNode(node, node->member);

                    dirty = true;
                    break;
                }
                case Action::Replace:
                case Action::Replace_Revisit: {
                    ReplaceNode(node, node->member, size, rep);
                    node->member = (Expr*) rep;

                    dirty = true;
                    break;
                }
                case Action::Remove: {
                    RemoveNode(node, node->member);

                    node->member = nullptr;

                    // A member access without a member doesn't make sense; delete it
                    return Action::Remove;
                }
                case Action::_UpdateChild: {
                    AdjustSize(node, node->member->sourceSize - size);
                    break;
                }
                default: {
                    break;
                }
                }

                action = plugin->OnExitMemberAccess(node, replacement);

                // Node was altered
                if (action != Action::None) {
                    return action;
                }

                // Node wasn't altered, but children were
                if (dirty) {
                    return Action::_UpdateChild;
                }

                // Node and children weren't altered
                return Action::None;
            }
            Action PluginVisitor::VisitNumber(Number* node, Expr*& replacement)
            {
                // Update node source start if any nodes before it were modified
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterNumber(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                action = plugin->OnExitNumber(node, replacement);
                return action;
            }
            Action PluginVisitor::VisitString(AST::String* node, Expr*& replacement)
            {
                // Update node source start if any nodes before it were modified
                node->AdjustSourceStart(tokenOffset);

                auto action = plugin->OnEnterString(node, replacement);
                if (action != Action::None) {
                    return action;
                }

                action = plugin->OnExitString(node, replacement);
                return action;
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

            void DumpVisitor::VisitFunDecl(const FunDecl* node)
            {
                DUMP("FunDecl");

                file << ", \"name\": \"" << ToString(node->name).GetText() << "\", \"params\": [";

                DUMP_LIST(params);

                file << "], \"block\": ";

                DUMP_MEMBER(block);

                file << "}";
            }
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
            void DumpVisitor::VisitReturnStmt(const ReturnStmt* node)
            {
                DUMP("ReturnStmt");

                file << ", \"expr\": ";

                DUMP_MEMBER(expr);

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

#define ADVANCE_NOCHECK() ++current;

#define ADVANCE_ONCE() ++current;

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

                SKIP_COMMENTS();

                return block;
            }

            Decl* Parser::ParseDecl()
            {
                auto type = GetCurrentType();

                switch (type) {
                case TokenType::DataType_Var:
                case TokenType::DataType_Let: {
                    auto sourceStart = GetCurrent();

                    auto decl = ParseVarDecl();

                    if (GetCurrentType() == TokenType::Semicolumn) {
                        ADVANCE_NOCHECK();

                        // Include ';'
                        decl->SetSourceEnd(GetPrevious());

                        SKIP_COMMENTS();
                    }

                    return decl;
                }
                case TokenType::Keyword_Function: {
                    return ParseFunDecl();
                }
                default: {
                    return ParseStmt();
                }
                }
            }

            FunDecl* Parser::ParseFunDecl()
            {
                auto sourceStart = GetCurrent();

                ADVANCE(); // function

                EXPECT(TokenType::Word);

                auto name = GetCurrent().GetText();
                auto nameOffset = GetCurrentOffset();

                ADVANCE();

                auto fun = new FunDecl(name);

                EXPECT(TokenType::ExpressionOpen);
                ADVANCE();

                if (GetCurrentType() != TokenType::ExpressionClose) {
                    while (current < end) {
                        auto id = ParseIdentifier();

                        fun->params.emplace_back((Identifier*) id);

                        if (GetCurrentType() != TokenType::Comma) {
                            break;
                        }

                        ADVANCE();
                    }
                }

                EXPECT(TokenType::ExpressionClose);
                ADVANCE();

                fun->block = ParseBlock();

                fun->SetSource(sourceStart, GetPrevious());
                fun->nameOffset = nameOffset;

                return fun;
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
                case TokenType::Keyword_Return:
                    return ParseReturnStmt();
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

                        SKIP_COMMENTS();
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
                ADVANCE();

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

            ReturnStmt* Parser::ParseReturnStmt()
            {
                auto sourceStart = GetCurrent();

                ADVANCE();

                auto node = new ReturnStmt(ParseExpr());

                if (GetCurrentType() == TokenType::Semicolumn) {
                    ADVANCE_NOCHECK();
                }

                node->SetSource(sourceStart, GetPrevious());

                SKIP_COMMENTS();

                return node;
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
                auto type        = GetCurrentType();

                if (type != TokenType::Word && type < TokenType::Keyword_Clearinterval && type > TokenType::DataType_Long) {
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

            uint32 Parser::GetCurrentOffset()
            {
                auto opt = tokens[current].GetTokenStartOffset();

                if (opt.has_value()) {
                    return opt.value();
                }

                return 0;
            }
        } // namespace AST
    }     // namespace JS
} // namespace Type
} // namespace GView