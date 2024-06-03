#include "js.hpp"

#include <fstream>

namespace GView
{
namespace Type
{
    namespace JS
    {
        namespace AST
        {
            typedef GView::View::LexicalViewer::Token Token;
            typedef GView::View::LexicalViewer::TokensList TokensList;
            typedef GView::View::LexicalViewer::TextEditor TextEditor;

            class Node;
            class Decl;
            class VarDeclList;
            class VarDecl;
            class Stmt;
            class Block;
            class IfStmt;
            class WhileStmt;
            class ForStmt;
            class ExprStmt;
            class Expr;
            class Identifier;
            class Unop;
            class Binop;
            class Ternary;
            class Call;
            class Lambda;
            class Grouping;
            class CommaList;
            class MemberAccess;
            class Constant;
            class Number;
            class String;

            enum class Action { None, Update, Replace, Delete, _UpdateChild };

            class ConstVisitor
            {
              public:
                virtual void VisitVarDeclList(const VarDeclList* node);
                virtual void VisitVarDecl(const VarDecl* node);
                virtual void VisitBlock(const Block* node);
                virtual void VisitIfStmt(const IfStmt* nodet);
                virtual void VisitWhileStmt(const WhileStmt* node);
                virtual void VisitForStmt(const ForStmt* node);
                virtual void VisitExprStmt(const ExprStmt* node);
                virtual void VisitIdentifier(const Identifier* node);
                virtual void VisitUnop(const Unop* node);
                virtual void VisitBinop(const Binop* node);
                virtual void VisitTernary(const Ternary* node);
                virtual void VisitCall(const Call* node);
                virtual void VisitLambda(const Lambda* node);
                virtual void VisitGrouping(const Grouping* node);
                virtual void VisitCommaList(const CommaList* node);
                virtual void VisitMemberAccess(const MemberAccess* node);
                virtual void VisitNumber(const Number* node);
                virtual void VisitString(const AST::String* node);
            };

            class Visitor
            {
              public:
                virtual Action VisitVarDeclList(VarDeclList* node, Decl*& replacement);
                virtual Action VisitVarDecl(VarDecl* node, Decl*& replacement);
                virtual Action VisitBlock(Block* node, Block*& replacement);
                virtual Action VisitIfStmt(IfStmt* node, Stmt*& replacement);
                virtual Action VisitWhileStmt(WhileStmt* node, Stmt*& replacement);
                virtual Action VisitForStmt(ForStmt* node, Stmt*& replacement);
                virtual Action VisitExprStmt(ExprStmt* node, Stmt*& replacement);
                virtual Action VisitIdentifier(Identifier* node, Expr*& replacement);
                virtual Action VisitUnop(Unop* node, Expr*& replacement);
                virtual Action VisitBinop(Binop* node, Expr*& replacement);
                virtual Action VisitTernary(Ternary* node, Expr*& replacement);
                virtual Action VisitCall(Call* node, Expr*& replacement);
                virtual Action VisitLambda(Lambda* node, Expr*& replacement);
                virtual Action VisitGrouping(Grouping* node, Expr*& replacement);
                virtual Action VisitCommaList(CommaList* node, Expr*& replacement);
                virtual Action VisitMemberAccess(MemberAccess* node, Expr*& replacement);
                virtual Action VisitNumber(Number* node, Expr*& replacement);
                virtual Action VisitString(AST::String* node, Expr*& replacement);
            };

            class Plugin
            {
              public:
                virtual Action OnEnterVarDeclList(VarDeclList* node, Decl*& replacement);
                virtual Action OnEnterVarDecl(VarDecl* node, Decl*& replacement);
                virtual Action OnEnterBlock(Block* node, Block*& replacement);
                virtual Action OnEnterIfStmt(IfStmt* node, Stmt*& replacement);
                virtual Action OnEnterWhileStmt(WhileStmt* node, Stmt*& replacement);
                virtual Action OnEnterForStmt(ForStmt* node, Stmt*& replacement);
                virtual Action OnEnterExprStmt(ExprStmt* node, Stmt*& replacement);
                virtual Action OnEnterIdentifier(Identifier* node, Expr*& replacement);
                virtual Action OnEnterUnop(Unop* node, Expr*& replacement);
                virtual Action OnEnterBinop(Binop* node, Expr*& replacement);
                virtual Action OnEnterTernary(Ternary* node, Expr*& replacement);
                virtual Action OnEnterCall(Call* node, Expr*& replacement);
                virtual Action OnEnterLambda(Lambda* node, Expr*& replacement);
                virtual Action OnEnterGrouping(Grouping* node, Expr*& replacement);
                virtual Action OnEnterCommaList(CommaList* node, Expr*& replacement);
                virtual Action OnEnterMemberAccess(MemberAccess* node, Expr*& replacement);
                virtual Action OnEnterNumber(Number* node, Expr*& replacement);
                virtual Action OnEnterString(AST::String* node, Expr*& replacement);

                virtual Action OnExitVarDeclList(VarDeclList* node, Decl*& replacement);
                virtual Action OnExitVarDecl(VarDecl* node, Decl*& replacement);
                virtual Action OnExitBlock(Block* node, Block*& replacement);
                virtual Action OnExitIfStmt(IfStmt* node, Stmt*& replacement);
                virtual Action OnExitWhileStmt(WhileStmt* node, Stmt*& replacement);
                virtual Action OnExitForStmt(ForStmt* node, Stmt*& replacement);
                virtual Action OnExitExprStmt(ExprStmt* node, Stmt*& replacement);
                virtual Action OnExitIdentifier(Identifier* node, Expr*& replacement);
                virtual Action OnExitUnop(Unop* node, Expr*& replacement);
                virtual Action OnExitBinop(Binop* node, Expr*& replacement);
                virtual Action OnExitTernary(Ternary* node, Expr*& replacement);
                virtual Action OnExitCall(Call* node, Expr*& replacement);
                virtual Action OnExitLambda(Lambda* node, Expr*& replacement);
                virtual Action OnExitGrouping(Grouping* node, Expr*& replacement);
                virtual Action OnExitCommaList(CommaList* node, Expr*& replacement);
                virtual Action OnExitMemberAccess(MemberAccess* node, Expr*& replacement);
                virtual Action OnExitNumber(Number* node, Expr*& replacement);
                virtual Action OnExitString(AST::String* node, Expr*& replacement);
            };

            class PluginVisitor : public Visitor
            {
              public:
                Plugin* plugin;
                TextEditor* editor;
                int32 tokenOffset;

                PluginVisitor(Plugin* plugin, TextEditor* editor);

                virtual Action VisitVarDeclList(VarDeclList* node, Decl*& replacement) override;
                virtual Action VisitVarDecl(VarDecl* node, Decl*& replacement) override;
                virtual Action VisitBlock(Block* node, Block*& replacement) override;
                virtual Action VisitIfStmt(IfStmt* node, Stmt*& replacement) override;
                virtual Action VisitWhileStmt(WhileStmt* node, Stmt*& replacement) override;
                virtual Action VisitForStmt(ForStmt* node, Stmt*& replacement) override;
                virtual Action VisitExprStmt(ExprStmt* node, Stmt*& replacement) override;
                virtual Action VisitIdentifier(Identifier* node, Expr*& replacement) override;
                virtual Action VisitUnop(Unop* node, Expr*& replacement) override;
                virtual Action VisitBinop(Binop* node, Expr*& replacement) override;
                virtual Action VisitTernary(Ternary* node, Expr*& replacement) override;
                virtual Action VisitCall(Call* node, Expr*& replacement) override;
                virtual Action VisitLambda(Lambda* node, Expr*& replacement) override;
                virtual Action VisitGrouping(Grouping* node, Expr*& replacement) override;
                virtual Action VisitCommaList(CommaList* node, Expr*& replacement) override;
                virtual Action VisitMemberAccess(MemberAccess* node, Expr*& replacement) override;
                virtual Action VisitNumber(Number* node, Expr*& replacement) override;
                virtual Action VisitString(AST::String* node, Expr*& replacement) override;

                private:
                  void ReplaceNode(Node* parent, Node* child, uint32 oldChildSize, Node* replacement);
                  void AdjustSize(Node* node, int32 offset);
            };

            class DumpVisitor : public ConstVisitor
            {
              public:
                std::ofstream file;

                DumpVisitor(const char* file);
                ~DumpVisitor();

                virtual void VisitVarDeclList(const VarDeclList* node) override;
                virtual void VisitVarDecl(const VarDecl* node) override;
                virtual void VisitBlock(const Block* node) override;
                virtual void VisitIfStmt(const IfStmt* node) override;
                virtual void VisitWhileStmt(const WhileStmt* node) override;
                virtual void VisitForStmt(const ForStmt* node) override;
                virtual void VisitExprStmt(const ExprStmt* node) override;
                virtual void VisitIdentifier(const Identifier* node) override;
                virtual void VisitUnop(const Unop* node) override;
                virtual void VisitBinop(const Binop* node) override;
                virtual void VisitTernary(const Ternary* node) override;
                virtual void VisitCall(const Call* node) override;
                virtual void VisitLambda(const Lambda* node) override;
                virtual void VisitGrouping(const Grouping* node) override;
                virtual void VisitCommaList(const CommaList* node) override;
                virtual void VisitMemberAccess(const MemberAccess* node) override;
                virtual void VisitNumber(const Number* node) override;
                virtual void VisitString(const AST::String* node) override;
            };

            class Parser
            {
              public:
                TokensList& tokens;

                int32 start;
                int32 end;
                int32 current;

                Parser(TokensList& tokens, int32 end);

                Block* ParseBlock();

                Decl* ParseDecl();
                VarDeclList* ParseVarDecl();

                Stmt* ParseStmt();
                IfStmt* ParseIfStmt();
                WhileStmt* ParseWhileStmt();
                ForStmt* ParseForStmt();
                ExprStmt* ParseExprStmt();

                Expr* ParseExpr();
                Expr* ParseComma();
                Expr* ParseAssignmentAndMisc();
                Expr* ParseLogicalOr();
                Expr* ParseLogicalAnd();
                Expr* ParseBitwiseOr();
                Expr* ParseBitwiseXor();
                Expr* ParseBitwiseAnd();
                Expr* ParseEquality();
                Expr* ParseRelational();
                Expr* ParseBitwiseShift();
                Expr* ParseAdditive();
                Expr* ParseMultiplicative();
                Expr* ParseExponentiation();
                Expr* ParsePrefix();
                Expr* ParsePostfix();

                // TODO: new
                Expr* ParseCall();
                Expr* ParseGrouping();
                Expr* ParsePrimary();
                Expr* ParseIdentifier();

                Token GetCurrent();
                Token GetPrevious();
                uint32 GetCurrentType();
            }; // namespace AST

            class Instance
            {
              public:
                Block* script;

                int32 tokenOffset;

                void Create(TokensList& tokens);

                ~Instance();
            };

            class Node
            {
              public:
                virtual ~Node() = default;

                virtual Action Accept(Visitor& visitor, Node*& replacement) = 0;
                virtual void AcceptConst(ConstVisitor& visitor) = 0;

                uint32 sourceStart;
                uint32 sourceSize;
                int32 sourceOffset = 0;

                void SetSource(Token start, Token end);
                void SetSourceEnd(Token end);

                virtual void AdjustSourceStart(int32 offset);

                virtual std::u16string GenSourceCode();
            };

            class Decl : public Node
            {
            };

            class VarDeclList : public Decl
            {
              public:
                uint32 type;
                std::vector<VarDecl*> decls;

                VarDeclList(uint32 type);
                ~VarDeclList();

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            class VarDecl : public Decl
            {
              public:
                u16string_view name;
                Expr* init;

                ~VarDecl();

                VarDecl(u16string_view name, Expr* init);

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            // Function decl

            class Stmt : public Decl
            {
            };

            class Block : public Stmt
            {
              public:
                std::vector<Decl*> decls;

                ~Block();

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            class IfStmt : public Stmt
            {
              public:
                Expr* cond;
                Stmt* stmtTrue;
                Stmt* stmtFalse;

                ~IfStmt();

                IfStmt(Expr* cond, Stmt* stmtTrue, Stmt* stmtFalse);

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            class WhileStmt : public Stmt
            {
              public:
                Expr* cond;
                Stmt* stmt;

                WhileStmt(Expr* cond, Stmt* stmt);

                ~WhileStmt();

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            class ForStmt : public Stmt
            {
              public:
                VarDeclList* decl;
                Expr* cond;
                Expr* inc;
                Stmt* stmt;

                ~ForStmt();

                ForStmt(VarDeclList* decl, Expr* cond, Expr* inc, Stmt* stmt);

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            class ExprStmt : public Stmt
            {
              public:
                Expr* expr;

                ~ExprStmt();

                ExprStmt(Expr* expr);

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            enum class ExprType { Unop, Binop, Ternary, Call, Constant, Identifier, Lambda, CommaList, Grouping, MemberAccess };
            enum class ConstType { Number, String };

            class Expr : public Node
            {
              public:
                virtual ExprType GetExprType() = 0;
            };

            class Identifier : public Expr
            {
              public:
                std::u16string name;

                Identifier(u16string_view name);

                virtual ExprType GetExprType() override;

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            class Unop : public Expr
            {
              public:
                uint32 type;
                Expr* expr;

                Unop(uint32 type, Expr* expr);

                ~Unop();

                virtual ExprType GetExprType() override;

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            class Binop : public Expr
            {
              public:
                uint32 type;
                Expr* left;
                Expr* right;

                Binop(uint32 type, Expr* left, Expr* right);

                ~Binop();

                virtual ExprType GetExprType() override;

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            class Ternary : public Expr
            {
              public:
                Expr* cond;
                Expr* exprTrue;
                Expr* exprFalse;

                Ternary(Expr* cond, Expr* exprTrue, Expr* exprFalse);

                ~Ternary();

                virtual ExprType GetExprType() override;

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            class Call : public Expr
            {
              public:
                Expr* callee;
                std::vector<Expr*> args;

                Call(Expr* callee, std::vector<Expr*> args);
                virtual ~Call() override;

                virtual ExprType GetExprType() override;

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            class Lambda : public Expr
            {
              public:
                std::vector<Identifier*> params;
                Stmt* body;

                Lambda(std::vector<Identifier*> params, Stmt* body);

                virtual ~Lambda() override;

                virtual ExprType GetExprType() override;

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            class Grouping : public Expr
            {
              public:
                Expr* expr;

                Grouping(Expr* expr);

                virtual ~Grouping() override;

                virtual ExprType GetExprType() override;

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            class CommaList : public Expr
            {
              public:
                std::vector<Expr*> list;

                ~CommaList();

                CommaList(std::vector<Expr*> list);

                virtual ExprType GetExprType() override;

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            class MemberAccess : public Expr
            {
              public:
                Expr* obj;
                Expr* member;

                ~MemberAccess();

                MemberAccess(Expr* obj, Expr* member);

                virtual ExprType GetExprType() override;

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;
            };

            class Constant : public Expr
            {
              public:
                virtual ExprType GetExprType() override;
                virtual ConstType GetConstType() = 0;
            };

            class Number : public Constant
            {
              public:
                int32 value;

                Number(int32 value);

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;

                virtual std::u16string GenSourceCode() override;

                virtual ConstType GetConstType() override;
            };

            class String : public Constant
            {
              public:
                std::u16string value;

                String(u16string_view value);

                virtual void AdjustSourceStart(int32 offset) override;

                virtual Action Accept(Visitor& visitor, Node*& replacement) override;
                virtual void AcceptConst(ConstVisitor& visitor) override;

                virtual std::u16string GenSourceCode() override;

                virtual ConstType GetConstType() override;
            };
        } // namespace AST
    }     // namespace JS
} // namespace Type
} // namespace GView