#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace JS
    {
        constexpr uint32 SIZABLE_VALUE = 32;

        enum class BlockType
        {
            Block,
            Expression,
            Array,
            None
        };
        namespace TokenType
        {
            constexpr uint32 None            = 0xFFFFFFFF;
            constexpr uint32 Comment         = 0;
            constexpr uint32 ArrayOpen       = 1;
            constexpr uint32 ArrayClose      = 2;
            constexpr uint32 BlockOpen       = 3;
            constexpr uint32 BlockClose      = 4;
            constexpr uint32 ExpressionOpen  = 5;
            constexpr uint32 ExpressionClose = 6;
            constexpr uint32 Number          = 7;
            constexpr uint32 String          = 8;
            constexpr uint32 Comma           = 9;
            constexpr uint32 Semicolumn      = 10;
            constexpr uint32 Preprocess      = 11;
            constexpr uint32 Word            = 12;
            constexpr uint32 RegEx           = 13;

            constexpr uint32 Keyword_Clearinterval = 1000;
            constexpr uint32 Keyword_Java          = 1001;
            constexpr uint32 Keyword_Eval          = 1002;
            constexpr uint32 Keyword_Settimeout    = 1003;
            constexpr uint32 Keyword_Location      = 1004;
            constexpr uint32 Keyword_Win           = 1005;
            constexpr uint32 Keyword_With          = 1006;
            constexpr uint32 Keyword_While         = 1007;
            constexpr uint32 Keyword_Import        = 1008;
            constexpr uint32 Keyword_Releaseevents = 1009;
            constexpr uint32 Keyword_Focus         = 1010;
            constexpr uint32 Keyword_Final         = 1011;
            constexpr uint32 Keyword_Print         = 1012;
            constexpr uint32 Keyword_Instanceof    = 1013;
            constexpr uint32 Keyword_Protected     = 1014;
            constexpr uint32 Keyword_Native        = 1015;
            constexpr uint32 Keyword_Isfinite      = 1016;
            constexpr uint32 Keyword_Throws        = 1017;
            constexpr uint32 Keyword_Close         = 1018;
            constexpr uint32 Keyword_Packages      = 1019;
            constexpr uint32 Keyword_New           = 1020;
            constexpr uint32 Keyword_Arguments     = 1021;
            constexpr uint32 Keyword_Console       = 1022;
            constexpr uint32 Keyword_Parseint      = 1023;
            constexpr uint32 Keyword_Moveby        = 1024;
            constexpr uint32 Keyword_If            = 1025;
            constexpr uint32 Keyword_Resizeto      = 1026;
            constexpr uint32 Keyword_In            = 1027;
            constexpr uint32 Keyword_Scrollto      = 1028;
            constexpr uint32 Keyword_Catch         = 1029;
            constexpr uint32 Keyword_Infinity      = 1030;
            constexpr uint32 Keyword_Resizeby      = 1031;
            constexpr uint32 Keyword_History       = 1032;
            constexpr uint32 Keyword_Scrollby      = 1033;
            constexpr uint32 Keyword_Callee        = 1034;
            constexpr uint32 Keyword_Transient     = 1035;
            constexpr uint32 Keyword_Debugger      = 1036;
            constexpr uint32 Keyword_Do            = 1037;
            constexpr uint32 Keyword_Private       = 1038;
            constexpr uint32 Keyword_Self          = 1039;
            constexpr uint32 Keyword_Const         = 1040;
            constexpr uint32 Keyword_Delete        = 1041;
            constexpr uint32 Keyword_Caller        = 1042;
            constexpr uint32 Keyword_Blur          = 1043;
            constexpr uint32 Keyword_Defaultstatus = 1044;
            constexpr uint32 Keyword_Confirm       = 1045;
            constexpr uint32 Keyword_Innerheight   = 1046;
            constexpr uint32 Keyword_Scrollbars    = 1047;
            constexpr uint32 Keyword_Throw         = 1048;
            constexpr uint32 Keyword_Frames        = 1049;
            constexpr uint32 Keyword_Enum          = 1050;
            constexpr uint32 Keyword_Length        = 1051;
            constexpr uint32 Keyword_Interface     = 1052;
            constexpr uint32 Keyword_Return        = 1053;
            constexpr uint32 Keyword_Captureevents = 1054;
            constexpr uint32 Keyword_Tostring      = 1055;
            constexpr uint32 Keyword_Array         = 1056;
            constexpr uint32 Keyword_Abstract      = 1057;
            constexpr uint32 Keyword_Name          = 1058;
            constexpr uint32 Keyword_Package       = 1059;
            constexpr uint32 Keyword_Default       = 1060;
            constexpr uint32 Keyword_Switch        = 1061;
            constexpr uint32 Keyword_Document      = 1062;
            constexpr uint32 Keyword_Watc          = 1063;
            constexpr uint32 Keyword_Typeof        = 1064;
            constexpr uint32 Keyword_Case          = 1065;
            constexpr uint32 Keyword_Finally       = 1066;
            constexpr uint32 Keyword_Implements    = 1067;
            constexpr uint32 Keyword_Extends       = 1068;
            constexpr uint32 Keyword_Escape        = 1069;
            constexpr uint32 Keyword_Menubar       = 1070;
            constexpr uint32 Keyword_Function      = 1071;
            constexpr uint32 Keyword_Double        = 1072;
            constexpr uint32 Keyword_Routeevent    = 1073;
            constexpr uint32 Keyword_Top           = 1074;
            constexpr uint32 Keyword_Valueof       = 1075;
            constexpr uint32 Keyword_Class         = 1076;
            constexpr uint32 Keyword_Try           = 1077;
            constexpr uint32 Keyword_For           = 1078;
            constexpr uint32 Keyword_Statusbar     = 1079;
            constexpr uint32 Keyword_Continue      = 1080;
            constexpr uint32 Keyword_Isnan         = 1081;
            constexpr uint32 Keyword_Alert         = 1082;
            constexpr uint32 Keyword_Prototype     = 1083;
            constexpr uint32 Keyword_Status        = 1084;
            constexpr uint32 Keyword_Else          = 1085;
            constexpr uint32 Keyword_Find          = 1086;
            constexpr uint32 Keyword_Personalbar   = 1087;
            constexpr uint32 Keyword_Outerwidth    = 1088;
            constexpr uint32 Keyword_Break         = 1089;
            constexpr uint32 Keyword_Stop          = 1090;
            constexpr uint32 Keyword_Public        = 1091;
            constexpr uint32 Keyword_Pagexoffset   = 1092;
            constexpr uint32 Keyword_Static        = 1093;
            constexpr uint32 Keyword_Home          = 1094;
            constexpr uint32 Keyword_Open          = 1095;
            constexpr uint32 Keyword_Date          = 1096;
            constexpr uint32 Keyword_Netscape      = 1097;
            constexpr uint32 Keyword_Pageyoffset   = 1098;
            constexpr uint32 Keyword_This          = 1099;
            constexpr uint32 Keyword_Innerwidth    = 1100;
            constexpr uint32 Keyword_Scroll        = 1101;
            constexpr uint32 Keyword_Opener        = 1102;
            constexpr uint32 Keyword_Prompt        = 1103;
            constexpr uint32 Keyword_Unescape      = 1104;
            constexpr uint32 Keyword_Parsefloat    = 1105;
            constexpr uint32 Keyword_Unwatch       = 1106;
            constexpr uint32 Keyword_Cleartimeout  = 1107;
            constexpr uint32 Keyword_Parent        = 1108;
            constexpr uint32 Keyword_Closed        = 1109;
            constexpr uint32 Keyword_Outerheight   = 1110;
            constexpr uint32 Keyword_Math          = 1111;
            constexpr uint32 Keyword_Synchronized  = 1112;
            constexpr uint32 Keyword_Constructor   = 1113;
            constexpr uint32 Keyword_Goto          = 1114;
            constexpr uint32 Keyword_Super         = 1115;
            constexpr uint32 Keyword_Regexp        = 1116;
            constexpr uint32 Keyword_Locationbar   = 1117;
            constexpr uint32 Keyword_Export        = 1118;
            constexpr uint32 Keyword_Toolbar       = 1119;
            constexpr uint32 Keyword_Setinterval   = 1120;

            constexpr uint32 DataType_String  = 6000;
            constexpr uint32 DataType_Number  = 6001;
            constexpr uint32 DataType_Void    = 6002;
            constexpr uint32 DataType_Let     = 6003;
            constexpr uint32 DataType_Byte    = 6004;
            constexpr uint32 DataType_Boolean = 6005;
            constexpr uint32 DataType_Var     = 6006;
            constexpr uint32 DataType_Int     = 6007;
            constexpr uint32 DataType_Float   = 6008;
            constexpr uint32 DataType_Char    = 6009;
            constexpr uint32 DataType_Object  = 6010;
            constexpr uint32 DataType_Short   = 6011;
            constexpr uint32 DataType_Long    = 6012;

            constexpr uint32 Constant_False = 8000;
            constexpr uint32 Constant_Nan   = 8001;
            constexpr uint32 Constant_True  = 8002;
            constexpr uint32 Constant_Null  = 8003;

            constexpr uint32 Operator_Assignment                   = 9000;
            constexpr uint32 Operator_PlusAssignment               = 9001;
            constexpr uint32 Operator_MinusAssignment              = 9002;
            constexpr uint32 Operator_MupliplyAssignment           = 9003;
            constexpr uint32 Operator_DivisionAssignment           = 9004;
            constexpr uint32 Operator_ModuloAssignment             = 9005;
            constexpr uint32 Operator_ExponentiationAssignment     = 9006;
            constexpr uint32 Operator_LeftShiftAssignment          = 9007;
            constexpr uint32 Operator_RightShiftAssignment         = 9008;
            constexpr uint32 Operator_UnsignedRightShiftAssignment = 9009;
            constexpr uint32 Operator_AndAssignment                = 9010;
            constexpr uint32 Operator_XorAssignment                = 9011;
            constexpr uint32 Operator_OrAssignment                 = 9012;
            constexpr uint32 Operator_LogicANDAssignment           = 9013;
            constexpr uint32 Operator_LogicORAssignment            = 9014;
            constexpr uint32 Operator_LogicNullishAssignment       = 9015;
            constexpr uint32 Operator_Bigger                       = 9016;
            constexpr uint32 Operator_Smaller                      = 9017;
            constexpr uint32 Operator_BiggerOrEq                   = 9018;
            constexpr uint32 Operator_SmallerOrEQ                  = 9019;
            constexpr uint32 Operator_Equal                        = 9020;
            constexpr uint32 Operator_StrictEqual                  = 9021;
            constexpr uint32 Operator_Different                    = 9022;
            constexpr uint32 Operator_StrictDifferent              = 9023;
            constexpr uint32 Operator_Increment                    = 9024;
            constexpr uint32 Operator_Decrement                    = 9025;
            constexpr uint32 Operator_Plus                         = 9026;
            constexpr uint32 Operator_Minus                        = 9027;
            constexpr uint32 Operator_Multiply                     = 9028;
            constexpr uint32 Operator_Division                     = 9029;
            constexpr uint32 Operator_Modulo                       = 9030;
            constexpr uint32 Operator_Exponential                  = 9031;
            constexpr uint32 Operator_AND                          = 9032;
            constexpr uint32 Operator_OR                           = 9033;
            constexpr uint32 Operator_XOR                          = 9034;
            constexpr uint32 Operator_NOT                          = 9035;
            constexpr uint32 Operator_LeftShift                    = 9036;
            constexpr uint32 Operator_RightShift                   = 9037;
            constexpr uint32 Operator_SignRightShift               = 9038;
            constexpr uint32 Operator_LogicAND                     = 9039;
            constexpr uint32 Operator_LogicOR                      = 9040;
            constexpr uint32 Operator_LogicalNOT                   = 9041;
            constexpr uint32 Operator_Condition                    = 9042;
            constexpr uint32 Operator_TWO_POINTS                   = 9043;
            constexpr uint32 Operator_MemberAccess                 = 9044;
            constexpr uint32 Operator_ArrowFunction                = 9045;

            inline bool IsOperator(uint32 tokenType)
            {
                return (tokenType >= 9000 && tokenType <= 9999);
            }

            inline bool IsConstant(uint32 tokenType)
            {
                return (tokenType >= 8000 && tokenType <= 9000);
            }

            inline bool IsDatatype(uint32 tokenType)
            {
                return (tokenType >= 6000 && tokenType <= 7000);
            }

            inline bool IsKeyword(uint32 tokenType)
            {
                return (tokenType >= 1000 && tokenType <= 5000);
            }

            inline bool IsClassicKeyword(uint32 tokenType)
            {
                return (tokenType >= 0 && tokenType <= 100);
            }

        } // namespace TokenType

        namespace Plugins
        {
            class FoldConstants : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };
            class AddStrings : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };

            class ReverseStrings : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };

			class ReplaceConstants : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };

            class ConstPropagation : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };

            class RemoveDeadCode : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };

            class ContextAwareRename : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };

            class Emulate : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };

            class RemoveComments : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };

            class MarkAlwaysTrue : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };

            class UnrollLoop : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };
            class DumpAST : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(GView::View::LexicalViewer::PluginData& data) override;
            };
        } // namespace Plugins

        class JSFile : public TypeInterface, public GView::View::LexicalViewer::ParseInterface
        {
		  private:
            uint32 TokenizeWord(
                  const GView::View::LexicalViewer::TextParser& text, GView::View::LexicalViewer::TokensList& tokenList, uint32 pos);
            int32 ParseRegEx(
                  const GView::View::LexicalViewer::TextParser& text, GView::View::LexicalViewer::TokensList& tokenList, uint32 pos);
			uint32 TokenizeOperator(
                  const GView::View::LexicalViewer::TextParser& text, GView::View::LexicalViewer::TokensList& tokenList, uint32 pos);
            uint32 TokenizeList(
                  const GView::View::LexicalViewer::TextParser& text, GView::View::LexicalViewer::TokensList& tokenList, uint32 idx);
            uint32 TokenizePreprocessDirective(
                  const GView::View::LexicalViewer::TextParser& text,
                  GView::View::LexicalViewer::TokensList& list,
                  GView::View::LexicalViewer::BlocksList& blocks,
                  uint32 pos);
            BlockType GetBlockTypeWhichContainLastToken(const GView::View::LexicalViewer::TokensList& tokenList);
            void BuildBlocks(GView::View::LexicalViewer::SyntaxManager& syntax);
            void IndentSimpleInstructions(GView::View::LexicalViewer::TokensList& list);
            void CreateFoldUnfoldLinks(GView::View::LexicalViewer::SyntaxManager& syntax);
            void Tokenize(
                  uint32 start,
                  uint32 end,
                  const GView::View::LexicalViewer::TextParser& text,
                  GView::View::LexicalViewer::TokensList& list,
                  GView::View::LexicalViewer::BlocksList& blocks);
            void Tokenize(
                  const GView::View::LexicalViewer::TextParser& text,
                  GView::View::LexicalViewer::TokensList& list,
                  GView::View::LexicalViewer::BlocksList& blocks);
            void RemoveLineContinuityCharacter(GView::View::LexicalViewer::TextEditor& editor);
            void OperatorAlignament(GView::View::LexicalViewer::TokensList& tokenList);

          public:
            struct
            {
                Plugins::FoldConstants foldConstants;
                Plugins::ConstPropagation constPropagation;
                Plugins::RemoveDeadCode removeDeadCode;
                Plugins::ContextAwareRename contextAwareRename;
                Plugins::Emulate emulate;
                Plugins::RemoveComments removeComments;
                Plugins::MarkAlwaysTrue markAlwaysTrue;
                Plugins::UnrollLoop unrollLoop;
                Plugins::DumpAST dumpAST;
                Plugins::AddStrings addStrings;
                Plugins::ReverseStrings reverseStrings;
                Plugins::ReplaceConstants replaceConstants;
            } plugins;
            JSFile();
            virtual ~JSFile()
            {
            }

            bool Update();

            std::string_view GetTypeName() override
            {
                return "JavaScript";
            }
            void RunCommand(std::string_view) override
            {
            }
            virtual void GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str) override;
            virtual void PreprocessText(GView::View::LexicalViewer::TextEditor& editor) override;
            virtual void AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax) override;
            virtual bool StringToContent(std::u16string_view string, AppCUI::Utils::UnicodeStringBuilder& result) override;
            virtual bool ContentToString(std::u16string_view content, AppCUI::Utils::UnicodeStringBuilder& result) override;
        };
        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
                Reference<GView::Type::JS::JSFile> js;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> issues;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::JS::JSFile> js);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        }; // namespace Panels
    }      // namespace JS
} // namespace Type
} // namespace GView
