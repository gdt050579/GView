#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace SQL
    {
        class SQLFile : public TypeInterface
        {
          public:
            SQLFile();

            bool Update();

            std::string_view GetTypeName() override
            {
                return "SQL";
            }
            void RunCommand(std::string_view) override
            {
            }
            virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
            {
                return true;
            }
            GView::Utils::JsonBuilderInterface* GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt) override;
        };
    } // namespace SQL
} // namespace Type
} // namespace GView
