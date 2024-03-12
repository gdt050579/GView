#include "Internal.hpp"

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;

class TutorialWindow : public Window, public Handlers::OnButtonPressedInterface
{
    Reference<AppCUI::Controls::ImageView> imgView;
    Reference<Label> label;

  public:
    TutorialWindow() : Window("GView tutorial", "d:c,w:80%,h:80%", WindowFlags::Sizeable)
    {
        label   = Factory::Label::Create(this, "Welcome to the GView tutorial", "t:1,l:5,w:50");
        imgView = Factory::ImageView::Create(this, "d:c,w:99%,h:80%", ViewerFlags::None);

        // imgView->SetVScrollBarTopMargin(4);
        // imgView->SetHScrollBarLeftMarging(4);
    }

    void OnButtonPressed(Reference<Controls::Button> r) override
    {
        this->Exit();
    }
};

void Instance::ShowTutorial()
{
    TutorialWindow tutorial{};
    tutorial.Show();
}