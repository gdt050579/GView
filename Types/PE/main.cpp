#include "GView.hpp"

using namespace AppCUI;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;

bool PLUGIN_EXPORT Validate(const unsigned char* buffer, unsigned int bufferSize, std::string extension)
{
    if (bufferSize < 2)
        return false;
    return (*buffer == 'M') && (buffer[1] == 'Z');
}

int main()
{
    return 0;
}
