#include <AppCUI/include/AppCUI.hpp>

#ifdef CORE_EXPORTABLE
#    ifdef BUILD_FOR_WINDOWS
#        define CORE_EXPORT __declspec(dllexport)
#    else
#        define CORE_EXPORT
#    endif
#    else
#        define CORE_EXPORT
#endif

#ifdef BUILD_FOR_WINDOWS
#    define PLUGIN_EXPORT __declspec(dllexport)
#else
#    define PLUGIN_EXPORT
#endif

namespace GView
{
    class CORE_EXPORT FileCache
    {
        AppCUI::OS::IFile* fileObj;
        unsigned long long fileSize, start, end, currentPos;
        unsigned char* cache;
        unsigned int cacheSize;
    public:
        FileCache();
        ~FileCache();

        bool Init(std::unique_ptr<AppCUI::OS::IFile> file, unsigned int cacheSize);
        unsigned char* Get(unsigned long long offset, unsigned int requestedSize, unsigned int& availableSize);
        unsigned char* Get(unsigned long long offset, unsigned int requestedSize);
        unsigned char* Get(unsigned int requestedSize, unsigned int& availableSize);
        unsigned char* Get(unsigned int requestedSize);

        inline unsigned long long GetSize() const { return fileSize; }
        inline unsigned long long GetCurrentPos() const { return currentPos; }
        inline void SetCurrentPos(unsigned long long value) { currentPos = value;  }

            
    };
    class CORE_EXPORT Object
    {
        FileCache cache;
        // cursorul si pozitia lui
        // selectiile
    public:

    };
    namespace Type
    {
        class CORE_EXPORT Interface
        {
        public:

        };        
    };
    namespace View
    {
                                
    };
    EXPORT void Nothing();
};   

/* Object
- file, pid, buffer, url ==> toate sunt bufere
- folder

1. primesc fisierul --> obtin un obiect
2. din obj din cache citesc primii 128 octeti
3. iterez prin fiecare plugin si vad daca stie sa il proceseze --> primul care spune DA ma opresc
    pas 1 ==> vad daca simple match il prinde
    pas 2 ==> daca pluginul NU e incarcat --> il incarc
    pas 3 ==> verific match-ul de la plugin
4. Pentru pluginul obtinut --> obtin o interfata de tipul Type 
5. creez un FileWindow la care ii dau acea interfata de tipul Type
6. in FileWindow apeles din interfata de tipul type:
    pas 1 ==> cer o lista cu toate modurile de vizualizare
        - daca vreau sa fie un control ==> trebuie un page control (ceva care nu deseneaza nimic, dar care face un switch)
        - daca as avea asa ceva, interfata type nu ar face decat sa adauge controale            
            a) daca e un custom control --> il construiesc eu si il returnez
            b) daca e ceva din stock, folosesc un builder care pe functia Build imi da Controlul

    pas 2 ==> fiecare mod de vizualizare are si un info panel a lui
    pas 3 ==> creez panel-urile de infos verticale si orizontale

? 

*/