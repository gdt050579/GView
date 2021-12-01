#include <AppCUI/include/AppCUI.hpp>

using namespace AppCUI::Controls;
using namespace AppCUI::Utils;
using namespace AppCUI::Graphics;

#ifdef CORE_EXPORTABLE
#    ifdef BUILD_FOR_WINDOWS
#        define CORE_EXPORT __declspec(dllexport)
#    else
#        define CORE_EXPORT
#    endif
#else
#    define CORE_EXPORT
#endif

#ifdef BUILD_FOR_WINDOWS
#    define PLUGIN_EXPORT __declspec(dllexport)
#else
#    define PLUGIN_EXPORT
#endif

namespace GView
{
struct CORE_EXPORT TypeInterface
{
    virtual std::string_view GetTypeName() = 0;
    virtual ~TypeInterface(){};

    template <typename T>
    Reference<T> To()
    {
        return static_cast<T*>(this);
    }
};
namespace Utils
{
    constexpr unsigned long long INVALID_OFFSET = 0xFFFFFFFFFFFFFFFFULL;
    constexpr int INVALID_SELECTION_INDEX       = -1;

    class CORE_EXPORT ErrorList
    {
        void* data;

      public:
        ErrorList();
        ~ErrorList();

        void Clear();
        bool AddError(const char* format, ...);
        bool AddWarning(const char* format, ...);
        bool Empty() const;

        unsigned int GetErrorsCount() const;
        unsigned int GetWarningsCount() const;

        std::string_view GetError(unsigned int index) const;
        std::string_view GetWarning(unsigned int index) const;

        void PopulateListView(AppCUI::Utils::Reference<AppCUI::Controls::ListView> listView) const;
    };
    class CORE_EXPORT FileCache
    {
        AppCUI::OS::IFile* fileObj;
        unsigned long long fileSize, start, end, currentPos;
        unsigned char* cache;
        unsigned int cacheSize;

        bool CopyObject(void* buffer, unsigned long long offset, unsigned int requestedSize);

      public:
        FileCache();
        ~FileCache();

        bool Init(std::unique_ptr<AppCUI::OS::IFile> file, unsigned int cacheSize);
        BufferView Get(unsigned long long offset, unsigned int requestedSize);

        Buffer CopyToBuffer(unsigned long long offset, unsigned int requestedSize, bool failIfRequestedSizeCanNotBeRead = true);
        inline unsigned char GetFromCache(unsigned long long offset, unsigned char defaultValue = 0) const
        {
            if ((offset >= start) && (offset < end))
                return cache[offset - start];
            return defaultValue;
        }
        inline BufferView Get(unsigned int requestedSize)
        {
            return Get(currentPos, requestedSize);
        }

        inline unsigned long long GetSize() const
        {
            return fileSize;
        }
        inline unsigned long long GetCurrentPos() const
        {
            return currentPos;
        }
        inline void SetCurrentPos(unsigned long long value)
        {
            currentPos = value;
        }

        template <typename T>
        inline bool Copy(unsigned long long offset, T& object)
        {
            return CopyObject(&object, offset, sizeof(T));
        }
    };
} // namespace Utils
struct CORE_EXPORT Object
{
    Utils::FileCache cache;
    TypeInterface* type;
    AppCUI::Utils::UnicodeStringBuilder name;

    Object() : type(nullptr)
    {
    }
};

namespace View
{
    typedef unsigned char MethodID;
    struct CORE_EXPORT ViewControl : public AppCUI::Controls::UserControl
    {
        virtual bool GoTo(unsigned long long offset)                                                                       = 0;
        virtual bool Select(unsigned long long offset, unsigned long long size)                                            = 0;
        virtual std::string_view GetName()                                                                                 = 0;
        virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, unsigned int width, unsigned int height) = 0;

        ViewControl() : UserControl("d:c")
        {
        }
    };
    namespace BufferViewer
    {
        struct CORE_EXPORT OffsetTranslateInterface
        {
            virtual uint64_t TranslateToFileOffset(uint64_t value, MethodID methodID) = 0;
        };

        struct CORE_EXPORT Settings
        {
            void* data;

            Settings();
            void AddZone(unsigned long long start, unsigned long long size, ColorPair col, std::string_view name);
            void AddBookmark(unsigned char bookmarkID, unsigned long long fileOffset);
            void AddOffsetTranslationMethod(std::string_view name, MethodID methodID);
            void SetOffsetTranslationCallback(OffsetTranslateInterface* interface);
        };
    }; // namespace BufferViewer
    struct CORE_EXPORT WindowInterface
    {
        virtual Reference<Object> GetObject()                                                     = 0;
        virtual bool AddPanel(Pointer<TabPage> page, bool vertical)                               = 0;
        virtual bool CreateViewer(const std::string_view& name, BufferViewer::Settings& settings) = 0;
        virtual Reference<ViewControl> GetCurrentView()                                           = 0;
    };
}; // namespace View
namespace App
{
    bool CORE_EXPORT Init();
    void CORE_EXPORT Run();
    bool CORE_EXPORT ResetConfiguration();
    void CORE_EXPORT OpenFile(const char*);
}; // namespace App
}; // namespace GView
