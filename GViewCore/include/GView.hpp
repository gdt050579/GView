#pragma once

#include <AppCUI/include/AppCUI.hpp>

using namespace AppCUI::Controls;
using namespace AppCUI::Utils;
using namespace AppCUI::Graphics;
using namespace AppCUI;

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
    constexpr uint64 INVALID_OFFSET       = 0xFFFFFFFFFFFFFFFFULL;
    constexpr int INVALID_SELECTION_INDEX = -1;

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

        uint32 GetErrorsCount() const;
        uint32 GetWarningsCount() const;

        std::string_view GetError(uint32 index) const;
        std::string_view GetWarning(uint32 index) const;

        void PopulateListView(AppCUI::Utils::Reference<AppCUI::Controls::ListView> listView) const;
    };
    class CORE_EXPORT FileCache
    {
        AppCUI::OS::IFile* fileObj;
        uint64 fileSize, start, end, currentPos;
        uint8* cache;
        uint32 cacheSize;

        bool CopyObject(void* buffer, uint64 offset, uint32 requestedSize);

      public:
        FileCache();
        ~FileCache();

        bool Init(std::unique_ptr<AppCUI::OS::IFile> file, uint32 cacheSize);
        BufferView Get(uint64 offset, uint32 requestedSize);

        Buffer CopyToBuffer(uint64 offset, uint32 requestedSize, bool failIfRequestedSizeCanNotBeRead = true);
        inline uint8 GetFromCache(uint64 offset, uint8 defaultValue = 0) const
        {
            if ((offset >= start) && (offset < end))
                return cache[offset - start];
            return defaultValue;
        }
        inline BufferView Get(uint32 requestedSize)
        {
            return Get(currentPos, requestedSize);
        }

        inline uint64 GetSize() const
        {
            return fileSize;
        }
        inline uint64 GetCurrentPos() const
        {
            return currentPos;
        }
        inline void SetCurrentPos(uint64 value)
        {
            currentPos = value;
        }

        template <typename T>
        inline bool Copy(uint64 offset, T& object)
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
    typedef uint8 MethodID;
    struct CORE_EXPORT ViewControl : public AppCUI::Controls::UserControl, public AppCUI::Utils::PropertiesInterface
    {
        virtual bool GoTo(uint64 offset)                                                                       = 0;
        virtual bool Select(uint64 offset, uint64 size)                                                        = 0;
        virtual std::string_view GetName()                                                                     = 0;
        virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) = 0;

        ViewControl() : UserControl("d:c")
        {
        }
    };
    namespace BufferViewer
    {
        struct BufferColor
        {
            uint64_t start;
            uint64_t end;
            ColorPair color;
            constexpr inline void Reset()
            {
                start = end = GView::Utils::INVALID_OFFSET;
            }
            constexpr inline bool IsValue() const
            {
                return start != GView::Utils::INVALID_OFFSET;
            }
            constexpr inline bool Empty() const
            {
                return start == GView::Utils::INVALID_OFFSET;
            }
        };
        struct CORE_EXPORT PositionToColorInterface
        {
            virtual bool GetColorForBuffer(uint64_t offset, BufferView buf, BufferColor& result) = 0;
        };
        struct CORE_EXPORT OffsetTranslateInterface
        {
            virtual uint64_t TranslateToFileOffset(uint64_t value, uint32 fromTranslationIndex) = 0;
            virtual uint64_t TranslateFromFileOffset(uint64_t value, uint32 toTranslationIndex) = 0;
        };

        struct CORE_EXPORT Settings
        {
            void* data;

            Settings();
            void AddZone(uint64 start, uint64 size, ColorPair col, std::string_view name);
            void AddBookmark(uint8 bookmarkID, uint64 fileOffset);
            void SetOffsetTranslationList(std::initializer_list<std::string_view> list, Reference<OffsetTranslateInterface> cbk);
            void SetPositionToColorCallback(Reference<PositionToColorInterface> cbk);
            void SetEntryPointOffset(uint64_t offset);
        };
    }; // namespace BufferViewer

    namespace GridViewer
    {
        struct CORE_EXPORT Settings
        {
            void* data;

            Settings();
            void InitGrid();
            void UpdateGrid();
        };
    } // namespace GridViewer

    struct CORE_EXPORT WindowInterface
    {
        virtual Reference<Object> GetObject()                                                     = 0;
        virtual bool AddPanel(Pointer<TabPage> page, bool vertical)                               = 0;
        virtual bool CreateViewer(const std::string_view& name, BufferViewer::Settings& settings) = 0;
        virtual bool CreateViewer(const std::string_view& name, GridViewer::Settings& settings)   = 0;
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
