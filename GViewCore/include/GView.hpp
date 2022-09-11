#pragma once

// Version MUST be in the following format <Major>.<Minor>.<Patch>
#define GVIEW_VERSION "0.205.0"

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
class CORE_EXPORT Object;
struct CORE_EXPORT TypeInterface
{
    Object* obj;

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
    class CORE_EXPORT DataCache
    {
        AppCUI::OS::DataObject* fileObj;
        uint64 fileSize, start, end, currentPos;
        uint8* cache;
        uint32 cacheSize;

        bool CopyObject(void* buffer, uint64 offset, uint32 requestedSize);

      public:
        DataCache();
        DataCache(DataCache&& obj);
        ~DataCache();

        bool Init(std::unique_ptr<AppCUI::OS::DataObject> file, uint32 cacheSize);
        BufferView Get(uint64 offset, uint32 requestedSize, bool failIfRequestedSizeCanNotBeRead);
        inline BufferView GetEntireFile()
        {
            return fileSize < 0xFFFFFFFF ? Get(0, (uint32) fileSize, true) : BufferView();
        }

        Buffer CopyToBuffer(uint64 offset, uint32 requestedSize, bool failIfRequestedSizeCanNotBeRead = true);
        inline Buffer CopyEntireFile(bool failIfRequestedSizeCanNotBeRead = true)
        {
            return CopyToBuffer(0, (uint32) fileSize, failIfRequestedSizeCanNotBeRead);
        }
        inline uint8 GetFromCache(uint64 offset, uint8 defaultValue = 0) const
        {
            if ((offset >= start) && (offset < end))
                return cache[offset - start];
            return defaultValue;
        }
        inline uint32 GetCacheSize() const
        {
            return cacheSize;
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

        bool WriteTo(Reference<AppCUI::OS::DataObject> output, uint64 offset, uint32 size);
    };

    enum class DemangleKind : uint8
    {
        Auto,
        Microsoft,
        Itanium,
        Rust,
    };
    CORE_EXPORT bool Demangle(std::string_view input, String& output, DemangleKind format = DemangleKind::Auto);

} // namespace Utils

namespace Hashes
{
    class CORE_EXPORT Adler32
    {
      private:
        uint16 a;
        uint16 b;

        bool init;

      public:
        bool Init();
        bool Update(const unsigned char* input, uint32 length);
        bool Update(const Buffer& buffer);
        bool Update(const BufferView& buffer);
        bool Final(uint32& hash);
        static std::string_view GetName();
        const std::string_view GetHexValue();

      public:
        inline static const uint32 ResultBytesLength = sizeof(a) + sizeof(b);

      private:
        char hexDigest[ResultBytesLength * 2];
    };

    class CORE_EXPORT CRC16
    {
      private:
        uint32 value;
        bool init;

      public:
        bool Init();
        bool Update(const unsigned char* input, uint32 length);
        bool Update(const Buffer& buffer);
        bool Update(const BufferView& buffer);
        bool Final(uint16& hash);
        static std::string_view GetName();
        const std::string_view GetHexValue();

      public:
        inline static const uint32 ResultBytesLength = sizeof(value);

      private:
        char hexDigest[ResultBytesLength * 2];
    };

    enum class CRC32Type : uint32
    {
        JAMCRC   = 0xFFFFFFFF,
        JAMCRC_0 = 0x00000000
    };

    class CORE_EXPORT CRC32
    {
      private:
        uint32 value;
        CRC32Type type;

        bool init;

      public:
        bool Init(CRC32Type type);
        bool Update(const unsigned char* input, uint32 length);
        bool Update(const Buffer& buffer);
        bool Update(const BufferView& buffer);
        bool Final(uint32& hash);
        static std::string_view GetName(CRC32Type type);
        const std::string_view GetHexValue();

      public:
        inline static const uint32 ResultBytesLength = sizeof(value);

      private:
        char hexDigest[ResultBytesLength * 2];
    };

    enum class CRC64Type : uint64
    {
        WE       = 0xFFFFFFFFFFFFFFFF,
        ECMA_182 = 0x0000000000000000
    };

    class CORE_EXPORT CRC64
    {
      private:
        uint64 value;
        CRC64Type type;

        bool init;

      private:
        bool Final();

      public:
        bool Init(CRC64Type type);
        bool Update(const unsigned char* input, uint32 length);
        bool Update(const Buffer& buffer);
        bool Update(const BufferView& buffer);
        bool Final(uint64& hash);
        static std::string_view GetName(CRC64Type type);
        const std::string_view GetHexValue();

      public:
        inline static const uint32 ResultBytesLength = sizeof(value);

      private:
        char hexDigest[ResultBytesLength * 2];
    };

    enum class OpenSSLHashKind : uint8
    {
        Md5,
        Blake2s256,
        Blake2b512,
        Sha1,
        Sha224,
        Sha256,
        Sha384,
        Sha512,
        Sha512_224,
        Sha512_256,
        Sha3_224,
        Sha3_256,
        Sha3_384,
        Sha3_512,
        Shake128,
        Shake256
    };

    class CORE_EXPORT OpenSSLHash
    {
      public:
        OpenSSLHash(OpenSSLHashKind kind);
        ~OpenSSLHash();

        bool Update(const void* input, uint32 length);
        bool Final();
        std::string_view GetHexValue();
        const uint8* Get() const;
        uint32 GetSize() const;

      private:
        void* handle;
        uint8 hash[64];
        uint32 size;

      private:
        char hexDigest[(sizeof(hash) / sizeof(hash[0])) * 2];
    };
} // namespace Hashes

namespace DigitalSignature
{
    enum class ASN1TYPE
    {
        EOC               = 0,
        BOOLEAN           = 1,
        INTEGER           = 2,
        BIT_STRING        = 3,
        OCTET_STRING      = 4,
        NULL_ASN          = 5,
        OBJECT            = 6,
        OBJECT_DESCRIPTOR = 7,
        EXTERNAL          = 8,
        REAL              = 9,
        ENUMERATED        = 10,
        UTF8STRING        = 12,
        SEQUENCE          = 16,
        SET               = 17,
        NUMERICSTRING     = 18,
        PRINTABLESTRING   = 19,
        T61STRING         = 20,
        TELETEXSTRING     = 20,
        VIDEOTEXSTRING    = 21,
        IA5STRING         = 22,
        UTCTIME           = 23,
        GENERALIZEDTIME   = 24,
        GRAPHICSTRING     = 25,
        ISO64STRING       = 26,
        VISIBLESTRING     = 26,
        GENERALSTRING     = 27,
        UNIVERSALSTRING   = 28,
        BMPSTRING         = 30
    };

    struct CORE_EXPORT Certificate
    {
        int32 version;
        String serialNumber;
        String signatureAlgorithm;
        String publicKeyAlgorithm;
        String validityNotBefore;
        String validityNotAfter;
        String issuer;
        String subject;
        int32 verify;
        String errorVerify;

        int32 signerVerify; //  compares the certificate cert against the signer identifier si
        String errorSignerVerify;
    };

    constexpr auto MAX_SIZE_IN_CONTAINER = 32U;

    struct CORE_EXPORT SignerAttributes
    {
        String name;
        ASN1TYPE types[MAX_SIZE_IN_CONTAINER]; // usually one value unless (attribute.contentType == "1.2.840.113635.100.9.2") //
                                               // V_ASN1_SEQUENCE
        String contentType;
        String contentTypeData;
        int32 count;

        String CDHashes[MAX_SIZE_IN_CONTAINER]; // optional -> (attribute.contentType == "1.2.840.113635.100.9.2") // V_ASN1_SEQUENCE
    };

    struct CORE_EXPORT Signer
    {
        int32 count;
        SignerAttributes attributes[MAX_SIZE_IN_CONTAINER];
        uint32 attributesCount;
    };

    struct CORE_EXPORT Signature
    {
        int32 isDetached;
        String sn;
        Buffer snContent;

        Certificate certificates[MAX_SIZE_IN_CONTAINER];
        uint32 certificatesCount = 0;
        Signer signers[MAX_SIZE_IN_CONTAINER];
        uint32 signersCount = 0;

        String errorMessage;
        bool error = true;
    };

    CORE_EXPORT bool CMSToHumanReadable(const Buffer& buffer, String& ouput);
    CORE_EXPORT bool CMSToPEMCerts(const Buffer& buffer, String output[32], uint32& count);
    CORE_EXPORT bool CMSToStructure(const Buffer& buffer, Signature& output);
} // namespace DigitalSignature

namespace Golang
{
    constexpr auto ELF_GO_BUILD_ID_TAG = 4U;
    constexpr auto GNU_BUILD_ID_TAG    = 3U;

    constexpr auto ELF_GO_NOTE  = std::string_view("Go\x00\x00", 4);
    constexpr auto ELF_GNU_NOTE = std::string_view("GNU\x00", 4);

    // version of the pclntab (Program Counter Line Table) -: https://go.dev/src/debug/gosym/pclntab.go
    enum class PclntabVersion : int32
    {
        Unknown = -1,
        _11     = 0,
        _12     = 1,
        _116    = 2,
        _118    = 3,
    };

    enum class GoMagic : uint32 // https://go.dev/src/debug/gosym/pclntab.go
    {
        _12  = 0xfffffffb,
        _116 = 0xfffffffa,
        _118 = 0xfffffff0,
    };

    struct CORE_EXPORT GoFunctionHeader
    {
        GoMagic magic;
        uint16 padding;
        uint8 instructionSizeQuantum; // (1 for x86, 4 for ARM)
        uint8 sizeOfUintptr;          // in bytes
    };

    enum class Architecture : uint8
    {
        Unknown = 0,
        x86     = 1,
        x64     = 2
    };

    struct CORE_EXPORT FstEntry32
    {
        uint32 pc;
        uint32 functionOffset;
    };

    struct FstEntry64
    {
        uint64 pc;
        uint32 functionOffset;
    };

    struct CORE_EXPORT Func32
    {
        uint32 entry;    // start pc
        int32 name;      // name (offset to C string)
        int32 args;      // size of arguments passed to function
        int32 frame;     // size of function frame, including saved caller PC
        int32 pcsp;      // pcsp table (offset to pcvalue table)
        int32 pcfile;    // pcfile table (offset to pcvalue table)
        int32 pcln;      // pcln table (offset to pcvalue table)
        int32 nfuncdata; // number of entries in funcdata list
        int32 npcdata;   // number of entries in pcdata list
    };

    struct CORE_EXPORT Func64
    {
        uint64 entry;    // start pc
        int32 name;      // name (offset to C string)
        int32 args;      // size of arguments passed to function
        int32 frame;     // size of function frame, including saved caller PC
        int32 pcsp;      // pcsp table (offset to pcvalue table)
        int32 pcfile;    // pcfile table (offset to pcvalue table)
        int32 pcln;      // pcln table (offset to pcvalue table)
        int32 nfuncdata; // number of entries in funcdata list
        int32 npcdata;   // number of entries in pcdata list
    };

    struct CORE_EXPORT Function
    {
        char* name{ nullptr };
        Func64 func;
    };

    struct CORE_EXPORT GoPclntab112
    {
      private:
        void* context{ nullptr };
        void Reset();

      public:
        GoPclntab112();
        ~GoPclntab112();
        bool Process(const Buffer& buffer, Architecture arch);
        GoFunctionHeader* GetHeader() const;
        uint64 GetFilesCount() const;
        bool GetFile(uint64 index, std::string_view& file) const;
        uint64 GetFunctionsCount() const;
        bool GetFunction(uint64 index, Function& func) const;
        uint64 GetEntriesCount() const;
    };

    CORE_EXPORT const char* GetNameForGoMagic(GoMagic magic);
} // namespace Golang

namespace Pyc
{

}

namespace Compression
{
    namespace LZXPRESS
    {
        namespace Huffman
        {
            CORE_EXPORT bool Decompress(const BufferView& compressed, Buffer& uncompressed);
        }
    } // namespace LZXPRESS
} // namespace Compression

/*
 * Object can be:
 *   - a file
 *   - a folder
 *   - a process
 *   - a memory buffer
 */
class CORE_EXPORT Object
{
  public:
    enum class Type : uint32
    {
        File,
        Folder,
        MemoryBuffer,
        Process
    };

  private:
    Utils::DataCache cache;
    TypeInterface* contentType;
    AppCUI::Utils::UnicodeStringBuilder name;
    AppCUI::Utils::UnicodeStringBuilder filePath;
    uint32 PID;
    Type objectType;

  public:
    Object(Type objType, Utils::DataCache&& dataCache, TypeInterface* contType, ConstString objName, ConstString objFilePath, uint32 pid)
        : cache(std::move(dataCache)), contentType(contType), name(objName), filePath(objFilePath), PID(pid), objectType(objType)
    {
        if (contentType)
            contentType->obj = this;
    }
    inline Utils::DataCache& GetData()
    {
        return cache;
    }
    inline u16string_view GetName() const
    {
        return name.ToStringView();
    }
    inline u16string_view GetPath() const
    {
        return filePath.ToStringView();
    }
    inline Reference<TypeInterface> GetContentType() const
    {
        return contentType;
    }
    template <typename T>
    inline Reference<T> GetContentType() const
    {
        return (T*) contentType;
    }
    inline uint32 GetPID() const
    {
        return PID;
    }
    inline Type GetObjectType() const
    {
        return objectType;
    }
};

namespace View
{
    typedef uint8 MethodID;

    struct CORE_EXPORT ViewControl : public AppCUI::Controls::UserControl, public AppCUI::Utils::PropertiesInterface
    {
      protected:
        const AppCUI::Application::Config& Cfg;

      public:
        virtual bool GoTo(uint64 offset)                                                                       = 0;
        virtual bool Select(uint64 offset, uint64 size)                                                        = 0;
        virtual bool ShowGoToDialog()                                                                          = 0;
        virtual bool ShowFindDialog()                                                                          = 0;
        virtual bool ShowCopyDialog()                                                                          = 0;
        virtual std::string_view GetName()                                                                     = 0;
        virtual void PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height) = 0;

        int WriteCursorInfo(AppCUI::Graphics::Renderer& renderer, int x, int y, int width, std::string_view key, std::string_view value);
        int WriteCursorInfo(AppCUI::Graphics::Renderer& renderer, int x, int y, int width, std::string_view key, std::u16string_view value);
        void WriteCusorInfoLine(AppCUI::Graphics::Renderer& renderer, int x, int y, std::string_view key, const ConstString& value);

        ViewControl(UserControlFlags flags = UserControlFlags::None) : UserControl("d:c", flags), Cfg(this->GetConfig())
        {
        }
    };
    namespace BufferViewer
    {
        struct BufferColor
        {
            uint64 start;
            uint64 end;
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
            virtual bool GetColorForBuffer(uint64 offset, BufferView buf, BufferColor& result) = 0;
        };
        struct CORE_EXPORT OffsetTranslateInterface
        {
            virtual uint64_t TranslateToFileOffset(uint64 value, uint32 fromTranslationIndex) = 0;
            virtual uint64_t TranslateFromFileOffset(uint64 value, uint32 toTranslationIndex) = 0;
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

    namespace ImageViewer
    {
        struct CORE_EXPORT LoadImageInterface
        {
            virtual bool LoadImageToObject(Image& img, uint32 index) = 0;
        };
        struct CORE_EXPORT Settings
        {
            void* data;

            Settings();
            void SetLoadImageCallback(Reference<LoadImageInterface> cbk);
            void AddImage(uint64 offset, uint64 size);
        };
    }; // namespace ImageViewer

    namespace ContainerViewer
    {
        struct CORE_EXPORT EnumerateInterface
        {
            virtual bool BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent) = 0;
            virtual bool PopulateItem(AppCUI::Controls::TreeViewItem item)                               = 0;
        };
        struct CORE_EXPORT OpenItemInterface
        {
            virtual void OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item) = 0;
        };
        struct CORE_EXPORT Settings
        {
            void* data;

            Settings();
            bool SetIcon(string_view imageStringFormat16x16);
            bool SetPathSeparator(char16 separator);
            bool AddProperty(string_view name, const ConstString& value, ListViewItem::Type itemType = ListViewItem::Type::Normal);
            void SetColumns(std::initializer_list<ConstString> columns);
            void SetEnumerateCallback(Reference<EnumerateInterface> callback);
            void SetOpenItemCallback(Reference<OpenItemInterface> callback);
        };
    }; // namespace ContainerViewer

    namespace TextViewer
    {
        enum class WrapMethod : uint8
        {
            None       = 0,
            LeftMargin = 1,
            Padding    = 2,
            Bullets    = 3,
        };
        struct CORE_EXPORT Settings
        {
            void* data;

            Settings();
            void SetWrapMethod(WrapMethod method);
            void SetTabSize(uint32 tabSize);
            void ShowTabCharacter(bool show);
            void HightlightCurrentLine(bool highlight);
        };
    }; // namespace TextViewer

    namespace LexicalViewer
    {
        enum class SpaceType : uint8
        {
            All          = 0,
            NewLine      = 1,
            Space        = 2,
            Tabs         = 3,
            SpaceAndTabs = 4,
        };
        enum class StringFormat : uint32
        {
            SingleQuotes                = 0x00000001, // "..."
            DoubleQuotes                = 0x00000002, // '...'
            TripleQuotes                = 0x00000004, // '''...''' or """..."""
            AllowEscapeSequences        = 0x00000008, // "...\n..."
            MultiLine                   = 0x00000010, // string accross mulitple lines
            LineContinuityWithBackslash = 0x00000020, // "   \<newline>   "
            All                         = 0xFFFFFFFF, // all possible forms of strings
        };
        enum class NumberFormat : uint32
        {
            DecimalOnly           = 0,
            HexFormat0x           = 0x00000001,
            BinFormat0b           = 0x00000002,
            FloatingPoint         = 0x00000004,
            AllowSignBeforeNumber = 0x00000008,
            AllowUnderline        = 0x00000010,
            AllowSingleQuote      = 0x00000020,
            ExponentFormat        = 0x00000040,
            All                   = 0xFFFFFFFF, // all possible forms of numbers
        };
        class CORE_EXPORT TextParser
        {
            const char16* text;
            uint32 size;

          public:
            TextParser(const char16* text, uint32 size);
            TextParser(u16string_view text);

            inline uint32 Len() const
            {
                return size;
            }
            inline char16 operator[](uint32 index) const
            {
                if (index < size)
                    return text[index];
                return 0;
            }
            inline u16string_view GetSubString(uint32 start, uint32 end) const
            {
                if ((start < end) && (end <= size))
                    return u16string_view{ text + start, (size_t) (end - start) };
                return u16string_view();
            }
            uint32 ParseUntillEndOfLine(uint32 index) const;
            uint32 ParseUntillStartOfNextLine(uint32 index) const;
            uint32 Parse(uint32 index, bool (*validate)(char16 character)) const;
            uint32 ParseBackwards(uint32 index, bool (*validate)(char16 character)) const;
            uint32 ParseSameGroupID(uint32 index, uint32 (*charToID)(char16 character)) const;
            uint32 ParseSpace(uint32 index, SpaceType type = SpaceType::SpaceAndTabs) const;
            uint32 ParseString(uint32 index, StringFormat format = StringFormat::All) const;
            uint32 ParseNumber(uint32 index, NumberFormat format = NumberFormat::All) const;
            uint32 ParseUntillText(uint32 index, string_view textToFind, bool ignoreCase) const;
            uint32 ParseUntilNextCharacterAfterText(uint32 index, string_view textToFind, bool ignoreCase) const;
            uint64 ComputeHash64(uint32 start, uint32 end, bool ignoreCase) const;
            uint32 ComputeHash32(uint32 start, uint32 end, bool ignoreCase) const;
            static uint32 ComputeHash32(u16string_view txt, bool ignoreCase);
            static uint64 ComputeHash64(u16string_view txt, bool ignoreCase);
        };
        class CORE_EXPORT TextEditor
        {
            bool Grow(size_t size);

          protected:
            char16* text;
            uint32 size;
            uint32 allocated;

            TextEditor();

          public:
            bool Insert(uint32 offset, std::string_view text);
            bool Insert(uint32 offset, std::u16string_view text);
            bool InsertChar(uint32 offset, char16 ch);
            std::optional<uint32> Find(uint32 startOffset, std::string_view textToSearch, bool ignoreCase = false);
            bool Replace(uint32 offset, uint32 size, std::string_view text);
            bool Replace(uint32 offset, uint32 size, std::u16string_view text);
            bool ReplaceAll(std::string_view textToSearch, std::string_view textToReplaceWith, bool ignoreCase = false);
            bool DeleteChar(uint32 offset);
            bool Delete(uint32 offset, uint32 charactersCount);
            bool Add(std::string_view text);
            bool Add(std::u16string_view text);
            bool Set(std::string_view text);
            bool Set(std::u16string_view text);
            bool Resize(uint32 charactersCount, char16 fillChar = ' ');
            bool Reserve(uint32 charactersCount);

            char16& operator[](uint32 index);

            inline uint32 Len() const
            {
                return size;
            }
            inline operator u16string_view() const
            {
                return { text, (size_t) size };
            }
        };
        enum class TokenDataType : uint8
        {
            None,
            String,
            Number,
            MetaInformation,
            Boolean
        };
        enum class TokenAlignament : uint32
        {
            None            = 0,
            AddSpaceBefore  = 0x00000001,    // adds a space on left (except when current token is already at left-most position)
            AddSpaceAfter   = 0x00000002,    // adds a space on right of the current token
            NewLineAfter    = 0x00000004,    // adds a new line after the current token
            NewLineBefore   = 0x00000008,    // makes sure that there is a new (empty) line before previous token and current one
            StartsOnNewLine = 0x00000010,    // makes sure that current token starts on new line. If already on new line, nothing happens.
                                             // otherwise adds a new line.
            AfterPreviousToken = 0x00000020, // make sure that there any space or new line (within the block) between current token
                                             // and previous token is removed. Both tokens are at on the same line.
            IncrementIndentBeforePaint = 0x00000040, // increments the indent of the current line (before painting the token)
            DecrementIndentBeforePaint = 0x00000080, // decrement the indent of the current line (before painting the token)
            ClearIndentBeforePaint     = 0x00000100, // resets current indent to 0 (before painting the token)
            IncrementIndentAfterPaint  = 0x00000200, // increments the indent of the current line (after painting the token)
            DecrementIndentAfterPaint  = 0x00000400, // decrement the indent of the current line (after painting the token)
            ClearIndentAfterPaint      = 0x00000800, // resets current indent to 0 (after painting the token)

            SameColumn     = 0x00001000, // make sure that first token with this flag from each line from a block has the same X-offste
            WrapToNextLine = 0x00002000, // if the "X" coordonate of a token is after a specific with, move to the next
                                         // line and reset the "X" coordonate acording to the block rules.

        };
        enum class TokenColor : uint8
        {
            Comment,
            Number,
            String,
            Operator,
            Keyword,
            Keyword2,
            Constant,
            Word,
            Preprocesor,
            Datatype,
            Error,
        };
        enum class BlockAlignament : uint8
        {
            ParentBlock,
            ParentBlockWithIndent,
            CurrentToken,
            CurrentTokenWithIndent,
        };
        enum class BlockFlags : uint16
        {
            None           = 0,
            EndMarker      = 0x0001,
            ManualCollapse = 0x0002,
        };
        class CORE_EXPORT Token;
        class CORE_EXPORT Block
        {
            void* data;
            uint32 index;

          public:
            Block(void* _data, uint32 _idx) : data(_data), index(_idx)
            {
            }
            Block() : data(nullptr), index(INVALID_INDEX)
            {
            }
            inline bool IsValid() const
            {
                return data != nullptr;
            }
            inline uint32 GetIndex() const
            {
                return index;
            }
            Token GetStartToken() const;
            Token GetEndToken() const;

            bool SetFoldMessage(std::string_view message);

            constexpr static uint32 INVALID_INDEX = 0xFFFFFFFF;
        };
        class CORE_EXPORT Token
        {
            void* data;
            uint32 index;

          public:
            Token(void* _data, uint32 _idx) : data(_data), index(_idx)
            {
            }
            Token() : data(nullptr), index(INVALID_INDEX)
            {
            }
            inline bool IsValid() const
            {
                return data != nullptr;
            }
            inline uint32 GetIndex() const
            {
                return index;
            }

            uint32 GetTypeID(uint32 errorValue) const;
            TokenAlignament GetAlignament() const;
            TokenDataType GetDataType() const;
            bool SetAlignament(TokenAlignament align);
            bool UpdateAlignament(TokenAlignament flagsToAdd, TokenAlignament flagsToRemove = TokenAlignament::None);
            bool SetTokenColor(TokenColor col);
            bool SetBlock(Block block);
            bool SetBlock(uint32 blockIndex);
            bool DisableSimilartyHighlight();
            bool SetText(const ConstString& text);
            bool SetError(const ConstString& error);
            bool Delete();

            std::optional<uint32> GetTokenStartOffset() const;
            std::optional<uint32> GetTokenEndOffset() const;

            Token Next() const;
            Token Precedent() const;

            u16string_view GetText() const;
            Block GetBlock() const;

            constexpr static uint32 INVALID_INDEX = 0xFFFFFFFF;
        };
        class CORE_EXPORT TokensList
        {
          protected:
            void* data;
            uint32 lastTokenID;

            TokensList() : data(nullptr), lastTokenID(0xFFFFFFFF)
            {
            }

          public:
            void ResetLastTokenID(uint32 value)
            {
                lastTokenID = value;
            }
            Token operator[](uint32 index) const;
            Token GetLastToken() const;
            uint32 GetLastTokenID() const
            {
                return lastTokenID;
            }
            uint32 Len() const;
            Token Add(uint32 typeID, uint32 start, uint32 end, TokenColor color);
            Token Add(uint32 typeID, uint32 start, uint32 end, TokenColor color, TokenDataType dataType);
            Token Add(uint32 typeID, uint32 start, uint32 end, TokenColor color, TokenAlignament align);
            Token Add(uint32 typeID, uint32 start, uint32 end, TokenColor color, TokenDataType dataType, TokenAlignament align);
            Token Add(
                  uint32 typeID,
                  uint32 start,
                  uint32 end,
                  TokenColor color,
                  TokenDataType dataType,
                  TokenAlignament align,
                  bool disableSimilartySearch);
            // Token AddErrorToken(uint32 start, uint32 end, ConstString error);
        };
        class CORE_EXPORT BlocksList
        {
          protected:
            void* data;

            BlocksList() : data(nullptr)
            {
            }

          public:
            uint32 Len() const;
            Block operator[](uint32 index) const;
            Block Add(uint32 start, uint32 end, BlockAlignament align, BlockFlags flags = BlockFlags::None);
            Block Add(Token start, Token end, BlockAlignament align, BlockFlags flags = BlockFlags::None);
        };
        struct SyntaxManager
        {
            const TextParser& text;
            TokensList& tokens;
            BlocksList& blocks;
            SyntaxManager(const TextParser& _text, TokensList& _tokens, BlocksList& _blocks) : text(_text), tokens(_tokens), blocks(_blocks)
            {
            }
        };
        class CORE_EXPORT TokenIndexStack
        {
            constexpr static uint32 LOCAL_SIZE = 8;
            uint32 count, allocated;
            uint32* stack;
            uint32 local[LOCAL_SIZE];

          public:
            TokenIndexStack();
            ~TokenIndexStack();
            bool Push(uint32 index);
            uint32 Pop(uint32 errorValue = Token::INVALID_INDEX);
            inline bool Empty() const
            {
                return count == 0;
            }
        };
        struct CORE_EXPORT ParseInterface
        {
            virtual void GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str) = 0;
            virtual void PreprocessText(TextEditor& editor)                                    = 0;
            virtual void AnalyzeText(SyntaxManager& syntax)                                    = 0;
        };
        struct PluginData
        {
            TextEditor& editor;
            TokensList& tokens;
            BlocksList& blocks;
            uint32 currentTokenIndex;
            uint32 startIndex;
            uint32 endIndex;
            PluginData(TextEditor& _editor, TokensList& _tokens, BlocksList& _blocks)
                : editor(_editor), tokens(_tokens), blocks(_blocks), currentTokenIndex(0), startIndex(0), endIndex(0)
            {
            }
        };
        enum class PluginAfterActionRequest
        {
            None,
            Refresh,
            Rescan,
        };
        struct CORE_EXPORT Plugin
        {
            virtual std::string_view GetName()                         = 0;
            virtual std::string_view GetDescription()                  = 0;
            virtual bool CanBeAppliedOn(const PluginData& data)        = 0;
            virtual PluginAfterActionRequest Execute(PluginData& data) = 0;
        };
        struct CORE_EXPORT Settings
        {
            void* data;

            Settings();
            void SetParser(Reference<ParseInterface> parser);
            void AddPlugin(Reference<Plugin> plugin);
            void SetCaseSensitivity(bool ignoreCase);
            void SetMaxWidth(uint32 width);
        };
    }; // namespace LexicalViewer

    namespace GridViewer
    {
        struct CORE_EXPORT Settings
        {
            void* data;

            Settings();

            void SetSeparator(char separator[2]);
        };
    }; // namespace GridViewer

    namespace DissasmViewer // StructureViewer
    {
        using TypeID = uint32;

        enum class DissasemblyLanguage : uint32
        {
            Default,
            x86,
            x64,
            JavaByteCode,
            IL,
            Count
        };

        enum class VariableType : uint32
        {
            UInt8,
            UInt16,
            UInt32,
            UInt64,
            Int8,
            Int16,
            Int32,
            Int64,
            AsciiZ,
            Utf16Z,
            Utf32Z
        };

        constexpr TypeID TypeIDError = static_cast<TypeID>(-1);

        struct CORE_EXPORT Settings
        {
            void* data;

            void SetDefaultDisassemblyLanguage(DissasemblyLanguage lang);
            void AddDisassemblyZone(uint64 start, uint64 size, DissasemblyLanguage lang = DissasemblyLanguage::Default);

            void AddMemoryMapping(uint64 address, std::string_view name);
            
            /**
             * Add a new data type with its definition. Default data types: UInt8-64,Int8-64, float,double, asciiZ, Unicode16Z,Unicode32Z
             *
             *
             * @param[in] name Name of the new type
             * @param[in] definition Multiple statements in the form DataType variableName followed by semicolon. Example: name="Point",
             * definition="UInt32 x;UInt32 y;"
             * @returns The id of the new data type generated or TypeIDError if there are errors.
             */
            TypeID AddType(std::string_view name, std::string_view definition);

            // structure view
            void AddVariable(uint64 offset, std::string_view name, VariableType type);
            void AddArray(uint64 offset, std::string_view name, VariableType type, uint32 count);
            void AddBidimensionalArray(uint64 offset, std::string_view name, VariableType type, uint32 width, uint32 height);

            void AddVariable(uint64 offset, std::string_view name, TypeID type);
            void AddArray(uint64 offset, std::string_view name, TypeID type, uint32 count);
            void AddBidimensionalArray(uint64 offset, std::string_view name, TypeID type, uint32 width, uint32 height);

            /*
             * types: uin8-64,int8-64, float,double, char* (asciiZ), Unicode16Z,Unicode32Z
             * auto point_id = AddType("Point","struct Point{ uint32 x;uint32 y };");
             * AddVariable(0x1234, "MyPoint", point_id);
             */

            Settings();
        };
    }; // namespace DissasmViewer

    struct CORE_EXPORT WindowInterface
    {
        virtual Reference<Object> GetObject()                                                        = 0;
        virtual bool AddPanel(Pointer<TabPage> page, bool vertical)                                  = 0;
        virtual bool CreateViewer(const std::string_view& name, BufferViewer::Settings& settings)    = 0;
        virtual bool CreateViewer(const std::string_view& name, ImageViewer::Settings& settings)     = 0;
        virtual bool CreateViewer(const std::string_view& name, GridViewer::Settings& settings)      = 0;
        virtual bool CreateViewer(const std::string_view& name, DissasmViewer::Settings& settings)   = 0;
        virtual bool CreateViewer(const std::string_view& name, TextViewer::Settings& settings)      = 0;
        virtual bool CreateViewer(const std::string_view& name, ContainerViewer::Settings& settings) = 0;
        virtual bool CreateViewer(const std::string_view& name, LexicalViewer::Settings& settings)   = 0;
        virtual Reference<ViewControl> GetCurrentView()                                              = 0;

        template <typename T>
        inline bool CreateViewer(const std::string_view& name)
        {
            T settings;
            return CreateViewer(name, settings);
        }
    };
}; // namespace View
namespace App
{
    bool CORE_EXPORT Init();
    void CORE_EXPORT Run();
    bool CORE_EXPORT ResetConfiguration();
    void CORE_EXPORT OpenFile(const std::filesystem::path& path);
    void CORE_EXPORT OpenBuffer(BufferView buf, const ConstString& name, string_view typeExtension = "");
    Reference<GView::Object> CORE_EXPORT GetObject(uint32 index);
    uint32 CORE_EXPORT GetObjectsCount();
}; // namespace App
}; // namespace GView

ADD_FLAG_OPERATORS(GView::View::LexicalViewer::StringFormat, AppCUI::uint32);
ADD_FLAG_OPERATORS(GView::View::LexicalViewer::NumberFormat, AppCUI::uint32);
ADD_FLAG_OPERATORS(GView::View::LexicalViewer::TokenAlignament, AppCUI::uint32);
ADD_FLAG_OPERATORS(GView::View::LexicalViewer::BlockFlags, AppCUI::uint16);