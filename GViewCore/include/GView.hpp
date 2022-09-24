#pragma once

// Version MUST be in the following format <Major>.<Minor>.<Patch>
#define GVIEW_VERSION "0.214.0"

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

    constexpr auto ERR_SIGNER            = -1;
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
        union FstEntry
        {
            FstEntry32* _32;
            FstEntry64* _64;
        } fstEntry{ nullptr };
    };

    struct CORE_EXPORT PcLnTab
    {
      private:
        void* context{ nullptr };
        void Reset();

      public:
        PcLnTab();
        ~PcLnTab();
        bool Process(const Buffer& buffer, Architecture arch);
        GoFunctionHeader* GetHeader() const;
        uint64 GetFilesCount() const;
        bool GetFile(uint64 index, std::string_view& file) const;
        uint64 GetFunctionsCount() const;
        bool GetFunction(uint64 index, Function& func) const;
        uint64 GetEntriesCount() const;
        void SetBuildId(std::string_view buildId);
        const std::string& GetBuildId() const;
        void SetRuntimeBuildVersion(std::string_view runtimeBuildVersion);
        const std::string& GetRuntimeBuildVersion() const;
        void SetRuntimeBuildModInfo(std::string_view runtimeBuildModInfo);
        const std::string& GetRuntimeBuildModInfo() const;
    };

    CORE_EXPORT const char* GetNameForGoMagic(GoMagic magic);
} // namespace Golang

namespace ZLIB
{
    CORE_EXPORT bool Decompress(const Buffer& input, uint64 inputSize, Buffer& output, uint64 outputSize);
}

namespace Dissasembly
{
    enum class Architecture // cs_arch from capstone (keep it synced!)
    {
        ARM = 0,    ///< ARM architecture (including Thumb, Thumb-2)
        ARM64,      ///< ARM-64, also called AArch64
        MIPS,       ///< Mips architecture
        X86,        ///< X86 architecture (including x86 & x86-64)
        PPC,        ///< PowerPC architecture
        SPARC,      ///< Sparc architecture
        SYSZ,       ///< SystemZ architecture
        XCORE,      ///< XCore architecture
        M68K,       ///< 68K architecture
        TMS320C64X, ///< TMS320C64x architecture
        M680X,      ///< 680X architecture
        EVM,        ///< Ethereum architecture
        MOS65XX,    ///< MOS65XX architecture (including MOS6502)
        WASM,       ///< WebAssembly architecture
        BPF,        ///< Berkeley Packet Filter architecture (including eBPF)
        RISCV,      ///< RISCV architecture
        MAX,
        ALL = 0xFFFF, // All architectures - for cs_support()
    };

    enum class Mode
    {
        Unknown,
        X16,
        X32,
        X64
    };

    enum class Opcodes : uint32
    {
        Header        = 1,
        Call          = 2,
        LCall         = 4,
        Jmp           = 8,
        LJmp          = 16,
        Breakpoint    = 32,
        FunctionStart = 64,
        FunctionEnd   = 128,
        All           = 0xFFFFFFFF
    };

    enum class InstructionX86 : uint32 // x86_insn from capstone (keep it synced!)
    {
        INVALID = 0,

        AAA,
        AAD,
        AAM,
        AAS,
        FABS,
        ADC,
        ADCX,
        ADD,
        ADDPD,
        ADDPS,
        ADDSD,
        ADDSS,
        ADDSUBPD,
        ADDSUBPS,
        FADD,
        FIADD,
        ADOX,
        AESDECLAST,
        AESDEC,
        AESENCLAST,
        AESENC,
        AESIMC,
        AESKEYGENASSIST,
        AND,
        ANDN,
        ANDNPD,
        ANDNPS,
        ANDPD,
        ANDPS,
        ARPL,
        BEXTR,
        BLCFILL,
        BLCI,
        BLCIC,
        BLCMSK,
        BLCS,
        BLENDPD,
        BLENDPS,
        BLENDVPD,
        BLENDVPS,
        BLSFILL,
        BLSI,
        BLSIC,
        BLSMSK,
        BLSR,
        BNDCL,
        BNDCN,
        BNDCU,
        BNDLDX,
        BNDMK,
        BNDMOV,
        BNDSTX,
        BOUND,
        BSF,
        BSR,
        BSWAP,
        BT,
        BTC,
        BTR,
        BTS,
        BZHI,
        CALL,
        CBW,
        CDQ,
        CDQE,
        FCHS,
        CLAC,
        CLC,
        CLD,
        CLDEMOTE,
        CLFLUSH,
        CLFLUSHOPT,
        CLGI,
        CLI,
        CLRSSBSY,
        CLTS,
        CLWB,
        CLZERO,
        CMC,
        CMOVA,
        CMOVAE,
        CMOVB,
        CMOVBE,
        FCMOVBE,
        FCMOVB,
        CMOVE,
        FCMOVE,
        CMOVG,
        CMOVGE,
        CMOVL,
        CMOVLE,
        FCMOVNBE,
        FCMOVNB,
        CMOVNE,
        FCMOVNE,
        CMOVNO,
        CMOVNP,
        FCMOVNU,
        FCMOVNP,
        CMOVNS,
        CMOVO,
        CMOVP,
        FCMOVU,
        CMOVS,
        CMP,
        CMPPD,
        CMPPS,
        CMPSB,
        CMPSD,
        CMPSQ,
        CMPSS,
        CMPSW,
        CMPXCHG16B,
        CMPXCHG,
        CMPXCHG8B,
        COMISD,
        COMISS,
        FCOMP,
        FCOMPI,
        FCOMI,
        FCOM,
        FCOS,
        CPUID,
        CQO,
        CRC32,
        CVTDQ2PD,
        CVTDQ2PS,
        CVTPD2DQ,
        CVTPD2PS,
        CVTPS2DQ,
        CVTPS2PD,
        CVTSD2SI,
        CVTSD2SS,
        CVTSI2SD,
        CVTSI2SS,
        CVTSS2SD,
        CVTSS2SI,
        CVTTPD2DQ,
        CVTTPS2DQ,
        CVTTSD2SI,
        CVTTSS2SI,
        CWD,
        CWDE,
        DAA,
        DAS,
        DATA16,
        DEC,
        DIV,
        DIVPD,
        DIVPS,
        FDIVR,
        FIDIVR,
        FDIVRP,
        DIVSD,
        DIVSS,
        FDIV,
        FIDIV,
        FDIVP,
        DPPD,
        DPPS,
        ENCLS,
        ENCLU,
        ENCLV,
        ENDBR32,
        ENDBR64,
        ENTER,
        EXTRACTPS,
        EXTRQ,
        F2XM1,
        LCALL,
        LJMP,
        JMP,
        FBLD,
        FBSTP,
        FCOMPP,
        FDECSTP,
        FDISI8087_NOP,
        FEMMS,
        FENI8087_NOP,
        FFREE,
        FFREEP,
        FICOM,
        FICOMP,
        FINCSTP,
        FLDCW,
        FLDENV,
        FLDL2E,
        FLDL2T,
        FLDLG2,
        FLDLN2,
        FLDPI,
        FNCLEX,
        FNINIT,
        FNOP,
        FNSTCW,
        FNSTSW,
        FPATAN,
        FSTPNCE,
        FPREM,
        FPREM1,
        FPTAN,
        FRNDINT,
        FRSTOR,
        FNSAVE,
        FSCALE,
        FSETPM,
        FSINCOS,
        FNSTENV,
        FXAM,
        FXRSTOR,
        FXRSTOR64,
        FXSAVE,
        FXSAVE64,
        FXTRACT,
        FYL2X,
        FYL2XP1,
        GETSEC,
        GF2P8AFFINEINVQB,
        GF2P8AFFINEQB,
        GF2P8MULB,
        HADDPD,
        HADDPS,
        HLT,
        HSUBPD,
        HSUBPS,
        IDIV,
        FILD,
        IMUL,
        IN,
        INC,
        INCSSPD,
        INCSSPQ,
        INSB,
        INSERTPS,
        INSERTQ,
        INSD,
        INSW,
        INT,
        INT1,
        INT3,
        INTO,
        INVD,
        INVEPT,
        INVLPG,
        INVLPGA,
        INVPCID,
        INVVPID,
        IRET,
        IRETD,
        IRETQ,
        FISTTP,
        FIST,
        FISTP,
        JAE,
        JA,
        JBE,
        JB,
        JCXZ,
        JECXZ,
        JE,
        JGE,
        JG,
        JLE,
        JL,
        JNE,
        JNO,
        JNP,
        JNS,
        JO,
        JP,
        JRCXZ,
        JS,
        KADDB,
        KADDD,
        KADDQ,
        KADDW,
        KANDB,
        KANDD,
        KANDNB,
        KANDND,
        KANDNQ,
        KANDNW,
        KANDQ,
        KANDW,
        KMOVB,
        KMOVD,
        KMOVQ,
        KMOVW,
        KNOTB,
        KNOTD,
        KNOTQ,
        KNOTW,
        KORB,
        KORD,
        KORQ,
        KORTESTB,
        KORTESTD,
        KORTESTQ,
        KORTESTW,
        KORW,
        KSHIFTLB,
        KSHIFTLD,
        KSHIFTLQ,
        KSHIFTLW,
        KSHIFTRB,
        KSHIFTRD,
        KSHIFTRQ,
        KSHIFTRW,
        KTESTB,
        KTESTD,
        KTESTQ,
        KTESTW,
        KUNPCKBW,
        KUNPCKDQ,
        KUNPCKWD,
        KXNORB,
        KXNORD,
        KXNORQ,
        KXNORW,
        KXORB,
        KXORD,
        KXORQ,
        KXORW,
        LAHF,
        LAR,
        LDDQU,
        LDMXCSR,
        LDS,
        FLDZ,
        FLD1,
        FLD,
        LEA,
        LEAVE,
        LES,
        LFENCE,
        LFS,
        LGDT,
        LGS,
        LIDT,
        LLDT,
        LLWPCB,
        LMSW,
        LOCK,
        LODSB,
        LODSD,
        LODSQ,
        LODSW,
        LOOP,
        LOOPE,
        LOOPNE,
        RETF,
        RETFQ,
        LSL,
        LSS,
        LTR,
        LWPINS,
        LWPVAL,
        LZCNT,
        MASKMOVDQU,
        MAXPD,
        MAXPS,
        MAXSD,
        MAXSS,
        MFENCE,
        MINPD,
        MINPS,
        MINSD,
        MINSS,
        CVTPD2PI,
        CVTPI2PD,
        CVTPI2PS,
        CVTPS2PI,
        CVTTPD2PI,
        CVTTPS2PI,
        EMMS,
        MASKMOVQ,
        MOVD,
        MOVQ,
        MOVDQ2Q,
        MOVNTQ,
        MOVQ2DQ,
        PABSB,
        PABSD,
        PABSW,
        PACKSSDW,
        PACKSSWB,
        PACKUSWB,
        PADDB,
        PADDD,
        PADDQ,
        PADDSB,
        PADDSW,
        PADDUSB,
        PADDUSW,
        PADDW,
        PALIGNR,
        PANDN,
        PAND,
        PAVGB,
        PAVGW,
        PCMPEQB,
        PCMPEQD,
        PCMPEQW,
        PCMPGTB,
        PCMPGTD,
        PCMPGTW,
        PEXTRW,
        PHADDD,
        PHADDSW,
        PHADDW,
        PHSUBD,
        PHSUBSW,
        PHSUBW,
        PINSRW,
        PMADDUBSW,
        PMADDWD,
        PMAXSW,
        PMAXUB,
        PMINSW,
        PMINUB,
        PMOVMSKB,
        PMULHRSW,
        PMULHUW,
        PMULHW,
        PMULLW,
        PMULUDQ,
        POR,
        PSADBW,
        PSHUFB,
        PSHUFW,
        PSIGNB,
        PSIGND,
        PSIGNW,
        PSLLD,
        PSLLQ,
        PSLLW,
        PSRAD,
        PSRAW,
        PSRLD,
        PSRLQ,
        PSRLW,
        PSUBB,
        PSUBD,
        PSUBQ,
        PSUBSB,
        PSUBSW,
        PSUBUSB,
        PSUBUSW,
        PSUBW,
        PUNPCKHBW,
        PUNPCKHDQ,
        PUNPCKHWD,
        PUNPCKLBW,
        PUNPCKLDQ,
        PUNPCKLWD,
        PXOR,
        MONITORX,
        MONITOR,
        MONTMUL,
        MOV,
        MOVABS,
        MOVAPD,
        MOVAPS,
        MOVBE,
        MOVDDUP,
        MOVDIR64B,
        MOVDIRI,
        MOVDQA,
        MOVDQU,
        MOVHLPS,
        MOVHPD,
        MOVHPS,
        MOVLHPS,
        MOVLPD,
        MOVLPS,
        MOVMSKPD,
        MOVMSKPS,
        MOVNTDQA,
        MOVNTDQ,
        MOVNTI,
        MOVNTPD,
        MOVNTPS,
        MOVNTSD,
        MOVNTSS,
        MOVSB,
        MOVSD,
        MOVSHDUP,
        MOVSLDUP,
        MOVSQ,
        MOVSS,
        MOVSW,
        MOVSX,
        MOVSXD,
        MOVUPD,
        MOVUPS,
        MOVZX,
        MPSADBW,
        MUL,
        MULPD,
        MULPS,
        MULSD,
        MULSS,
        MULX,
        FMUL,
        FIMUL,
        FMULP,
        MWAITX,
        MWAIT,
        NEG,
        NOP,
        NOT,
        OR,
        ORPD,
        ORPS,
        OUT,
        OUTSB,
        OUTSD,
        OUTSW,
        PACKUSDW,
        PAUSE,
        PAVGUSB,
        PBLENDVB,
        PBLENDW,
        PCLMULQDQ,
        PCMPEQQ,
        PCMPESTRI,
        PCMPESTRM,
        PCMPGTQ,
        PCMPISTRI,
        PCMPISTRM,
        PCONFIG,
        PDEP,
        PEXT,
        PEXTRB,
        PEXTRD,
        PEXTRQ,
        PF2ID,
        PF2IW,
        PFACC,
        PFADD,
        PFCMPEQ,
        PFCMPGE,
        PFCMPGT,
        PFMAX,
        PFMIN,
        PFMUL,
        PFNACC,
        PFPNACC,
        PFRCPIT1,
        PFRCPIT2,
        PFRCP,
        PFRSQIT1,
        PFRSQRT,
        PFSUBR,
        PFSUB,
        PHMINPOSUW,
        PI2FD,
        PI2FW,
        PINSRB,
        PINSRD,
        PINSRQ,
        PMAXSB,
        PMAXSD,
        PMAXUD,
        PMAXUW,
        PMINSB,
        PMINSD,
        PMINUD,
        PMINUW,
        PMOVSXBD,
        PMOVSXBQ,
        PMOVSXBW,
        PMOVSXDQ,
        PMOVSXWD,
        PMOVSXWQ,
        PMOVZXBD,
        PMOVZXBQ,
        PMOVZXBW,
        PMOVZXDQ,
        PMOVZXWD,
        PMOVZXWQ,
        PMULDQ,
        PMULHRW,
        PMULLD,
        POP,
        POPAW,
        POPAL,
        POPCNT,
        POPF,
        POPFD,
        POPFQ,
        PREFETCH,
        PREFETCHNTA,
        PREFETCHT0,
        PREFETCHT1,
        PREFETCHT2,
        PREFETCHW,
        PREFETCHWT1,
        PSHUFD,
        PSHUFHW,
        PSHUFLW,
        PSLLDQ,
        PSRLDQ,
        PSWAPD,
        PTEST,
        PTWRITE,
        PUNPCKHQDQ,
        PUNPCKLQDQ,
        PUSH,
        PUSHAW,
        PUSHAL,
        PUSHF,
        PUSHFD,
        PUSHFQ,
        RCL,
        RCPPS,
        RCPSS,
        RCR,
        RDFSBASE,
        RDGSBASE,
        RDMSR,
        RDPID,
        RDPKRU,
        RDPMC,
        RDRAND,
        RDSEED,
        RDSSPD,
        RDSSPQ,
        RDTSC,
        RDTSCP,
        REPNE,
        REP,
        RET,
        REX64,
        ROL,
        ROR,
        RORX,
        ROUNDPD,
        ROUNDPS,
        ROUNDSD,
        ROUNDSS,
        RSM,
        RSQRTPS,
        RSQRTSS,
        RSTORSSP,
        SAHF,
        SAL,
        SALC,
        SAR,
        SARX,
        SAVEPREVSSP,
        SBB,
        SCASB,
        SCASD,
        SCASQ,
        SCASW,
        SETAE,
        SETA,
        SETBE,
        SETB,
        SETE,
        SETGE,
        SETG,
        SETLE,
        SETL,
        SETNE,
        SETNO,
        SETNP,
        SETNS,
        SETO,
        SETP,
        SETSSBSY,
        SETS,
        SFENCE,
        SGDT,
        SHA1MSG1,
        SHA1MSG2,
        SHA1NEXTE,
        SHA1RNDS4,
        SHA256MSG1,
        SHA256MSG2,
        SHA256RNDS2,
        SHL,
        SHLD,
        SHLX,
        SHR,
        SHRD,
        SHRX,
        SHUFPD,
        SHUFPS,
        SIDT,
        FSIN,
        SKINIT,
        SLDT,
        SLWPCB,
        SMSW,
        SQRTPD,
        SQRTPS,
        SQRTSD,
        SQRTSS,
        FSQRT,
        STAC,
        STC,
        STD,
        STGI,
        STI,
        STMXCSR,
        STOSB,
        STOSD,
        STOSQ,
        STOSW,
        STR,
        FST,
        FSTP,
        SUB,
        SUBPD,
        SUBPS,
        FSUBR,
        FISUBR,
        FSUBRP,
        SUBSD,
        SUBSS,
        FSUB,
        FISUB,
        FSUBP,
        SWAPGS,
        SYSCALL,
        SYSENTER,
        SYSEXIT,
        SYSEXITQ,
        SYSRET,
        SYSRETQ,
        T1MSKC,
        TEST,
        TPAUSE,
        FTST,
        TZCNT,
        TZMSK,
        UCOMISD,
        UCOMISS,
        FUCOMPI,
        FUCOMI,
        FUCOMPP,
        FUCOMP,
        FUCOM,
        UD0,
        UD1,
        UD2,
        UMONITOR,
        UMWAIT,
        UNPCKHPD,
        UNPCKHPS,
        UNPCKLPD,
        UNPCKLPS,
        V4FMADDPS,
        V4FMADDSS,
        V4FNMADDPS,
        V4FNMADDSS,
        VADDPD,
        VADDPS,
        VADDSD,
        VADDSS,
        VADDSUBPD,
        VADDSUBPS,
        VAESDECLAST,
        VAESDEC,
        VAESENCLAST,
        VAESENC,
        VAESIMC,
        VAESKEYGENASSIST,
        VALIGND,
        VALIGNQ,
        VANDNPD,
        VANDNPS,
        VANDPD,
        VANDPS,
        VBLENDMPD,
        VBLENDMPS,
        VBLENDPD,
        VBLENDPS,
        VBLENDVPD,
        VBLENDVPS,
        VBROADCASTF128,
        VBROADCASTF32X2,
        VBROADCASTF32X4,
        VBROADCASTF32X8,
        VBROADCASTF64X2,
        VBROADCASTF64X4,
        VBROADCASTI128,
        VBROADCASTI32X2,
        VBROADCASTI32X4,
        VBROADCASTI32X8,
        VBROADCASTI64X2,
        VBROADCASTI64X4,
        VBROADCASTSD,
        VBROADCASTSS,
        VCMP,
        VCMPPD,
        VCMPPS,
        VCMPSD,
        VCMPSS,
        VCOMISD,
        VCOMISS,
        VCOMPRESSPD,
        VCOMPRESSPS,
        VCVTDQ2PD,
        VCVTDQ2PS,
        VCVTPD2DQ,
        VCVTPD2PS,
        VCVTPD2QQ,
        VCVTPD2UDQ,
        VCVTPD2UQQ,
        VCVTPH2PS,
        VCVTPS2DQ,
        VCVTPS2PD,
        VCVTPS2PH,
        VCVTPS2QQ,
        VCVTPS2UDQ,
        VCVTPS2UQQ,
        VCVTQQ2PD,
        VCVTQQ2PS,
        VCVTSD2SI,
        VCVTSD2SS,
        VCVTSD2USI,
        VCVTSI2SD,
        VCVTSI2SS,
        VCVTSS2SD,
        VCVTSS2SI,
        VCVTSS2USI,
        VCVTTPD2DQ,
        VCVTTPD2QQ,
        VCVTTPD2UDQ,
        VCVTTPD2UQQ,
        VCVTTPS2DQ,
        VCVTTPS2QQ,
        VCVTTPS2UDQ,
        VCVTTPS2UQQ,
        VCVTTSD2SI,
        VCVTTSD2USI,
        VCVTTSS2SI,
        VCVTTSS2USI,
        VCVTUDQ2PD,
        VCVTUDQ2PS,
        VCVTUQQ2PD,
        VCVTUQQ2PS,
        VCVTUSI2SD,
        VCVTUSI2SS,
        VDBPSADBW,
        VDIVPD,
        VDIVPS,
        VDIVSD,
        VDIVSS,
        VDPPD,
        VDPPS,
        VERR,
        VERW,
        VEXP2PD,
        VEXP2PS,
        VEXPANDPD,
        VEXPANDPS,
        VEXTRACTF128,
        VEXTRACTF32X4,
        VEXTRACTF32X8,
        VEXTRACTF64X2,
        VEXTRACTF64X4,
        VEXTRACTI128,
        VEXTRACTI32X4,
        VEXTRACTI32X8,
        VEXTRACTI64X2,
        VEXTRACTI64X4,
        VEXTRACTPS,
        VFIXUPIMMPD,
        VFIXUPIMMPS,
        VFIXUPIMMSD,
        VFIXUPIMMSS,
        VFMADD132PD,
        VFMADD132PS,
        VFMADD132SD,
        VFMADD132SS,
        VFMADD213PD,
        VFMADD213PS,
        VFMADD213SD,
        VFMADD213SS,
        VFMADD231PD,
        VFMADD231PS,
        VFMADD231SD,
        VFMADD231SS,
        VFMADDPD,
        VFMADDPS,
        VFMADDSD,
        VFMADDSS,
        VFMADDSUB132PD,
        VFMADDSUB132PS,
        VFMADDSUB213PD,
        VFMADDSUB213PS,
        VFMADDSUB231PD,
        VFMADDSUB231PS,
        VFMADDSUBPD,
        VFMADDSUBPS,
        VFMSUB132PD,
        VFMSUB132PS,
        VFMSUB132SD,
        VFMSUB132SS,
        VFMSUB213PD,
        VFMSUB213PS,
        VFMSUB213SD,
        VFMSUB213SS,
        VFMSUB231PD,
        VFMSUB231PS,
        VFMSUB231SD,
        VFMSUB231SS,
        VFMSUBADD132PD,
        VFMSUBADD132PS,
        VFMSUBADD213PD,
        VFMSUBADD213PS,
        VFMSUBADD231PD,
        VFMSUBADD231PS,
        VFMSUBADDPD,
        VFMSUBADDPS,
        VFMSUBPD,
        VFMSUBPS,
        VFMSUBSD,
        VFMSUBSS,
        VFNMADD132PD,
        VFNMADD132PS,
        VFNMADD132SD,
        VFNMADD132SS,
        VFNMADD213PD,
        VFNMADD213PS,
        VFNMADD213SD,
        VFNMADD213SS,
        VFNMADD231PD,
        VFNMADD231PS,
        VFNMADD231SD,
        VFNMADD231SS,
        VFNMADDPD,
        VFNMADDPS,
        VFNMADDSD,
        VFNMADDSS,
        VFNMSUB132PD,
        VFNMSUB132PS,
        VFNMSUB132SD,
        VFNMSUB132SS,
        VFNMSUB213PD,
        VFNMSUB213PS,
        VFNMSUB213SD,
        VFNMSUB213SS,
        VFNMSUB231PD,
        VFNMSUB231PS,
        VFNMSUB231SD,
        VFNMSUB231SS,
        VFNMSUBPD,
        VFNMSUBPS,
        VFNMSUBSD,
        VFNMSUBSS,
        VFPCLASSPD,
        VFPCLASSPS,
        VFPCLASSSD,
        VFPCLASSSS,
        VFRCZPD,
        VFRCZPS,
        VFRCZSD,
        VFRCZSS,
        VGATHERDPD,
        VGATHERDPS,
        VGATHERPF0DPD,
        VGATHERPF0DPS,
        VGATHERPF0QPD,
        VGATHERPF0QPS,
        VGATHERPF1DPD,
        VGATHERPF1DPS,
        VGATHERPF1QPD,
        VGATHERPF1QPS,
        VGATHERQPD,
        VGATHERQPS,
        VGETEXPPD,
        VGETEXPPS,
        VGETEXPSD,
        VGETEXPSS,
        VGETMANTPD,
        VGETMANTPS,
        VGETMANTSD,
        VGETMANTSS,
        VGF2P8AFFINEINVQB,
        VGF2P8AFFINEQB,
        VGF2P8MULB,
        VHADDPD,
        VHADDPS,
        VHSUBPD,
        VHSUBPS,
        VINSERTF128,
        VINSERTF32X4,
        VINSERTF32X8,
        VINSERTF64X2,
        VINSERTF64X4,
        VINSERTI128,
        VINSERTI32X4,
        VINSERTI32X8,
        VINSERTI64X2,
        VINSERTI64X4,
        VINSERTPS,
        VLDDQU,
        VLDMXCSR,
        VMASKMOVDQU,
        VMASKMOVPD,
        VMASKMOVPS,
        VMAXPD,
        VMAXPS,
        VMAXSD,
        VMAXSS,
        VMCALL,
        VMCLEAR,
        VMFUNC,
        VMINPD,
        VMINPS,
        VMINSD,
        VMINSS,
        VMLAUNCH,
        VMLOAD,
        VMMCALL,
        VMOVQ,
        VMOVAPD,
        VMOVAPS,
        VMOVDDUP,
        VMOVD,
        VMOVDQA32,
        VMOVDQA64,
        VMOVDQA,
        VMOVDQU16,
        VMOVDQU32,
        VMOVDQU64,
        VMOVDQU8,
        VMOVDQU,
        VMOVHLPS,
        VMOVHPD,
        VMOVHPS,
        VMOVLHPS,
        VMOVLPD,
        VMOVLPS,
        VMOVMSKPD,
        VMOVMSKPS,
        VMOVNTDQA,
        VMOVNTDQ,
        VMOVNTPD,
        VMOVNTPS,
        VMOVSD,
        VMOVSHDUP,
        VMOVSLDUP,
        VMOVSS,
        VMOVUPD,
        VMOVUPS,
        VMPSADBW,
        VMPTRLD,
        VMPTRST,
        VMREAD,
        VMRESUME,
        VMRUN,
        VMSAVE,
        VMULPD,
        VMULPS,
        VMULSD,
        VMULSS,
        VMWRITE,
        VMXOFF,
        VMXON,
        VORPD,
        VORPS,
        VP4DPWSSDS,
        VP4DPWSSD,
        VPABSB,
        VPABSD,
        VPABSQ,
        VPABSW,
        VPACKSSDW,
        VPACKSSWB,
        VPACKUSDW,
        VPACKUSWB,
        VPADDB,
        VPADDD,
        VPADDQ,
        VPADDSB,
        VPADDSW,
        VPADDUSB,
        VPADDUSW,
        VPADDW,
        VPALIGNR,
        VPANDD,
        VPANDND,
        VPANDNQ,
        VPANDN,
        VPANDQ,
        VPAND,
        VPAVGB,
        VPAVGW,
        VPBLENDD,
        VPBLENDMB,
        VPBLENDMD,
        VPBLENDMQ,
        VPBLENDMW,
        VPBLENDVB,
        VPBLENDW,
        VPBROADCASTB,
        VPBROADCASTD,
        VPBROADCASTMB2Q,
        VPBROADCASTMW2D,
        VPBROADCASTQ,
        VPBROADCASTW,
        VPCLMULQDQ,
        VPCMOV,
        VPCMP,
        VPCMPB,
        VPCMPD,
        VPCMPEQB,
        VPCMPEQD,
        VPCMPEQQ,
        VPCMPEQW,
        VPCMPESTRI,
        VPCMPESTRM,
        VPCMPGTB,
        VPCMPGTD,
        VPCMPGTQ,
        VPCMPGTW,
        VPCMPISTRI,
        VPCMPISTRM,
        VPCMPQ,
        VPCMPUB,
        VPCMPUD,
        VPCMPUQ,
        VPCMPUW,
        VPCMPW,
        VPCOM,
        VPCOMB,
        VPCOMD,
        VPCOMPRESSB,
        VPCOMPRESSD,
        VPCOMPRESSQ,
        VPCOMPRESSW,
        VPCOMQ,
        VPCOMUB,
        VPCOMUD,
        VPCOMUQ,
        VPCOMUW,
        VPCOMW,
        VPCONFLICTD,
        VPCONFLICTQ,
        VPDPBUSDS,
        VPDPBUSD,
        VPDPWSSDS,
        VPDPWSSD,
        VPERM2F128,
        VPERM2I128,
        VPERMB,
        VPERMD,
        VPERMI2B,
        VPERMI2D,
        VPERMI2PD,
        VPERMI2PS,
        VPERMI2Q,
        VPERMI2W,
        VPERMIL2PD,
        VPERMILPD,
        VPERMIL2PS,
        VPERMILPS,
        VPERMPD,
        VPERMPS,
        VPERMQ,
        VPERMT2B,
        VPERMT2D,
        VPERMT2PD,
        VPERMT2PS,
        VPERMT2Q,
        VPERMT2W,
        VPERMW,
        VPEXPANDB,
        VPEXPANDD,
        VPEXPANDQ,
        VPEXPANDW,
        VPEXTRB,
        VPEXTRD,
        VPEXTRQ,
        VPEXTRW,
        VPGATHERDD,
        VPGATHERDQ,
        VPGATHERQD,
        VPGATHERQQ,
        VPHADDBD,
        VPHADDBQ,
        VPHADDBW,
        VPHADDDQ,
        VPHADDD,
        VPHADDSW,
        VPHADDUBD,
        VPHADDUBQ,
        VPHADDUBW,
        VPHADDUDQ,
        VPHADDUWD,
        VPHADDUWQ,
        VPHADDWD,
        VPHADDWQ,
        VPHADDW,
        VPHMINPOSUW,
        VPHSUBBW,
        VPHSUBDQ,
        VPHSUBD,
        VPHSUBSW,
        VPHSUBWD,
        VPHSUBW,
        VPINSRB,
        VPINSRD,
        VPINSRQ,
        VPINSRW,
        VPLZCNTD,
        VPLZCNTQ,
        VPMACSDD,
        VPMACSDQH,
        VPMACSDQL,
        VPMACSSDD,
        VPMACSSDQH,
        VPMACSSDQL,
        VPMACSSWD,
        VPMACSSWW,
        VPMACSWD,
        VPMACSWW,
        VPMADCSSWD,
        VPMADCSWD,
        VPMADD52HUQ,
        VPMADD52LUQ,
        VPMADDUBSW,
        VPMADDWD,
        VPMASKMOVD,
        VPMASKMOVQ,
        VPMAXSB,
        VPMAXSD,
        VPMAXSQ,
        VPMAXSW,
        VPMAXUB,
        VPMAXUD,
        VPMAXUQ,
        VPMAXUW,
        VPMINSB,
        VPMINSD,
        VPMINSQ,
        VPMINSW,
        VPMINUB,
        VPMINUD,
        VPMINUQ,
        VPMINUW,
        VPMOVB2M,
        VPMOVD2M,
        VPMOVDB,
        VPMOVDW,
        VPMOVM2B,
        VPMOVM2D,
        VPMOVM2Q,
        VPMOVM2W,
        VPMOVMSKB,
        VPMOVQ2M,
        VPMOVQB,
        VPMOVQD,
        VPMOVQW,
        VPMOVSDB,
        VPMOVSDW,
        VPMOVSQB,
        VPMOVSQD,
        VPMOVSQW,
        VPMOVSWB,
        VPMOVSXBD,
        VPMOVSXBQ,
        VPMOVSXBW,
        VPMOVSXDQ,
        VPMOVSXWD,
        VPMOVSXWQ,
        VPMOVUSDB,
        VPMOVUSDW,
        VPMOVUSQB,
        VPMOVUSQD,
        VPMOVUSQW,
        VPMOVUSWB,
        VPMOVW2M,
        VPMOVWB,
        VPMOVZXBD,
        VPMOVZXBQ,
        VPMOVZXBW,
        VPMOVZXDQ,
        VPMOVZXWD,
        VPMOVZXWQ,
        VPMULDQ,
        VPMULHRSW,
        VPMULHUW,
        VPMULHW,
        VPMULLD,
        VPMULLQ,
        VPMULLW,
        VPMULTISHIFTQB,
        VPMULUDQ,
        VPOPCNTB,
        VPOPCNTD,
        VPOPCNTQ,
        VPOPCNTW,
        VPORD,
        VPORQ,
        VPOR,
        VPPERM,
        VPROLD,
        VPROLQ,
        VPROLVD,
        VPROLVQ,
        VPRORD,
        VPRORQ,
        VPRORVD,
        VPRORVQ,
        VPROTB,
        VPROTD,
        VPROTQ,
        VPROTW,
        VPSADBW,
        VPSCATTERDD,
        VPSCATTERDQ,
        VPSCATTERQD,
        VPSCATTERQQ,
        VPSHAB,
        VPSHAD,
        VPSHAQ,
        VPSHAW,
        VPSHLB,
        VPSHLDD,
        VPSHLDQ,
        VPSHLDVD,
        VPSHLDVQ,
        VPSHLDVW,
        VPSHLDW,
        VPSHLD,
        VPSHLQ,
        VPSHLW,
        VPSHRDD,
        VPSHRDQ,
        VPSHRDVD,
        VPSHRDVQ,
        VPSHRDVW,
        VPSHRDW,
        VPSHUFBITQMB,
        VPSHUFB,
        VPSHUFD,
        VPSHUFHW,
        VPSHUFLW,
        VPSIGNB,
        VPSIGND,
        VPSIGNW,
        VPSLLDQ,
        VPSLLD,
        VPSLLQ,
        VPSLLVD,
        VPSLLVQ,
        VPSLLVW,
        VPSLLW,
        VPSRAD,
        VPSRAQ,
        VPSRAVD,
        VPSRAVQ,
        VPSRAVW,
        VPSRAW,
        VPSRLDQ,
        VPSRLD,
        VPSRLQ,
        VPSRLVD,
        VPSRLVQ,
        VPSRLVW,
        VPSRLW,
        VPSUBB,
        VPSUBD,
        VPSUBQ,
        VPSUBSB,
        VPSUBSW,
        VPSUBUSB,
        VPSUBUSW,
        VPSUBW,
        VPTERNLOGD,
        VPTERNLOGQ,
        VPTESTMB,
        VPTESTMD,
        VPTESTMQ,
        VPTESTMW,
        VPTESTNMB,
        VPTESTNMD,
        VPTESTNMQ,
        VPTESTNMW,
        VPTEST,
        VPUNPCKHBW,
        VPUNPCKHDQ,
        VPUNPCKHQDQ,
        VPUNPCKHWD,
        VPUNPCKLBW,
        VPUNPCKLDQ,
        VPUNPCKLQDQ,
        VPUNPCKLWD,
        VPXORD,
        VPXORQ,
        VPXOR,
        VRANGEPD,
        VRANGEPS,
        VRANGESD,
        VRANGESS,
        VRCP14PD,
        VRCP14PS,
        VRCP14SD,
        VRCP14SS,
        VRCP28PD,
        VRCP28PS,
        VRCP28SD,
        VRCP28SS,
        VRCPPS,
        VRCPSS,
        VREDUCEPD,
        VREDUCEPS,
        VREDUCESD,
        VREDUCESS,
        VRNDSCALEPD,
        VRNDSCALEPS,
        VRNDSCALESD,
        VRNDSCALESS,
        VROUNDPD,
        VROUNDPS,
        VROUNDSD,
        VROUNDSS,
        VRSQRT14PD,
        VRSQRT14PS,
        VRSQRT14SD,
        VRSQRT14SS,
        VRSQRT28PD,
        VRSQRT28PS,
        VRSQRT28SD,
        VRSQRT28SS,
        VRSQRTPS,
        VRSQRTSS,
        VSCALEFPD,
        VSCALEFPS,
        VSCALEFSD,
        VSCALEFSS,
        VSCATTERDPD,
        VSCATTERDPS,
        VSCATTERPF0DPD,
        VSCATTERPF0DPS,
        VSCATTERPF0QPD,
        VSCATTERPF0QPS,
        VSCATTERPF1DPD,
        VSCATTERPF1DPS,
        VSCATTERPF1QPD,
        VSCATTERPF1QPS,
        VSCATTERQPD,
        VSCATTERQPS,
        VSHUFF32X4,
        VSHUFF64X2,
        VSHUFI32X4,
        VSHUFI64X2,
        VSHUFPD,
        VSHUFPS,
        VSQRTPD,
        VSQRTPS,
        VSQRTSD,
        VSQRTSS,
        VSTMXCSR,
        VSUBPD,
        VSUBPS,
        VSUBSD,
        VSUBSS,
        VTESTPD,
        VTESTPS,
        VUCOMISD,
        VUCOMISS,
        VUNPCKHPD,
        VUNPCKHPS,
        VUNPCKLPD,
        VUNPCKLPS,
        VXORPD,
        VXORPS,
        VZEROALL,
        VZEROUPPER,
        WAIT,
        WBINVD,
        WBNOINVD,
        WRFSBASE,
        WRGSBASE,
        WRMSR,
        WRPKRU,
        WRSSD,
        WRSSQ,
        WRUSSD,
        WRUSSQ,
        XABORT,
        XACQUIRE,
        XADD,
        XBEGIN,
        XCHG,
        FXCH,
        XCRYPTCBC,
        XCRYPTCFB,
        XCRYPTCTR,
        XCRYPTECB,
        XCRYPTOFB,
        XEND,
        XGETBV,
        XLATB,
        XOR,
        XORPD,
        XORPS,
        XRELEASE,
        XRSTOR,
        XRSTOR64,
        XRSTORS,
        XRSTORS64,
        XSAVE,
        XSAVE64,
        XSAVEC,
        XSAVEC64,
        XSAVEOPT,
        XSAVEOPT64,
        XSAVES,
        XSAVES64,
        XSETBV,
        XSHA1,
        XSHA256,
        XSTORE,
        XTEST,

        ENDING, // mark the end of the list of insn
    };

    constexpr auto BYTES_SIZE    = 24U;
    constexpr auto MNEMONIC_SIZE = 32U;
    constexpr auto OP_STR_SIZE   = 160U;

    struct Instruction
    {
        uint32 id;
        uint64 address;
        uint16 size;
        uint8 bytes[BYTES_SIZE];
        char mnemonic[MNEMONIC_SIZE];
        char opStr[OP_STR_SIZE];
    };

    CORE_EXPORT bool DissasembleInstructionIntelx86(BufferView buf, uint64 va, Instruction& instruction);
    CORE_EXPORT bool DissasembleInstructionIntelx64(BufferView buf, uint64 va, Instruction& instruction);
} // namespace Dissasembly

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
            SingleQuotes                = 0x00000001, // '...'
            DoubleQuotes                = 0x00000002, // "..."
            Apostrophe                  = 0x00000004, // `...`
            TripleQuotes                = 0x00000008, // '''...''' or """...""" or ```...``` (pending on the SingleQuotes..Apostrophe flag)
            AllowEscapeSequences        = 0x00000010, // "...\n..."
            MultiLine                   = 0x00000020, // string accross mulitple lines
            LineContinuityWithBackslash = 0x00000040, // "   \<newline>   "
            All                         = 0xFFFFFFFF, // all possible forms of strings
        };
        enum class NumberFormat : uint32
        {
            DecimalOnly           = 0,
            HexFormat0x           = 0x00000001,
            BinFormat0b           = 0x00000002,
            OctFormatOo           = 0x00000004,
            FloatingPoint         = 0x00000008,
            AllowSignBeforeNumber = 0x00000010,
            AllowUnderline        = 0x00000020,
            AllowSingleQuote      = 0x00000040,
            ExponentFormat        = 0x00000080,
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
        enum class TokenFlags : uint8
        {
            None                    = 0,
            DisableSimilaritySearch = 0x01,
            UnSizeable              = 0x02,
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
                  TokenFlags flags);
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
ADD_FLAG_OPERATORS(GView::View::LexicalViewer::TokenFlags, AppCUI::uint8);