#include <cassert>
#include <GView.hpp>
#include "endian.hpp"

using namespace AppCUI::Utils;
using namespace GView;

namespace GView::Java
{
struct JavaViewer : public TypeInterface
{
    string_view GetTypeName() override;
};

struct ClassFile
{
};

bool parse_class(BufferView buffer);

class BufferReader
{
    const uint8* ptr_start;
    const uint8* ptr_current;
    const uint8* ptr_end;

  public:
    BufferReader(const uint8* ptr_start, size_t size);

    size_t available() const;
    const uint8* get() const;
    bool read(void* buffer, size_t size);
    bool skip(size_t size);

    template <typename T>
    bool read(T& x)
    {
        return read(&x, sizeof(x));
    }

    template <typename T>
    bool read_big(T& x)
    {
        if (!read(&x, sizeof(x)))
            return false;
        x = Endian::big_to_native(x);
        return true;
    }
};

#define READB(x)                                                                                                                           \
    if (!reader.read_big(x))                                                                                                               \
    return false

#define SKIPTYPE(x)                                                                                                                        \
    if (!reader.skip(sizeof(x)))                                                                                                           \
    return false

#define SKIP(x)                                                                                                                            \
    if (!reader.skip(x))                                                                                                                   \
    return false

#define FCHECK(x) CHECK(x, false, #x)

#define unreachable                                                                                                                        \
    __debugbreak();                                                                                                                        \
    std::abort()

} // namespace GView::Java