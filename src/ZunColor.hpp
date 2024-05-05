#include "inttypes.hpp"

// Note: Little endian!
union ZunColor {
    u32 color;
    u8 bytes[4];
    struct
    {
        u8 blue;
        u8 green;
        u8 red;
        u8 alpha;
    };
};
