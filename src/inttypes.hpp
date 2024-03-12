#pragma once

typedef char i8;
typedef unsigned char u8;
typedef short i16;
typedef unsigned short u16;
typedef int i32;
typedef unsigned int u32;
typedef float f32;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define ARRAY_SIZE_SIGNED(x) ((i32)sizeof(x) / (i32)sizeof(x[0]))
