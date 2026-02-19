/*
 Copyright (c) 2026 Basalt contributors. All rights reserved.

 Bridge prefix header — resolves BOOL conflict between TrueCrypt (C legacy)
 and Objective-C. Must be included BEFORE any other headers in .mm files.
*/

#ifndef TC_HEADER_Bridge_Prefix
#define TC_HEADER_Bridge_Prefix

// Import ObjC/Foundation FIRST so that typedef bool BOOL is established
#import <Foundation/Foundation.h>

// Now prevent Tcdefs.h from redefining BOOL
// Tcdefs.h does: #define BOOL int (for non-MSVC builds)
// We need to block this because ObjC already typedef'd BOOL as bool
#ifndef _MSC_VER
#define TC_OBJCXX_BOOL_GUARD 1
#endif

#endif // TC_HEADER_Bridge_Prefix
