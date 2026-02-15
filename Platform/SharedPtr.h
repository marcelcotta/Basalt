/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Platform_SharedPtr
#define TC_HEADER_Platform_SharedPtr

#include "SharedVal.h"

// Convenience macro: declares a shared_ptr<T> and constructs a default T
#define make_shared_auto(typeName,instanceName) shared_ptr <typeName> instanceName (new typeName ())

#endif // TC_HEADER_Platform_SharedPtr
