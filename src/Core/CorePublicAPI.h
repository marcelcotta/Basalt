/*
 Copyright (c) 2024-2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

// Convenience header: includes the complete public API of libTrueCryptCore.
// No wxWidgets dependency. Safe to use from SwiftUI, CLI, or any C++ consumer.

#ifndef TC_HEADER_Core_CorePublicAPI
#define TC_HEADER_Core_CorePublicAPI

// Core singleton and base interface
#include "Core/Core.h"
#include "Core/CoreBase.h"

// Volume operations (backup, restore, KDF upgrade) with callback interface
#include "Core/VolumeOperations.h"

// Mount/create options
#include "Core/MountOptions.h"
#include "Core/VolumeCreator.h"
#include "Core/RandomNumberGenerator.h"

// Volume information and types
#include "Volume/VolumeInfo.h"
#include "Volume/VolumePassword.h"
#include "Volume/Keyfile.h"
#include "Volume/Pkcs5Kdf.h"
#include "Volume/EncryptionAlgorithm.h"
#include "Volume/Hash.h"

// Platform essentials
#include "Platform/Event.h"
#include "Platform/Functor.h"

#endif // TC_HEADER_Core_CorePublicAPI
