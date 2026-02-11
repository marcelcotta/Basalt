/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Platform/Mutex.h"
#include "Platform/SystemException.h"

namespace TrueCrypt
{
	Mutex::Mutex ()
	{
		InitializeCriticalSection (&SystemMutex);
		Initialized = true;
	}

	Mutex::~Mutex ()
	{
		Initialized = false;
		DeleteCriticalSection (&SystemMutex);
	}

	void Mutex::Lock ()
	{
		assert (Initialized);
		EnterCriticalSection (&SystemMutex);
	}

	void Mutex::Unlock ()
	{
		LeaveCriticalSection (&SystemMutex);
	}
}
