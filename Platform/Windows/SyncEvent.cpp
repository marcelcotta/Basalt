/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Platform/Exception.h"
#include "Platform/SyncEvent.h"
#include "Platform/SystemException.h"

namespace Basalt
{
	SyncEvent::SyncEvent ()
	{
		SystemSyncEvent = CreateEventW (NULL, FALSE, FALSE, NULL);
		if (SystemSyncEvent == NULL)
			throw SystemException (SRC_POS);

		Initialized = true;
	}

	SyncEvent::~SyncEvent ()
	{
		if (Initialized && SystemSyncEvent != NULL)
			CloseHandle (SystemSyncEvent);

		Initialized = false;
	}

	void SyncEvent::Signal ()
	{
		assert (Initialized);

		if (!SetEvent (SystemSyncEvent))
			throw SystemException (SRC_POS);
	}

	void SyncEvent::Wait ()
	{
		assert (Initialized);

		DWORD result = WaitForSingleObject (SystemSyncEvent, INFINITE);
		if (result == WAIT_FAILED)
			throw SystemException (SRC_POS);
	}
}
