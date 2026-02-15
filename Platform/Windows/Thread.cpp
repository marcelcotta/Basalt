/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Platform/SystemException.h"
#include "Platform/Thread.h"
#include "Platform/SystemLog.h"

namespace Basalt
{
	void Thread::Join () const
	{
		DWORD result = WaitForSingleObject (SystemHandle, INFINITE);
		if (result == WAIT_FAILED)
			throw SystemException (SRC_POS);
	}

	void Thread::Start (ThreadProcPtr threadProc, void *parameter)
	{
		SystemHandle = CreateThread (NULL, MinThreadStackSize, threadProc, parameter, 0, NULL);
		if (SystemHandle == NULL)
			throw SystemException (SRC_POS);
	}

	void Thread::Sleep (uint32 milliSeconds)
	{
		::Sleep ((DWORD) milliSeconds);
	}
}
