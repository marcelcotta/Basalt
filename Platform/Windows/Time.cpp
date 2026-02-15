/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Platform/Time.h"
#include <windows.h>

namespace Basalt
{
	uint64 Time::GetCurrent ()
	{
		// Returns time in hundreds of nanoseconds since 1601/01/01
		// This is the native FILETIME format on Windows — no conversion needed.
		FILETIME ft;
		GetSystemTimeAsFileTime (&ft);

		ULARGE_INTEGER li;
		li.LowPart = ft.dwLowDateTime;
		li.HighPart = ft.dwHighDateTime;
		return (uint64) li.QuadPart;
	}
}
