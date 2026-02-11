/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <windows.h>
#include "Platform/SystemLog.h"

namespace TrueCrypt
{
	void SystemLog::WriteDebug (const string &debugMessage)
	{
		string msg = "basalt: " + debugMessage + "\n";
		OutputDebugStringA (msg.c_str());
	}

	void SystemLog::WriteError (const string &errorMessage)
	{
		string msg = "basalt: ERROR: " + errorMessage + "\n";
		OutputDebugStringA (msg.c_str());
	}
}
