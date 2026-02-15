/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Platform/SystemException.h"
#include "Platform/SystemInfo.h"

#include <windows.h>
#include <winternl.h>

namespace Basalt
{
	wstring SystemInfo::GetPlatformName ()
	{
		return L"Windows";
	}

	vector <int> SystemInfo::GetVersion ()
	{
		// Use RtlGetVersion via ntdll to get accurate version numbers
		// (GetVersionEx is deprecated and lies on Windows 10+)
		typedef LONG (WINAPI *RtlGetVersionFunc)(OSVERSIONINFOW *);

		vector <int> version;

		HMODULE ntdll = GetModuleHandleW (L"ntdll.dll");
		if (ntdll)
		{
			RtlGetVersionFunc rtlGetVersion = (RtlGetVersionFunc)
				GetProcAddress (ntdll, "RtlGetVersion");
			if (rtlGetVersion)
			{
				OSVERSIONINFOW osvi = {};
				osvi.dwOSVersionInfoSize = sizeof (osvi);

				if (rtlGetVersion (&osvi) == 0)
				{
					version.push_back ((int) osvi.dwMajorVersion);
					version.push_back ((int) osvi.dwMinorVersion);
					version.push_back ((int) osvi.dwBuildNumber);
					return version;
				}
			}
		}

		// Fallback: return 10.0.0
		version.push_back (10);
		version.push_back (0);
		version.push_back (0);
		return version;
	}

	bool SystemInfo::IsVersionAtLeast (int versionNumber1, int versionNumber2, int versionNumber3)
	{
		vector <int> osVersionNumbers = GetVersion();

		if (osVersionNumbers.size() < 2)
			throw ParameterIncorrect (SRC_POS);

		if (osVersionNumbers.size() < 3)
			osVersionNumbers.push_back (0);

		return (osVersionNumbers[0] * 10000000 +  osVersionNumbers[1] * 10000 + osVersionNumbers[2]) >=
			(versionNumber1 * 10000000 +  versionNumber2 * 10000 + versionNumber3);
	}
}
