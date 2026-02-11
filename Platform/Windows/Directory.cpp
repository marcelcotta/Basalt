/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <windows.h>
#include "Platform/Directory.h"
#include "Platform/Finally.h"
#include "Platform/SystemException.h"

namespace TrueCrypt
{
	void Directory::Create (const DirectoryPath &path)
	{
		wstring p = path;
		throw_sys_sub_if (!CreateDirectoryW (p.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS, p);
	}

	DirectoryPath Directory::AppendSeparator (const DirectoryPath &path)
	{
		wstring p (path);

		if (p.find_last_of (L'\\') + 1 != p.size() && p.find_last_of (L'/') + 1 != p.size())
			return p + L'\\';

		return p;
	}

	FilePathList Directory::GetFilePaths (const DirectoryPath &path, bool regularFilesOnly)
	{
		wstring searchPattern = wstring (AppendSeparator (path)) + L"*";

		WIN32_FIND_DATAW findData;
		HANDLE findHandle = FindFirstFileW (searchPattern.c_str(), &findData);
		throw_sys_sub_if (findHandle == INVALID_HANDLE_VALUE, wstring (path));
		finally_do_arg (HANDLE, findHandle, { FindClose (finally_arg); });

		FilePathList files;
		do
		{
			wstring name = findData.cFileName;
			if (name == L"." || name == L"..")
				continue;

			shared_ptr <FilePath> filePath (new FilePath (wstring (AppendSeparator (path)) + name));

			if (!regularFilesOnly || !(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				files.push_back (filePath);

		} while (FindNextFileW (findHandle, &findData));

		DWORD err = GetLastError();
		if (err != ERROR_NO_MORE_FILES)
		{
			SetLastError (err);
			throw SystemException (SRC_POS, wstring (path));
		}

		return files;
	}
}
