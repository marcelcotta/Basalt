/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <windows.h>
#include "Platform/FilesystemPath.h"
#include "Platform/SystemException.h"
#include "Platform/StringConverter.h"

namespace TrueCrypt
{
	void FilesystemPath::Delete () const
	{
		wstring p = StringConverter::ToWide (StringConverter::ToSingle (Path));
		DWORD attrs = GetFileAttributesW (p.c_str());

		if (attrs == INVALID_FILE_ATTRIBUTES)
			throw SystemException (SRC_POS, Path);

		if (attrs & FILE_ATTRIBUTE_DIRECTORY)
			throw_sys_sub_if (!RemoveDirectoryW (p.c_str()), Path);
		else
			throw_sys_sub_if (!DeleteFileW (p.c_str()), Path);
	}

	UserId FilesystemPath::GetOwner () const
	{
		// Windows does not have simple UID-based ownership.
		// Return a dummy owner — ACLs are used instead.
		UserId owner;
		owner.SystemId = 0;
		return owner;
	}

	FilesystemPathType::Enum FilesystemPath::GetType () const
	{
		wstring path = Path;

		// Strip trailing separator
		while (path.size() > 1 && (path.back() == L'\\' || path.back() == L'/'))
			path.pop_back();

		DWORD attrs = GetFileAttributesW (path.c_str());
		if (attrs == INVALID_FILE_ATTRIBUTES)
			throw SystemException (SRC_POS, Path);

		if (attrs & FILE_ATTRIBUTE_DIRECTORY)
			return FilesystemPathType::Directory;

		if (attrs & FILE_ATTRIBUTE_REPARSE_POINT)
			return FilesystemPathType::SymbolickLink;

		// Check if it's a device path (\\.\PhysicalDriveN or \\.\X:)
		string pathSingle = StringConverter::ToSingle (path);
		if (pathSingle.find ("\\\\.\\") == 0)
			return FilesystemPathType::BlockDevice;

		return FilesystemPathType::File;
	}

	FilesystemPath FilesystemPath::ToBaseName () const
	{
		wstring path = Path;
		size_t pos = path.find_last_of (L"\\/");

		if (pos == string::npos)
			return Path;

		return Path.substr (pos + 1);
	}

	FilesystemPath FilesystemPath::ToHostDriveOfPartition () const
	{
		// On Windows, partition paths like \\.\HarddiskVolumeN don't have a simple
		// mapping to the physical drive. For now, throw NotImplemented — we only
		// support file-based volumes initially.
		throw NotImplemented (SRC_POS);
	}
}
