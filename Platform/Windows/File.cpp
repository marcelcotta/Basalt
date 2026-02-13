/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <windows.h>
#include <winioctl.h>
#include "Platform/File.h"
#include "Platform/TextReader.h"

namespace TrueCrypt
{
	void File::Close ()
	{
		if_debug (ValidateState());

		if (!SharedHandle)
		{
			CloseHandle (FileHandle);
			FileHandle = INVALID_HANDLE_VALUE;
			FileIsOpen = false;
		}
	}

	void File::Delete ()
	{
		Close();
		Path.Delete();
	}

	void File::Flush () const
	{
		if_debug (ValidateState());
		throw_sys_sub_if (!FlushFileBuffers (FileHandle), wstring (Path));
	}

	uint32 File::GetDeviceSectorSize () const
	{
		if (Path.IsDevice())
		{
			DISK_GEOMETRY dg;
			DWORD bytesReturned;
			throw_sys_sub_if (!DeviceIoControl (FileHandle, IOCTL_DISK_GET_DRIVE_GEOMETRY,
				NULL, 0, &dg, sizeof (dg), &bytesReturned, NULL), wstring (Path));
			return (uint32) dg.BytesPerSector;
		}
		else
			throw ParameterIncorrect (SRC_POS);
	}

	uint64 File::GetPartitionDeviceStartOffset () const
	{
		PARTITION_INFORMATION_EX partInfo;
		DWORD bytesReturned;

		if (DeviceIoControl (FileHandle, IOCTL_DISK_GET_PARTITION_INFO_EX,
			NULL, 0, &partInfo, sizeof (partInfo), &bytesReturned, NULL))
		{
			return (uint64) partInfo.StartingOffset.QuadPart;
		}

		throw NotImplemented (SRC_POS);
	}

	uint64 File::Length () const
	{
		if_debug (ValidateState());

		if (Path.IsDevice())
		{
			DISK_GEOMETRY dg;
			DWORD bytesReturned;

			if (DeviceIoControl (FileHandle, IOCTL_DISK_GET_DRIVE_GEOMETRY,
				NULL, 0, &dg, sizeof (dg), &bytesReturned, NULL))
			{
				return (uint64) dg.Cylinders.QuadPart * dg.TracksPerCylinder *
					dg.SectorsPerTrack * dg.BytesPerSector;
			}

			// Try GET_LENGTH_INFO for partitions
			GET_LENGTH_INFORMATION lengthInfo;
			if (DeviceIoControl (FileHandle, IOCTL_DISK_GET_LENGTH_INFO,
				NULL, 0, &lengthInfo, sizeof (lengthInfo), &bytesReturned, NULL))
			{
				return (uint64) lengthInfo.Length.QuadPart;
			}

			throw SystemException (SRC_POS, wstring (Path));
		}

		LARGE_INTEGER size;
		throw_sys_sub_if (!GetFileSizeEx (FileHandle, &size), wstring (Path));
		return (uint64) size.QuadPart;
	}

	void File::Open (const FilePath &path, FileOpenMode mode, FileShareMode shareMode, FileOpenFlags flags)
	{
		DWORD desiredAccess = 0;
		DWORD creationDisposition = 0;
		DWORD shareFlags = 0;
		DWORD flagsAndAttributes = FILE_ATTRIBUTE_NORMAL;

		switch (mode)
		{
		case CreateReadWrite:
			desiredAccess = GENERIC_READ | GENERIC_WRITE;
			creationDisposition = CREATE_ALWAYS;
			break;

		case CreateWrite:
			desiredAccess = GENERIC_WRITE;
			creationDisposition = CREATE_ALWAYS;
			break;

		case OpenRead:
			desiredAccess = GENERIC_READ;
			creationDisposition = OPEN_EXISTING;
			break;

		case OpenWrite:
			desiredAccess = GENERIC_WRITE;
			creationDisposition = OPEN_EXISTING;
			break;

		case OpenReadWrite:
			desiredAccess = GENERIC_READ | GENERIC_WRITE;
			creationDisposition = OPEN_EXISTING;
			break;

		default:
			throw ParameterIncorrect (SRC_POS);
		}

		switch (shareMode)
		{
		case ShareNone:
			shareFlags = 0;
			break;

		case ShareRead:
			shareFlags = FILE_SHARE_READ;
			break;

		case ShareReadWrite:
		case ShareReadWriteIgnoreLock:
			shareFlags = FILE_SHARE_READ | FILE_SHARE_WRITE;
			break;

		default:
			throw ParameterIncorrect (SRC_POS);
		}

		if (flags & File::DisableWriteCaching)
			flagsAndAttributes |= FILE_FLAG_WRITE_THROUGH;

		wstring wPath = path;

		// Convert relative paths to absolute (avoids ambiguous errors on Windows)
		if (!wPath.empty() && wPath[0] != L'\\' && (wPath.size() < 2 || wPath[1] != L':'))
		{
			wchar_t absPath[MAX_PATH];
			DWORD len = GetFullPathNameW (wPath.c_str(), MAX_PATH, absPath, NULL);
			if (len > 0 && len < MAX_PATH)
				wPath = absPath;
		}

		FileHandle = CreateFileW (wPath.c_str(), desiredAccess, shareFlags,
			NULL, creationDisposition, flagsAndAttributes, NULL);
		throw_sys_sub_if (FileHandle == INVALID_HANDLE_VALUE, wPath);

		Path = path;
		mFileOpenFlags = flags;
		FileIsOpen = true;
	}

	uint64 File::Read (const BufferPtr &buffer) const
	{
		if_debug (ValidateState());

		DWORD bytesRead;
		throw_sys_sub_if (!ReadFile (FileHandle, buffer, (DWORD) buffer.Size(), &bytesRead, NULL), wstring (Path));

		return bytesRead;
	}

	uint64 File::ReadAt (const BufferPtr &buffer, uint64 position) const
	{
		if_debug (ValidateState());

		OVERLAPPED overlapped = {};
		overlapped.Offset = (DWORD) (position & 0xFFFFFFFF);
		overlapped.OffsetHigh = (DWORD) (position >> 32);

		DWORD bytesRead;
		throw_sys_sub_if (!ReadFile (FileHandle, buffer, (DWORD) buffer.Size(), &bytesRead, &overlapped), wstring (Path));

		return bytesRead;
	}

	void File::SeekAt (uint64 position) const
	{
		if_debug (ValidateState());

		LARGE_INTEGER pos;
		pos.QuadPart = (LONGLONG) position;
		throw_sys_sub_if (!SetFilePointerEx (FileHandle, pos, NULL, FILE_BEGIN), wstring (Path));
	}

	void File::SeekEnd (int offset) const
	{
		if_debug (ValidateState());

		LARGE_INTEGER pos;
		pos.QuadPart = (LONGLONG) offset;
		throw_sys_sub_if (!SetFilePointerEx (FileHandle, pos, NULL, FILE_END), wstring (Path));
	}

	void File::Write (const ConstBufferPtr &buffer) const
	{
		if_debug (ValidateState());

		DWORD bytesWritten;
		throw_sys_sub_if (!WriteFile (FileHandle, buffer, (DWORD) buffer.Size(), &bytesWritten, NULL), wstring (Path));
		throw_sys_sub_if (bytesWritten != (DWORD) buffer.Size(), wstring (Path));
	}

	void File::WriteAt (const ConstBufferPtr &buffer, uint64 position) const
	{
		if_debug (ValidateState());

		OVERLAPPED overlapped = {};
		overlapped.Offset = (DWORD) (position & 0xFFFFFFFF);
		overlapped.OffsetHigh = (DWORD) (position >> 32);

		DWORD bytesWritten;
		throw_sys_sub_if (!WriteFile (FileHandle, buffer, (DWORD) buffer.Size(), &bytesWritten, &overlapped), wstring (Path));
		throw_sys_sub_if (bytesWritten != (DWORD) buffer.Size(), wstring (Path));
	}
}
