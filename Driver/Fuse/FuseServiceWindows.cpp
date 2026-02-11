/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.

 Windows-specific FuseService implementation.
 Uses LamarckFUSE (NFSv4 loopback) instead of native FUSE.
 On Windows, the NFS server provides decrypted volume sectors directly,
 and Windows NFS client mounts them as a drive letter.
*/

#ifdef TC_WINDOWS

#include <windows.h>
#include <errno.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "FuseService.h"
#include "Platform/FileStream.h"
#include "Platform/MemoryStream.h"
#include "Platform/Serializable.h"
#include "Platform/SystemLog.h"
#include "Volume/EncryptionThreadPool.h"
#include "Core/Core.h"

// LamarckFUSE C API
extern "C" {
#include "fuse.h"
}

namespace TrueCrypt
{
	// ---- FUSE callback implementations (shared with Unix) ----

	static int fuse_service_access (const char *path, int mask)
	{
		// On Windows, access control is handled by the NFS client.
		// Always allow access from localhost.
		return 0;
	}

	static void *fuse_service_init (struct fuse_conn_info *conn)
	{
		try
		{
			if (!EncryptionThreadPool::IsRunning())
				EncryptionThreadPool::Start();
		}
		catch (exception &e)
		{
			SystemLog::WriteException (e);
		}
		catch (...)
		{
			SystemLog::WriteException (UnknownException (SRC_POS));
		}

		return nullptr;
	}

	static void fuse_service_destroy (void *userdata)
	{
		try
		{
			FuseService::Dismount();
		}
		catch (exception &e)
		{
			SystemLog::WriteException (e);
		}
		catch (...)
		{
			SystemLog::WriteException (UnknownException (SRC_POS));
		}
	}

	static int fuse_service_getattr (const char *path, struct stat *statData)
	{
		try
		{
			memset (statData, 0, sizeof (*statData));

			statData->st_uid = 0;
			statData->st_gid = 0;
			statData->st_atime = (int64_t) time (NULL);
			statData->st_ctime = (int64_t) time (NULL);
			statData->st_mtime = (int64_t) time (NULL);

			if (strcmp (path, "/") == 0)
			{
				statData->st_mode = S_IFDIR | 0500;
				statData->st_nlink = 2;
			}
			else
			{
				if (strcmp (path, FuseService::GetVolumeImagePath()) == 0)
				{
					statData->st_mode = S_IFREG | 0600;
					statData->st_nlink = 1;
					statData->st_size = FuseService::GetVolumeSize();
				}
				else if (strcmp (path, FuseService::GetControlPath()) == 0)
				{
					statData->st_mode = S_IFREG | 0600;
					statData->st_nlink = 1;
					statData->st_size = FuseService::GetVolumeInfo()->Size();
				}
				else
				{
					return -ENOENT;
				}
			}
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return 0;
	}

	static int fuse_service_opendir (const char *path, struct fuse_file_info *fi)
	{
		if (strcmp (path, "/") != 0)
			return -ENOENT;
		return 0;
	}

	static int fuse_service_open (const char *path, struct fuse_file_info *fi)
	{
		if (strcmp (path, FuseService::GetVolumeImagePath()) == 0)
			return 0;

		if (strcmp (path, FuseService::GetControlPath()) == 0)
		{
			fi->direct_io = 1;
			return 0;
		}

		return -ENOENT;
	}

	static int fuse_service_read (const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
	{
		try
		{
			if (strcmp (path, FuseService::GetVolumeImagePath()) == 0)
			{
				try
				{
					if ((uint64) offset + size > FuseService::GetVolumeSize())
						size = (size_t) (FuseService::GetVolumeSize() - offset);

					size_t sectorSize = FuseService::GetVolumeSectorSize();
					if (size % sectorSize != 0 || offset % sectorSize != 0)
					{
						uint64 alignedOffset = offset - (offset % sectorSize);
						uint64 alignedSize = size + (offset % sectorSize);

						if (alignedSize % sectorSize != 0)
							alignedSize += sectorSize - (alignedSize % sectorSize);

						SecureBuffer alignedBuffer (alignedSize);
						FuseService::ReadVolumeSectors (alignedBuffer, alignedOffset);
						BufferPtr ((byte *) buf, size).CopyFrom (alignedBuffer.GetRange (offset % sectorSize, size));
					}
					else
					{
						FuseService::ReadVolumeSectors (BufferPtr ((byte *) buf, size), offset);
					}
				}
				catch (MissingVolumeData&)
				{
					return 0;
				}

				return (int) size;
			}

			if (strcmp (path, FuseService::GetControlPath()) == 0)
			{
				shared_ptr <Buffer> infoBuf = FuseService::GetVolumeInfo();
				BufferPtr outBuf ((byte *)buf, size);

				if (offset >= (off_t) infoBuf->Size())
					return 0;

				if (offset + size > infoBuf->Size())
					size = infoBuf->Size () - offset;

				outBuf.CopyFrom (infoBuf->GetRange (offset, size));
				return (int) size;
			}
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return -ENOENT;
	}

	static int fuse_service_readdir (const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
	{
		if (strcmp (path, "/") != 0)
			return -ENOENT;

		filler (buf, ".", NULL, 0);
		filler (buf, "..", NULL, 0);
		filler (buf, FuseService::GetVolumeImagePath() + 1, NULL, 0);
		filler (buf, FuseService::GetControlPath() + 1, NULL, 0);

		return 0;
	}

	static int fuse_service_write (const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
	{
		try
		{
			if (strcmp (path, FuseService::GetVolumeImagePath()) == 0)
			{
				FuseService::WriteVolumeSectors (BufferPtr ((byte *) buf, size), offset);
				return (int) size;
			}

			if (strcmp (path, FuseService::GetControlPath()) == 0)
			{
				if (FuseService::AuxDeviceInfoReceived())
					return -EACCES;

				FuseService::ReceiveAuxDeviceInfo (ConstBufferPtr ((const byte *)buf, size));
				return (int) size;
			}
		}
		catch (...)
		{
			return FuseService::ExceptionToErrorCode();
		}

		return -ENOENT;
	}

	// ---- FuseService methods ----

	void FuseService::CloseMountedVolume ()
	{
		if (MountedVolume)
		{
			if (MountedVolume->GetFile().use_count() > 1)
				MountedVolume->GetFile()->Close();

			if (MountedVolume.use_count() > 1)
				delete MountedVolume.get();

			MountedVolume.reset();
		}
	}

	void FuseService::Dismount ()
	{
		CloseMountedVolume();

		if (EncryptionThreadPool::IsRunning())
			EncryptionThreadPool::Stop();
	}

	int FuseService::ExceptionToErrorCode ()
	{
		try
		{
			throw;
		}
		catch (std::bad_alloc&)
		{
			return -ENOMEM;
		}
		catch (ParameterIncorrect &e)
		{
			SystemLog::WriteException (e);
			return -EINVAL;
		}
		catch (VolumeProtected&)
		{
			return -EPERM;
		}
		catch (VolumeReadOnly&)
		{
			return -EPERM;
		}
		catch (SystemException &e)
		{
			SystemLog::WriteException (e);
			return -EIO;
		}
		catch (std::exception &e)
		{
			SystemLog::WriteException (e);
			return -EIO;
		}
		catch (...)
		{
			SystemLog::WriteException (UnknownException (SRC_POS));
			return -EIO;
		}
	}

	shared_ptr <Buffer> FuseService::GetVolumeInfo ()
	{
		shared_ptr <Stream> stream (new MemoryStream);

		{
			ScopeLock lock (OpenVolumeInfoMutex);

			OpenVolumeInfo.Set (*MountedVolume);
			OpenVolumeInfo.SlotNumber = SlotNumber;

			OpenVolumeInfo.Serialize (stream);
		}

		ConstBufferPtr infoBuf = dynamic_cast <MemoryStream&> (*stream);
		shared_ptr <Buffer> outBuf (new Buffer (infoBuf.Size()));
		outBuf->CopyFrom (infoBuf);

		return outBuf;
	}

	const char *FuseService::GetVolumeImagePath ()
	{
		return "/volume";
	}

	uint64 FuseService::GetVolumeSize ()
	{
		if (!MountedVolume)
			throw NotInitialized (SRC_POS);

		return MountedVolume->GetSize();
	}

	void FuseService::Mount (shared_ptr <Volume> openVolume, VolumeSlotNumber slotNumber, const string &fuseMountPoint)
	{
		// On Windows, LamarckFUSE handles everything:
		// 1. Starts NFSv4 server on 127.0.0.1:2049
		// 2. fuse_main() blocks until the server exits
		//
		// We set up the FUSE callbacks, then call fuse_main() which runs on a background
		// thread (LamarckFUSE internally uses CreateThread, not fork).

		MountedVolume = openVolume;
		SlotNumber = slotNumber;
		OpenVolumeInfo.SerialInstanceNumber = (uint64) GetTickCount64();

		static struct fuse_operations fuse_service_oper = {};
		fuse_service_oper.access = fuse_service_access;
		fuse_service_oper.destroy = fuse_service_destroy;
		fuse_service_oper.getattr = fuse_service_getattr;
		fuse_service_oper.init = fuse_service_init;
		fuse_service_oper.open = fuse_service_open;
		fuse_service_oper.opendir = fuse_service_opendir;
		fuse_service_oper.read = fuse_service_read;
		fuse_service_oper.readdir = fuse_service_readdir;
		fuse_service_oper.write = fuse_service_write;

		// Build argc/argv for fuse_main
		// LamarckFUSE expects: device_type mount_point
		const char *argv[] = { "basalt", fuseMountPoint.c_str() };
		int argc = 2;

		int result = fuse_main (argc, const_cast <char**> (argv), &fuse_service_oper, NULL);
		if (result != 0)
			throw SystemException (SRC_POS, "LamarckFUSE fuse_main failed");
	}

	void FuseService::ReadVolumeSectors (const BufferPtr &buffer, uint64 byteOffset)
	{
		if (!MountedVolume)
			throw NotInitialized (SRC_POS);

		MountedVolume->ReadSectors (buffer, byteOffset);
	}

	void FuseService::ReceiveAuxDeviceInfo (const ConstBufferPtr &buffer)
	{
		shared_ptr <Stream> stream (new MemoryStream (buffer));
		Serializer sr (stream);

		ScopeLock lock (OpenVolumeInfoMutex);
		OpenVolumeInfo.VirtualDevice = sr.DeserializeString ("VirtualDevice");
		OpenVolumeInfo.LoopDevice = sr.DeserializeString ("LoopDevice");
	}

	void FuseService::SendAuxDeviceInfo (const DirectoryPath &fuseMountPoint, const DevicePath &virtualDevice, const DevicePath &loopDevice)
	{
		// On Windows, aux device info is stored in the in-memory volume list
		// via CoreWindows::MountVolume. No file/NFS write needed.
		ScopeLock lock (OpenVolumeInfoMutex);
		OpenVolumeInfo.VirtualDevice = virtualDevice;
		OpenVolumeInfo.LoopDevice = loopDevice;
	}

	void FuseService::WriteVolumeSectors (const ConstBufferPtr &buffer, uint64 byteOffset)
	{
		if (!MountedVolume)
			throw NotInitialized (SRC_POS);

		MountedVolume->WriteSectors (buffer, byteOffset);
	}

	VolumeInfo FuseService::OpenVolumeInfo;
	Mutex FuseService::OpenVolumeInfoMutex;
	shared_ptr <Volume> FuseService::MountedVolume;
	VolumeSlotNumber FuseService::SlotNumber;
}

#endif // TC_WINDOWS
