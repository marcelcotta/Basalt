/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.

 Windows-specific FuseService implementation.
 Uses LamarckFUSE with an iSCSI target (127.0.0.1:3260) instead of VHD+NFS.
 The Windows iSCSI Initiator creates a real local block device that Windows
 can format and mount as a drive letter.
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

namespace Basalt
{
	// ---- iSCSI Block-I/O Wrappers (C-callable) ----
	// These bridge the C iSCSI target to the C++ FuseService crypto layer.

	extern "C" {
		int basalt_iscsi_read(void *ctx, uint8_t *buf, uint64_t offset, uint32_t len)
		{
			(void)ctx;
			try
			{
				FuseService::ReadVolumeSectors (BufferPtr (buf, len), offset);
				return 0;
			}
			catch (...)
			{
				return -1;
			}
		}

		int basalt_iscsi_write(void *ctx, const uint8_t *buf, uint64_t offset, uint32_t len)
		{
			(void)ctx;
			try
			{
				FuseService::WriteVolumeSectors (ConstBufferPtr (buf, len), offset);
				return 0;
			}
			catch (...)
			{
				return -1;
			}
		}

		uint64_t basalt_iscsi_get_size(void *ctx)
		{
			(void)ctx;
			try
			{
				return FuseService::GetVolumeSize();
			}
			catch (...)
			{
				return 0;
			}
		}

		uint32_t basalt_iscsi_get_sector_size(void *ctx)
		{
			(void)ctx;
			try
			{
				return (uint32_t)FuseService::GetVolumeSectorSize();
			}
			catch (...)
			{
				return 512;
			}
		}
	}

	// ---- FUSE callback implementations (init/destroy only) ----
	// The NFS file-serving callbacks (getattr, read, write, readdir, open) are
	// no longer needed — iSCSI serves data directly via block-level callbacks.

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
		// No longer used on Windows (iSCSI serves data directly).
		// Keep for API compatibility.
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
		// On Windows, LamarckFUSE now uses iSCSI:
		// 1. Starts iSCSI target on 127.0.0.1:<port> (port = 3260 + slot - 1)
		// 2. Windows iSCSI Initiator connects and creates a block device
		// 3. Drive letter assigned to the iSCSI disk
		//
		// fuse_main() is non-blocking — returns after mount completes.
		// The iSCSI server runs on a background thread.

		MountedVolume = openVolume;
		SlotNumber = slotNumber;
		OpenVolumeInfo.SerialInstanceNumber = (uint64) GetTickCount64();

		// Only init and destroy callbacks are needed — iSCSI bypasses FUSE file ops
		static struct fuse_operations fuse_service_oper = {};
		fuse_service_oper.init = fuse_service_init;
		fuse_service_oper.destroy = fuse_service_destroy;

		// Build argc/argv for fuse_main.
		// Port and IQN are derived from the drive letter automatically.
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
