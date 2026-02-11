/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "CoreWindows.h"
#include <windows.h>
#include <winnetwk.h>
#include <shlobj.h>
#include "Platform/FileStream.h"
#include "Platform/Serializer.h"
#include "Driver/Fuse/FuseService.h"
#include "Core/Core.h"

namespace TrueCrypt
{
	CoreWindows::CoreWindows ()
	{
	}

	CoreWindows::~CoreWindows ()
	{
	}

	void CoreWindows::CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair) const
	{
		// On Windows, filesystem checking is done via chkdsk
		if (!mountedVolume->MountPoint.IsEmpty())
		{
			string driveLetter = StringConverter::ToSingle (wstring (mountedVolume->MountPoint));
			list <string> args;
			if (repair)
				args.push_back ("/F");
			args.push_back (driveLetter);

			try
			{
				Process::Execute ("chkdsk", args, 60000);
			}
			catch (...) { }
		}
	}

	void CoreWindows::DismountFilesystem (const DirectoryPath &mountPoint, bool force) const
	{
		// On Windows, unmounting is done via WNetCancelConnection2
		// The actual disconnect happens in DismountVolume
	}

	shared_ptr <VolumeInfo> CoreWindows::DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles, bool syncVolumeInfo)
	{
		// Disconnect the network drive (NFS mount)
		if (!mountedVolume->MountPoint.IsEmpty())
		{
			wstring driveLetter = mountedVolume->MountPoint;
			DWORD result = WNetCancelConnection2W (driveLetter.c_str(),
				0,  // dwFlags: 0 = don't update profile
				ignoreOpenFiles ? TRUE : FALSE);

			if (result != NO_ERROR && result != ERROR_NOT_CONNECTED)
			{
				if (!ignoreOpenFiles && (result == ERROR_OPEN_FILES || result == ERROR_DEVICE_IN_USE))
					throw MountedVolumeInUse (SRC_POS);

				// Try force disconnect
				WNetCancelConnection2W (driveLetter.c_str(), 0, TRUE);
			}
		}

		// Stop the FUSE/NFS server
		FuseService::Dismount ();

		// Remove from tracked list
		{
			ScopeLock lock (MountedVolumesMutex);
			MountedVolumeList.remove_if ([&](const shared_ptr <VolumeInfo> &v) {
				return wstring (v->Path) == wstring (mountedVolume->Path);
			});
		}

		VolumeEventArgs eventArgs (mountedVolume);
		VolumeDismountedEvent.Raise (eventArgs);

		return mountedVolume;
	}

	bool CoreWindows::FilesystemSupportsLargeFiles (const FilePath &filePath) const
	{
		// Check the filesystem type of the drive containing the file
		wstring path = filePath;
		wstring root;

		if (path.size() >= 2 && path[1] == L':')
			root = path.substr (0, 3);
		else
			root = L"C:\\";

		wchar_t fsName[MAX_PATH + 1] = {};
		if (GetVolumeInformationW (root.c_str(), NULL, 0, NULL, NULL, NULL, fsName, MAX_PATH))
		{
			wstring fs = fsName;
			// FAT/FAT32 has 4GB file size limit
			if (fs == L"FAT" || fs == L"FAT32")
				return false;
		}

		return true;  // NTFS, ReFS, exFAT all support large files
	}

	DirectoryPath CoreWindows::GetDeviceMountPoint (const DevicePath &devicePath) const
	{
		return DirectoryPath();
	}

	uint32 CoreWindows::GetDeviceSectorSize (const DevicePath &devicePath) const
	{
		File dev;
		dev.Open (devicePath);
		return dev.GetDeviceSectorSize();
	}

	uint64 CoreWindows::GetDeviceSize (const DevicePath &devicePath) const
	{
		File dev;
		dev.Open (devicePath);
		return dev.Length();
	}

	string CoreWindows::GetDefaultMountPointPrefix () const
	{
		return "Z:";
	}

	int CoreWindows::GetOSMajorVersion () const
	{
		vector <int> ver = SystemInfo::GetVersion();
		return ver.size() > 0 ? ver[0] : 10;
	}

	int CoreWindows::GetOSMinorVersion () const
	{
		vector <int> ver = SystemInfo::GetVersion();
		return ver.size() > 1 ? ver[1] : 0;
	}

	HostDeviceList CoreWindows::GetHostDevices (bool pathListOnly) const
	{
		HostDeviceList devices;

		// Enumerate physical drives (\\.\PhysicalDriveN)
		for (int i = 0; i < 32; i++)
		{
			stringstream path;
			path << "\\\\.\\PhysicalDrive" << i;

			HANDLE hDrive = CreateFileA (path.str().c_str(),
				0,  // No access needed for query
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				NULL, OPEN_EXISTING, 0, NULL);

			if (hDrive != INVALID_HANDLE_VALUE)
			{
				shared_ptr <HostDevice> device (new HostDevice);
				device->Path = StringConverter::ToWide (path.str());
				device->Removable = false;

				if (!pathListOnly)
				{
					DISK_GEOMETRY dg;
					DWORD bytesReturned;
					if (DeviceIoControl (hDrive, IOCTL_DISK_GET_DRIVE_GEOMETRY,
						NULL, 0, &dg, sizeof (dg), &bytesReturned, NULL))
					{
						device->Size = (uint64) dg.Cylinders.QuadPart * dg.TracksPerCylinder *
							dg.SectorsPerTrack * dg.BytesPerSector;
					}
				}

				devices.push_back (device);
				CloseHandle (hDrive);
			}
		}

		return devices;
	}

	VolumeInfoList CoreWindows::GetMountedVolumes (const VolumePath &volumePath) const
	{
		ScopeLock lock (MountedVolumesMutex);

		if (volumePath.IsEmpty())
			return MountedVolumeList;

		VolumeInfoList filtered;
		for (const auto &vol : MountedVolumeList)
		{
			if (wstring (vol->Path) == wstring (volumePath))
			{
				filtered.push_back (vol);
				break;
			}
		}

		return filtered;
	}

	bool CoreWindows::IsDevicePresent (const DevicePath &device) const
	{
		wstring path = device;
		HANDLE hDev = CreateFileW (path.c_str(), 0,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, 0, NULL);

		if (hDev != INVALID_HANDLE_VALUE)
		{
			CloseHandle (hDev);
			return true;
		}

		return false;
	}

	bool CoreWindows::IsMountPointAvailable (const DirectoryPath &mountPoint) const
	{
		wstring driveLetter = mountPoint;

		// Check if drive letter is already in use
		if (driveLetter.size() >= 2 && driveLetter[1] == L':')
		{
			DWORD drives = GetLogicalDrives();
			int driveIndex = toupper ((char) driveLetter[0]) - 'A';
			if (driveIndex >= 0 && driveIndex < 26)
				return !(drives & (1 << driveIndex));
		}

		return true;
	}

	bool CoreWindows::IsOSVersion (int major, int minor) const
	{
		return GetOSMajorVersion() == major && GetOSMinorVersion() == minor;
	}

	bool CoreWindows::IsOSVersionLower (int major, int minor) const
	{
		return (GetOSMajorVersion() < major) ||
			(GetOSMajorVersion() == major && GetOSMinorVersion() < minor);
	}

	VolumeSlotNumber CoreWindows::MountPointToSlotNumber (const DirectoryPath &mountPoint) const
	{
		wstring mp = mountPoint;
		if (mp.size() >= 1)
		{
			wchar_t letter = towupper (mp[0]);
			if (letter >= L'A' && letter <= L'Z')
				return (VolumeSlotNumber) (letter - L'A' + 1);
		}
		return GetFirstFreeSlotNumber();
	}

	shared_ptr <VolumeInfo> CoreWindows::MountVolume (MountOptions &options)
	{
		CoalesceSlotNumberAndMountPoint (options);

		if (IsVolumeMounted (*options.Path))
			throw VolumeAlreadyMounted (SRC_POS);

		Cipher::EnableHwSupport (!options.NoHardwareCrypto);

		// Step 1: Open and decrypt the volume (100% portable crypto code)
		shared_ptr <Volume> volume;
		while (true)
		{
			try
			{
				volume = OpenVolume (
					options.Path,
					options.PreserveTimestamps,
					options.Password,
					options.Keyfiles,
					options.Protection,
					options.ProtectionPassword,
					options.ProtectionKeyfiles,
					options.SharedAccessAllowed,
					VolumeType::Unknown,
					options.UseBackupHeaders,
					options.PartitionInSystemEncryptionScope);

				options.Password.reset();
			}
			catch (SystemException &e)
			{
				if (options.Protection != VolumeProtection::ReadOnly
					&& (e.GetErrorCode() == ERROR_ACCESS_DENIED || e.GetErrorCode() == ERROR_WRITE_PROTECT))
				{
					options.Protection = VolumeProtection::ReadOnly;
					continue;
				}
				throw;
			}
			break;
		}

		// Step 2: Determine drive letter
		wstring driveLetter;
		if (options.MountPoint && !options.MountPoint->IsEmpty())
		{
			driveLetter = *options.MountPoint;
		}
		else
		{
			// Find first free drive letter, Z: downwards
			DWORD drives = GetLogicalDrives();
			for (int i = 25; i >= 3; i--)  // Z=25 down to D=3
			{
				if (!(drives & (1 << i)))
				{
					wchar_t letter = L'A' + (wchar_t) i;
					driveLetter = wstring (1, letter) + L":";
					break;
				}
			}
			if (driveLetter.empty())
				throw ParameterIncorrect (SRC_POS);  // No free drive letter
		}

		// Step 3: Start LamarckFUSE (NFSv4 server serving decrypted sectors)
		string fuseMountPoint = StringConverter::ToSingle (driveLetter);
		FuseService::Mount (volume, options.SlotNumber, fuseMountPoint);

		// Step 4: Connect Windows NFS client to the LamarckFUSE server
		try
		{
			NETRESOURCEW nr = {};
			nr.dwType = RESOURCETYPE_DISK;
			nr.lpLocalName = const_cast <wchar_t*> (driveLetter.c_str());
			nr.lpRemoteName = const_cast <wchar_t*> (L"\\\\127.0.0.1\\basalt");
			nr.lpProvider = NULL;

			DWORD result = WNetAddConnection2W (&nr, NULL, NULL, 0);
			if (result != NO_ERROR)
			{
				// Cleanup: stop the NFS server
				FuseService::Dismount();
				SetLastError (result);
				throw SystemException (SRC_POS, driveLetter);
			}
		}
		catch (...)
		{
			FuseService::Dismount();
			throw;
		}

		// Step 5: Build and track VolumeInfo
		shared_ptr <VolumeInfo> mountedVolume (new VolumeInfo);
		mountedVolume->Path = *options.Path;
		mountedVolume->MountPoint = DirectoryPath (driveLetter);
		mountedVolume->SlotNumber = options.SlotNumber ? options.SlotNumber : MountPointToSlotNumber (driveLetter);
		mountedVolume->Size = volume->GetSize();
		mountedVolume->Type = volume->GetType();
		mountedVolume->Protection = options.Protection;
		mountedVolume->EncryptionAlgorithmName = volume->GetEncryptionAlgorithm()->GetName();
		mountedVolume->Pkcs5PrfName = volume->GetPkcs5Kdf()->GetName();

		{
			ScopeLock lock (MountedVolumesMutex);
			MountedVolumeList.push_back (mountedVolume);
		}

		VolumeEventArgs eventArgs (mountedVolume);
		VolumeMountedEvent.Raise (eventArgs);

		return mountedVolume;
	}

	void CoreWindows::SetFileOwner (const FilesystemPath &path, const UserId &owner) const
	{
		// Windows uses ACLs, not UID-based ownership.
		// This is a no-op for Windows.
	}

	DirectoryPath CoreWindows::SlotNumberToMountPoint (VolumeSlotNumber slotNumber) const
	{
		if (slotNumber < 1 || slotNumber > 26)
			throw ParameterIncorrect (SRC_POS);

		wchar_t letter = L'A' + (wchar_t) (slotNumber - 1);
		return wstring (1, letter) + L":";
	}

	// Global Core singletons — Windows does not need CoreServiceProxy
	shared_ptr <CoreBase> Core (new CoreWindows);
	shared_ptr <CoreBase> CoreDirect (new CoreWindows);
}
