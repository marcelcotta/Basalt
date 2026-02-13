/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "CoreWindows.h"
#include <windows.h>
#include <shlobj.h>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <tlhelp32.h>
#include "Platform/FileStream.h"
#include "Platform/Serializer.h"
#include "Platform/SystemInfo.h"
#include "Platform/Windows/Process.h"
#include "Driver/Fuse/FuseService.h"
#include "Core/Core.h"

// LamarckFUSE C API (for fuse_teardown)
extern "C" {
#include "fuse.h"
}

namespace TrueCrypt
{
	// ---- Mount Registry ----
	// Cross-process volume discovery via %LOCALAPPDATA%/Basalt/mounts/
	// Each mounted volume writes a slot_N.info file with key=value metadata.
	// basalt-cli --list reads all files and checks PID liveness.

	static string GetMountRegistryDir ()
	{
		char localAppData[MAX_PATH] = {};
		if (SHGetFolderPathA (NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData) != S_OK)
			return "";

		string dir = string (localAppData) + "\\Basalt\\mounts";

		// Create directory hierarchy if needed
		CreateDirectoryA ((string (localAppData) + "\\Basalt").c_str(), NULL);
		CreateDirectoryA (dir.c_str(), NULL);

		return dir;
	}

	static string GetSlotInfoPath (VolumeSlotNumber slot)
	{
		string dir = GetMountRegistryDir ();
		if (dir.empty ())
			return "";

		char filename[64];
		snprintf (filename, sizeof(filename), "\\slot_%u.info", (unsigned)slot);
		return dir + filename;
	}

	static bool IsProcessAlive (DWORD pid)
	{
		if (pid == 0)
			return false;

		HANDLE hProcess = OpenProcess (PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (hProcess == NULL)
			return false;

		DWORD exitCode = 0;
		BOOL ok = GetExitCodeProcess (hProcess, &exitCode);
		CloseHandle (hProcess);

		return ok && exitCode == STILL_ACTIVE;
	}

	static void WriteSlotInfo (VolumeSlotNumber slot, shared_ptr <VolumeInfo> vol)
	{
		string path = GetSlotInfoPath (slot);
		if (path.empty ())
			return;

		std::ofstream f (path);
		if (!f.is_open ())
			return;

		f << "pid=" << GetCurrentProcessId () << "\n";
		f << "slot=" << vol->SlotNumber << "\n";
		f << "path=" << StringConverter::ToSingle (wstring (vol->Path)) << "\n";
		f << "mountpoint=" << StringConverter::ToSingle (wstring (vol->MountPoint)) << "\n";
		f << "size=" << vol->Size << "\n";
		f << "type=" << (int)vol->Type << "\n";
		f << "protection=" << (int)vol->Protection << "\n";
		f << "encryption=" << StringConverter::ToSingle (vol->EncryptionAlgorithmName) << "\n";
		f << "encmode=" << StringConverter::ToSingle (vol->EncryptionModeName) << "\n";
		f << "pkcs5=" << StringConverter::ToSingle (vol->Pkcs5PrfName) << "\n";
		f << "pkcs5iterations=" << vol->Pkcs5IterationCount << "\n";
		f << "keysize=" << vol->EncryptionAlgorithmKeySize << "\n";

		f.close ();
	}

	static void RemoveSlotInfo (VolumeSlotNumber slot)
	{
		string path = GetSlotInfoPath (slot);
		if (!path.empty ())
			DeleteFileA (path.c_str ());
	}

	static shared_ptr <VolumeInfo> ReadSlotInfo (const string &filePath)
	{
		std::ifstream f (filePath);
		if (!f.is_open ())
			return shared_ptr <VolumeInfo> ();

		// Parse key=value pairs
		DWORD pid = 0;
		shared_ptr <VolumeInfo> vol (new VolumeInfo);
		string line;

		while (std::getline (f, line))
		{
			size_t eq = line.find ('=');
			if (eq == string::npos)
				continue;

			string key = line.substr (0, eq);
			string value = line.substr (eq + 1);

			if (key == "pid")
				pid = (DWORD)atoi (value.c_str ());
			else if (key == "slot")
				vol->SlotNumber = (VolumeSlotNumber)atoi (value.c_str ());
			else if (key == "path")
				vol->Path = VolumePath (StringConverter::ToWide (value));
			else if (key == "mountpoint")
				vol->MountPoint = DirectoryPath (StringConverter::ToWide (value));
			else if (key == "size")
				vol->Size = (uint64)strtoull (value.c_str (), nullptr, 10);
			else if (key == "type")
				vol->Type = (VolumeType::Enum)atoi (value.c_str ());
			else if (key == "protection")
				vol->Protection = (VolumeProtection::Enum)atoi (value.c_str ());
			else if (key == "encryption")
				vol->EncryptionAlgorithmName = StringConverter::ToWide (value);
			else if (key == "encmode")
				vol->EncryptionModeName = StringConverter::ToWide (value);
			else if (key == "pkcs5")
				vol->Pkcs5PrfName = StringConverter::ToWide (value);
			else if (key == "pkcs5iterations")
				vol->Pkcs5IterationCount = (uint32)atoi (value.c_str ());
			else if (key == "keysize")
				vol->EncryptionAlgorithmKeySize = (uint32)atoi (value.c_str ());
		}

		f.close ();

		// Check if the owning process is still alive
		if (!IsProcessAlive (pid))
		{
			// Stale mount info — remove it
			DeleteFileA (filePath.c_str ());
			return shared_ptr <VolumeInfo> ();
		}

		return vol;
	}

	// ---- CoreWindows implementation ----

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
		// On Windows, unmounting is done via iSCSI logout + fuse_teardown
		// The actual disconnect happens in DismountVolume
	}

	shared_ptr <VolumeInfo> CoreWindows::DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles, bool syncVolumeInfo)
	{
		// Check if this volume is owned by our process (in-process list)
		// or by another process (cross-process via mount registry).
		bool isOwnVolume = false;
		{
			ScopeLock lock (MountedVolumesMutex);
			for (const auto &v : MountedVolumeList)
			{
				if (wstring (v->Path) == wstring (mountedVolume->Path))
				{
					isOwnVolume = true;
					break;
				}
			}
		}

		if (isOwnVolume)
		{
			// In-process dismount: use fuse_teardown() for the complete sequence
			// (remove drive letter, logout iSCSI, stop server, destroy crypto)
			if (!mountedVolume->MountPoint.IsEmpty())
			{
				string mp = StringConverter::ToSingle (wstring (mountedVolume->MountPoint));
				fuse_teardown (mp.c_str());
			}
			else
			{
				FuseService::Dismount ();
			}

			// Remove from mount registry
			if (mountedVolume->SlotNumber > 0)
				RemoveSlotInfo (mountedVolume->SlotNumber);

			// Remove from in-process tracked list
			{
				ScopeLock lock (MountedVolumesMutex);
				MountedVolumeList.remove_if ([&](const shared_ptr <VolumeInfo> &v) {
					return wstring (v->Path) == wstring (mountedVolume->Path);
				});
			}
		}
		else
		{
			// Cross-process dismount: signal the owning process via named event.
			// The owner waits on Global\BasaltDismount_SlotN and will perform
			// the actual teardown when signaled.
			if (mountedVolume->SlotNumber > 0)
			{
				char eventName[64];
				snprintf (eventName, sizeof(eventName), "Global\\BasaltDismount_Slot%u",
				          (unsigned)mountedVolume->SlotNumber);
				HANDLE hEvent = OpenEventA (EVENT_MODIFY_STATE, FALSE, eventName);
				if (hEvent)
				{
					SetEvent (hEvent);
					CloseHandle (hEvent);

					// Wait for the owning process to finish dismount
					// (the slot info file will be removed when it's done)
					for (int i = 0; i < 30; i++)
					{
						Sleep (500);
						string slotPath = GetSlotInfoPath (mountedVolume->SlotNumber);
						if (slotPath.empty () || GetFileAttributesA (slotPath.c_str ()) == INVALID_FILE_ATTRIBUTES)
							break;  // Slot info removed — dismount complete
					}
				}
			}
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
		VolumeInfoList volumes;

		// Read from shared mount registry (cross-process discovery).
		// Each running basalt-cli writes a slot_N.info file;
		// stale files from dead processes are automatically cleaned up.
		string registryDir = GetMountRegistryDir ();
		if (!registryDir.empty ())
		{
			WIN32_FIND_DATAA fd;
			string pattern = registryDir + "\\slot_*.info";
			HANDLE hFind = FindFirstFileA (pattern.c_str (), &fd);

			if (hFind != INVALID_HANDLE_VALUE)
			{
				do
				{
					string filePath = registryDir + "\\" + fd.cFileName;
					shared_ptr <VolumeInfo> vol = ReadSlotInfo (filePath);

					if (vol)
					{
						if (volumePath.IsEmpty () ||
							wstring (vol->Path) == wstring (volumePath))
						{
							volumes.push_back (vol);
						}
					}
				}
				while (FindNextFileA (hFind, &fd));

				FindClose (hFind);
			}
		}

		// Also include volumes from our in-process list (the current mount,
		// in case registry write failed or the volume was just mounted)
		{
			ScopeLock lock (MountedVolumesMutex);
			for (const auto &vol : MountedVolumeList)
			{
				// Skip if already found in registry
				bool found = false;
				for (const auto &existing : volumes)
				{
					if (existing->SlotNumber == vol->SlotNumber)
					{
						found = true;
						break;
					}
				}
				if (!found)
				{
					if (volumePath.IsEmpty () ||
						wstring (vol->Path) == wstring (volumePath))
					{
						volumes.push_back (vol);
					}
				}
			}
		}

		return volumes;
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
			{
				bool inUse = (drives & (1 << driveIndex)) != 0;
				return !inUse;
			}
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

		// Step 3: Start LamarckFUSE iSCSI target
		// Each volume gets a unique port: 3260 + (slot - 1)
		// and a unique IQN: iqn.2025-01.org.basalt:vol{slot}
		string fuseMountPoint = StringConverter::ToSingle (driveLetter);
		FuseService::Mount (volume, options.SlotNumber, fuseMountPoint);

		// Step 4: Build and track VolumeInfo
		shared_ptr <VolumeInfo> mountedVolume (new VolumeInfo);
		mountedVolume->Path = *options.Path;
		mountedVolume->MountPoint = DirectoryPath (driveLetter);
		mountedVolume->SlotNumber = options.SlotNumber ? options.SlotNumber : MountPointToSlotNumber (driveLetter);
		mountedVolume->Size = volume->GetSize();
		mountedVolume->Type = volume->GetType();
		mountedVolume->Protection = options.Protection;
		mountedVolume->EncryptionAlgorithmName = volume->GetEncryptionAlgorithm()->GetName();
		mountedVolume->EncryptionAlgorithmKeySize = static_cast<uint32> (volume->GetEncryptionAlgorithm()->GetKeySize());
		mountedVolume->EncryptionModeName = volume->GetEncryptionMode()->GetName();
		mountedVolume->Pkcs5PrfName = volume->GetPkcs5Kdf()->GetName();
		mountedVolume->Pkcs5IterationCount = volume->GetPkcs5Kdf()->GetIterationCount();

		{
			ScopeLock lock (MountedVolumesMutex);
			MountedVolumeList.push_back (mountedVolume);
		}

		// Write mount info to shared registry (for cross-process discovery)
		WriteSlotInfo (mountedVolume->SlotNumber, mountedVolume);

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
