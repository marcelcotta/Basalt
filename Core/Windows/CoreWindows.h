/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Core_CoreWindows
#define TC_HEADER_Core_CoreWindows

#include "Core/CoreBase.h"

namespace TrueCrypt
{
	class CoreWindows : public CoreBase
	{
	public:
		CoreWindows ();
		virtual ~CoreWindows ();

		virtual void CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair = false) const;
		virtual void DismountFilesystem (const DirectoryPath &mountPoint, bool force) const;
		virtual shared_ptr <VolumeInfo> DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles = false, bool syncVolumeInfo = false);
		virtual bool FilesystemSupportsLargeFiles (const FilePath &filePath) const;
		virtual DirectoryPath GetDeviceMountPoint (const DevicePath &devicePath) const;
		virtual uint32 GetDeviceSectorSize (const DevicePath &devicePath) const;
		virtual uint64 GetDeviceSize (const DevicePath &devicePath) const;
		virtual int GetOSMajorVersion () const;
		virtual int GetOSMinorVersion () const;
		virtual HostDeviceList GetHostDevices (bool pathListOnly = false) const;
		virtual VolumeInfoList GetMountedVolumes (const VolumePath &volumePath = VolumePath()) const;
		virtual bool HasAdminPrivileges () const { return false; }  // No UAC needed
		virtual bool IsDevicePresent (const DevicePath &device) const;
		virtual bool IsInPortableMode () const { return false; }
		virtual bool IsMountPointAvailable (const DirectoryPath &mountPoint) const;
		virtual bool IsOSVersion (int major, int minor) const;
		virtual bool IsOSVersionLower (int major, int minor) const;
		virtual VolumeSlotNumber MountPointToSlotNumber (const DirectoryPath &mountPoint) const;
		virtual shared_ptr <VolumeInfo> MountVolume (MountOptions &options);
		virtual void SetFileOwner (const FilesystemPath &path, const UserId &owner) const;
		virtual DirectoryPath SlotNumberToMountPoint (VolumeSlotNumber slotNumber) const;

	protected:
		virtual string GetDefaultMountPointPrefix () const;

		// Mounted volumes are tracked in-memory (no /proc/mounts equivalent)
		mutable VolumeInfoList MountedVolumeList;
		mutable Mutex MountedVolumesMutex;

	private:
		CoreWindows (const CoreWindows &);
		CoreWindows &operator= (const CoreWindows &);
	};
}

#endif // TC_HEADER_Core_CoreWindows
