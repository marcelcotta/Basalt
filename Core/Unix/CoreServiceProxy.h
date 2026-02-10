/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Core_Windows_CoreServiceProxy
#define TC_HEADER_Core_Windows_CoreServiceProxy

#include "CoreService.h"

namespace TrueCrypt
{
	template <class T>
	class CoreServiceProxy : public T
	{
	public:
		CoreServiceProxy () { }
		virtual ~CoreServiceProxy () { }

		virtual void CheckFilesystem (shared_ptr <VolumeInfo> mountedVolume, bool repair) const
		{
			CoreService::RequestCheckFilesystem (mountedVolume, repair);
		}

		virtual void DismountFilesystem (const DirectoryPath &mountPoint, bool force) const
		{
			CoreService::RequestDismountFilesystem (mountPoint, force);
		}

		virtual shared_ptr <VolumeInfo> DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles = false, bool syncVolumeInfo = false)
		{
			shared_ptr <VolumeInfo> dismountedVolumeInfo = CoreService::RequestDismountVolume (mountedVolume, ignoreOpenFiles, syncVolumeInfo);

			VolumeEventArgs eventArgs (dismountedVolumeInfo);
			T::VolumeDismountedEvent.Raise (eventArgs);

			return dismountedVolumeInfo;
		}

		virtual uint32 GetDeviceSectorSize (const DevicePath &devicePath) const
		{
			return CoreService::RequestGetDeviceSectorSize (devicePath);
		}

		virtual uint64 GetDeviceSize (const DevicePath &devicePath) const
		{
			return CoreService::RequestGetDeviceSize (devicePath);
		}

#ifndef TC_LINUX
		virtual HostDeviceList GetHostDevices (bool pathListOnly = false) const
		{
			if (pathListOnly)
				return T::GetHostDevices (pathListOnly);
			else
				return CoreService::RequestGetHostDevices (pathListOnly);
		}
#endif

		virtual shared_ptr <VolumeInfo> MountVolume (MountOptions &options)
		{
			shared_ptr <VolumeInfo> mountedVolume;

			MountOptions newOptions = options;

			newOptions.Password = Keyfile::ApplyListToPassword (options.Keyfiles, options.Password);
			if (newOptions.Keyfiles)
				newOptions.Keyfiles->clear();

			newOptions.ProtectionPassword = Keyfile::ApplyListToPassword (options.ProtectionKeyfiles, options.ProtectionPassword);
			if (newOptions.ProtectionKeyfiles)
				newOptions.ProtectionKeyfiles->clear();

			try
			{
				mountedVolume = CoreService::RequestMountVolume (newOptions);
			}
			catch (ProtectionPasswordIncorrect &e)
			{
				if (options.ProtectionKeyfiles && !options.ProtectionKeyfiles->empty())
					throw ProtectionPasswordKeyfilesIncorrect (e.what());
				throw;
			}
			catch (PasswordIncorrect &e)
			{
				if (options.Keyfiles && !options.Keyfiles->empty())
					throw PasswordKeyfilesIncorrect (e.what());
				throw;
			}

			VolumeEventArgs eventArgs (mountedVolume);
			T::VolumeMountedEvent.Raise (eventArgs);

			return mountedVolume;
		}

		virtual void SetAdminPasswordCallback (shared_ptr <GetStringFunctor> functor)
		{
			CoreService::SetAdminPasswordCallback (functor);
		}

		virtual void SetFileOwner (const FilesystemPath &path, const UserId &owner) const
		{
			CoreService::RequestSetFileOwner (path, owner);
		}
	};
}

#endif // TC_HEADER_Core_Windows_CoreServiceProxy
