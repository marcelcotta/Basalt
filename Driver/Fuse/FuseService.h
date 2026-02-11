/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Driver_Fuse_FuseService
#define TC_HEADER_Driver_Fuse_FuseService

#include "Platform/Platform.h"
#ifndef TC_WINDOWS
#include "Platform/Unix/Pipe.h"
#include "Platform/Unix/Process.h"
#endif
#include "Volume/VolumeInfo.h"
#include "Volume/Volume.h"

namespace TrueCrypt
{

	class FuseService
	{
#ifndef TC_WINDOWS
	protected:
		struct ExecFunctor : public ProcessExecFunctor
		{
			ExecFunctor (shared_ptr <Volume> openVolume, VolumeSlotNumber slotNumber)
				: MountedVolume (openVolume), SlotNumber (slotNumber)
			{
			}
			virtual void operator() (int argc, char *argv[]);

		protected:
			shared_ptr <Volume> MountedVolume;
			VolumeSlotNumber SlotNumber;
		};

		friend class ExecFunctor;
#endif

	public:
		static bool AuxDeviceInfoReceived () { return !OpenVolumeInfo.VirtualDevice.IsEmpty(); }
#ifndef TC_WINDOWS
		static bool CheckAccessRights ();
#endif
		static void Dismount ();
		static int ExceptionToErrorCode ();
		static const char *GetControlPath () { return "/control"; }
		static const char *GetVolumeImagePath ();
		static string GetDeviceType () { return "truecrypt"; }
#ifndef TC_WINDOWS
		static uid_t GetGroupId () { return GroupId; }
		static uid_t GetUserId () { return UserId; }
#endif
		static shared_ptr <Buffer> GetVolumeInfo ();
		static uint64 GetVolumeSize ();
		static uint64 GetVolumeSectorSize () { return MountedVolume->GetSectorSize(); }
		static void Mount (shared_ptr <Volume> openVolume, VolumeSlotNumber slotNumber, const string &fuseMountPoint);
		static void ReadVolumeSectors (const BufferPtr &buffer, uint64 byteOffset);
		static void ReceiveAuxDeviceInfo (const ConstBufferPtr &buffer);
		static void SendAuxDeviceInfo (const DirectoryPath &fuseMountPoint, const DevicePath &virtualDevice, const DevicePath &loopDevice = DevicePath());
		static void WriteVolumeSectors (const ConstBufferPtr &buffer, uint64 byteOffset);

	protected:
		FuseService ();
		static void CloseMountedVolume ();
#ifndef TC_WINDOWS
		static void OnSignal (int signal);
#endif

		static VolumeInfo OpenVolumeInfo;
		static Mutex OpenVolumeInfoMutex;
		static shared_ptr <Volume> MountedVolume;
		static VolumeSlotNumber SlotNumber;
#ifndef TC_WINDOWS
		static uid_t UserId;
		static gid_t GroupId;
		static unique_ptr <Pipe> SignalHandlerPipe;
#endif
	};
}

#endif // TC_HEADER_Driver_Fuse_FuseService
