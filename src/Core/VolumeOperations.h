/*
 Copyright (c) 2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Core_VolumeOperations
#define TC_HEADER_Core_VolumeOperations

#include "Platform/Platform.h"
#include "Core/CoreBase.h"
#include "Volume/Volume.h"
#include "Volume/VolumeLayout.h"
#include "Volume/VolumePassword.h"
#include "Volume/Keyfile.h"
#include "Volume/Pkcs5Kdf.h"
#include "Core/MountOptions.h"
#include "Core/RandomNumberGenerator.h"

namespace Basalt
{
	// Abstract callback interface for user interaction during volume operations.
	// No UI dependency. Each UI layer (SwiftUI, CLI) provides its own implementation.
	struct VolumeOperationCallback
	{
		virtual ~VolumeOperationCallback () { }

		// Password/keyfile acquisition
		virtual shared_ptr <VolumePassword> AskPassword (const wstring &message = L"") = 0;
		virtual shared_ptr <KeyfileList> AskKeyfiles (const wstring &message = L"") = 0;

		// Combined password+keyfiles via dialog (for UIs with a single dialog).
		// Default: calls AskPassword + AskKeyfiles separately.
		virtual void AskCredentials (MountOptions &options, const wstring &message = L"")
		{
			options.Password = AskPassword (message);
			options.Keyfiles = AskKeyfiles ();
		}

		// File path selection
		virtual FilePath AskFilePath (const wstring &message = L"") = 0;
		virtual FilePath AskNewFilePath (const wstring &message = L"") = 0;

		// User decisions
		virtual bool AskYesNo (const wstring &message, bool defaultYes = false, bool warning = false) = 0;

		// Selection from a list of choices. Returns 0-based index, or -1 for cancel.
		virtual int AskSelection (const vector <wstring> &choices, const wstring &prompt = L"") = 0;

		// Status display
		virtual void ShowInfo (const wstring &message) = 0;
		virtual void ShowWarning (const wstring &message) = 0;
		virtual void ShowError (const wstring &message) = 0;

		// Progress
		virtual void BeginBusy () = 0;
		virtual void EndBusy () = 0;

		// Random pool enrichment (UI-specific: mouse movement for GUI, typing for CLI)
		virtual void EnrichRandomPool (shared_ptr <Hash> hash = shared_ptr <Hash> ()) = 0;

		// Called when the user cancels (throws UserAbort)
		// Default implementation provided to reduce boilerplate.
		virtual void ThrowUserAbort () { throw UserAbort (SRC_POS); }
	};

	class VolumeOperations
	{
	public:
		// Backup volume headers to an external file.
		static void BackupVolumeHeaders (
			shared_ptr <CoreBase> core,
			VolumeOperationCallback &cb,
			shared_ptr <VolumePath> volumePath);

		// Restore volume headers from internal backup or external file.
		static void RestoreVolumeHeaders (
			shared_ptr <CoreBase> core,
			VolumeOperationCallback &cb,
			shared_ptr <VolumePath> volumePath);

		// Offer KDF upgrade on legacy volumes. Returns true if upgrade was performed.
		// On upgrade: dismounts, re-encrypts header, remounts.
		// The volume shared_ptr is updated to the newly mounted volume.
		static bool UpgradeKdf (
			shared_ptr <CoreBase> core,
			VolumeOperationCallback &cb,
			shared_ptr <VolumeInfo> &mountedVolume,
			MountOptions &options,
			bool suppressPrompt);

	private:
		VolumeOperations (); // Static-only class
	};
}

#endif // TC_HEADER_Core_VolumeOperations
