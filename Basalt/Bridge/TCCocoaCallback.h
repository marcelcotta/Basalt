/*
 Copyright (c) 2024-2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

// Cocoa-native VolumeOperationCallback implementation.
// Uses NSAlert, NSOpenPanel, NSSecureTextField for user interaction.
// Must be called from the main thread.

#ifndef TC_HEADER_Bridge_TCCocoaCallback
#define TC_HEADER_Bridge_TCCocoaCallback

// AppKit MUST come first to establish typedef bool BOOL
#import <AppKit/AppKit.h>

#include "Core/VolumeOperations.h"

namespace TrueCrypt
{
	class CocoaOperationCallback : public VolumeOperationCallback
	{
	public:
		CocoaOperationCallback () { }
		virtual ~CocoaOperationCallback () { }

		virtual shared_ptr <VolumePassword> AskPassword (const wstring &message = L"") override;
		virtual shared_ptr <KeyfileList> AskKeyfiles (const wstring &message = L"") override;
		virtual void AskCredentials (MountOptions &options, const wstring &message = L"") override;

		virtual FilePath AskFilePath (const wstring &message = L"") override;
		virtual FilePath AskNewFilePath (const wstring &message = L"") override;

		virtual bool AskYesNo (const wstring &message, bool defaultYes = false, bool warning = false) override;
		virtual int AskSelection (const vector <wstring> &choices, const wstring &prompt = L"") override;

		virtual void ShowInfo (const wstring &message) override;
		virtual void ShowWarning (const wstring &message) override;
		virtual void ShowError (const wstring &message) override;

		virtual void BeginBusy () override;
		virtual void EndBusy () override;

		virtual void EnrichRandomPool (shared_ptr <Hash> hash = shared_ptr <Hash> ()) override;

	private:
		static NSString *ToNS (const wstring &s);
	};
}

#endif // TC_HEADER_Bridge_TCCocoaCallback
