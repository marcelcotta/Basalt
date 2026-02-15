/*
 Copyright (c) 2024-2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_CLI_CLICallback
#define TC_HEADER_CLI_CLICallback

#include "Core/VolumeOperations.h"
#include "Volume/VolumePassword.h"
#include "Volume/Keyfile.h"
#include "Platform/Platform.h"
#include <string>
#include <vector>
#include <iostream>

namespace Basalt
{
	// VolumeOperationCallback implementation using pure POSIX terminal I/O.
	// No wxWidgets dependency.
	class CLICallback : public VolumeOperationCallback
	{
	public:
		CLICallback (bool nonInteractive = false)
			: NonInteractive (nonInteractive) { }

		virtual ~CLICallback () { }

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

		virtual void BeginBusy () override { }
		virtual void EndBusy () override { }

		virtual void EnrichRandomPool (shared_ptr <Hash> hash = shared_ptr <Hash> ()) override;

		// Terminal echo control for password input
		static void SetTerminalEcho (bool enable);

	private:
		wstring ReadLine () const;

		bool NonInteractive;
	};
}

#endif // TC_HEADER_CLI_CLICallback
