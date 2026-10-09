/*
 Copyright (c) 2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

// TCCocoaCallback.h already includes AppKit.h first (BOOL guard)
#include "TCCocoaCallback.h"
#include "Core/RandomNumberGenerator.h"

namespace Basalt
{
	// ---- Helper: NSString password → VolumePassword ----
	//
	// Converts directly into a stack buffer that is wiped afterwards, instead of
	// going through autoreleased NSData and std::wstring temporaries that would
	// leave copies of the password in the heap.

	shared_ptr <VolumePassword> PasswordFromNS (NSString *s)
	{
		if (!s || s.length == 0)
			return make_shared <VolumePassword> ();

		wchar_t buf[VolumePassword::MaxSize + 1];
		NSUInteger usedBytes = 0;
		NSRange remaining = NSMakeRange (0, 0);

		BOOL ok = [s getBytes:buf
		             maxLength:sizeof (buf)
		            usedLength:&usedBytes
		              encoding:NSUTF32LittleEndianStringEncoding
		               options:0
		                 range:NSMakeRange (0, s.length)
		        remainingRange:&remaining];

		// The buffer holds one character more than allowed, so a conversion that
		// stopped early is either too long (buffer full) or hit a character that
		// cannot be converted (e.g. an unpaired surrogate).
		size_t count = usedBytes / sizeof (wchar_t);
		if (!ok || remaining.length > 0 || count > VolumePassword::MaxSize)
		{
			burn (buf, sizeof (buf));
			if (count > VolumePassword::MaxSize)
				throw PasswordTooLong (SRC_POS);
			throw ParameterIncorrect (SRC_POS);
		}

		shared_ptr <VolumePassword> password;
		try
		{
			password = make_shared <VolumePassword> (buf, count);
		}
		catch (...)
		{
			burn (buf, sizeof (buf));
			throw;
		}
		burn (buf, sizeof (buf));
		return password;
	}

	NSString *CocoaOperationCallback::ToNS (const wstring &s)
	{
		if (s.empty ()) return @"";
		return [[NSString alloc] initWithBytes:s.data ()
		                                length:s.size () * sizeof (wchar_t)
		                              encoding:NSUTF32LittleEndianStringEncoding];
	}

	shared_ptr <VolumePassword> CocoaOperationCallback::AskPassword (const wstring &message)
	{
		__block NSString *result = nil;
		NSString *msg = message.empty () ? NSLocalizedString (@"Enter password:", nil) : ToNS (message);

		dispatch_block_t block = ^{
			NSAlert *alert = [[NSAlert alloc] init];
			alert.messageText = msg;
			alert.alertStyle = NSAlertStyleInformational;
			[alert addButtonWithTitle:NSLocalizedString (@"OK", nil)];
			[alert addButtonWithTitle:NSLocalizedString (@"Cancel", nil)];

			NSSecureTextField *input = [[NSSecureTextField alloc] initWithFrame:NSMakeRect (0, 0, 300, 24)];
			alert.accessoryView = input;
			// SECURITY: Prevent screen capture of password dialog
			alert.window.sharingType = NSWindowSharingNone;

			if ([alert runModal] == NSAlertFirstButtonReturn)
				result = input.stringValue;
		};

		if ([NSThread isMainThread])
			block ();
		else
			dispatch_sync (dispatch_get_main_queue (), block);

		if (!result)
			ThrowUserAbort ();

		return PasswordFromNS (result);
	}

	shared_ptr <KeyfileList> CocoaOperationCallback::AskKeyfiles (const wstring &message)
	{
		__block NSArray<NSURL *> *urls = nil;

		dispatch_block_t block = ^{
			NSOpenPanel *panel = [NSOpenPanel openPanel];
			panel.title = message.empty () ? NSLocalizedString (@"Select Keyfiles", nil) : ToNS (message);
			panel.canChooseFiles = YES;
			panel.canChooseDirectories = YES;
			panel.allowsMultipleSelection = YES;

			if ([panel runModal] == NSModalResponseOK)
				urls = panel.URLs;
		};

		if ([NSThread isMainThread])
			block ();
		else
			dispatch_sync (dispatch_get_main_queue (), block);

		if (!urls || urls.count == 0)
			return nullptr;

		auto keyfiles = make_shared <KeyfileList> ();
		for (NSURL *url in urls)
		{
			NSData *data = [url.path dataUsingEncoding:NSUTF32LittleEndianStringEncoding];
			if (data)
			{
				wstring path (reinterpret_cast<const wchar_t *>(data.bytes), data.length / sizeof (wchar_t));
				keyfiles->push_back (make_shared <Keyfile> (path));
			}
		}
		return keyfiles;
	}

	void CocoaOperationCallback::AskCredentials (MountOptions &options, const wstring &message)
	{
		options.Password = AskPassword (message);
		options.Keyfiles = AskKeyfiles ();
	}

	FilePath CocoaOperationCallback::AskFilePath (const wstring &message)
	{
		__block NSString *result = nil;

		dispatch_block_t block = ^{
			NSOpenPanel *panel = [NSOpenPanel openPanel];
			panel.title = message.empty () ? NSLocalizedString (@"Select File", nil) : ToNS (message);
			panel.canChooseFiles = YES;
			panel.canChooseDirectories = NO;

			if ([panel runModal] == NSModalResponseOK)
				result = panel.URL.path;
		};

		if ([NSThread isMainThread])
			block ();
		else
			dispatch_sync (dispatch_get_main_queue (), block);

		if (!result) return FilePath ();

		NSData *data = [result dataUsingEncoding:NSUTF32LittleEndianStringEncoding];
		if (!data) return FilePath ();
		return FilePath (wstring (reinterpret_cast<const wchar_t *>(data.bytes), data.length / sizeof (wchar_t)));
	}

	FilePath CocoaOperationCallback::AskNewFilePath (const wstring &message)
	{
		__block NSString *result = nil;

		dispatch_block_t block = ^{
			NSSavePanel *panel = [NSSavePanel savePanel];
			panel.title = message.empty () ? NSLocalizedString (@"Save File", nil) : ToNS (message);

			if ([panel runModal] == NSModalResponseOK)
				result = panel.URL.path;
		};

		if ([NSThread isMainThread])
			block ();
		else
			dispatch_sync (dispatch_get_main_queue (), block);

		if (!result) return FilePath ();

		NSData *data = [result dataUsingEncoding:NSUTF32LittleEndianStringEncoding];
		if (!data) return FilePath ();
		return FilePath (wstring (reinterpret_cast<const wchar_t *>(data.bytes), data.length / sizeof (wchar_t)));
	}

	bool CocoaOperationCallback::AskYesNo (const wstring &message, bool defaultYes, bool warning)
	{
		__block BOOL result = defaultYes;

		dispatch_block_t block = ^{
			NSAlert *alert = [[NSAlert alloc] init];
			alert.messageText = ToNS (message);
			alert.alertStyle = warning ? NSAlertStyleWarning : NSAlertStyleInformational;
			[alert addButtonWithTitle:defaultYes ? NSLocalizedString (@"Yes", nil) : NSLocalizedString (@"No", nil)];
			[alert addButtonWithTitle:defaultYes ? NSLocalizedString (@"No", nil) : NSLocalizedString (@"Yes", nil)];

			NSModalResponse resp = [alert runModal];
			if (defaultYes)
				result = (resp == NSAlertFirstButtonReturn);
			else
				result = (resp == NSAlertSecondButtonReturn);
		};

		if ([NSThread isMainThread])
			block ();
		else
			dispatch_sync (dispatch_get_main_queue (), block);

		return result;
	}

	int CocoaOperationCallback::AskSelection (const vector <wstring> &choices, const wstring &prompt)
	{
		__block NSInteger result = -1;

		dispatch_block_t block = ^{
			NSAlert *alert = [[NSAlert alloc] init];
			alert.messageText = prompt.empty () ? NSLocalizedString (@"Select an option:", nil) : ToNS (prompt);
			alert.alertStyle = NSAlertStyleInformational;

			for (const auto &choice : choices)
				[alert addButtonWithTitle:ToNS (choice)];

			[alert addButtonWithTitle:NSLocalizedString (@"Cancel", nil)];

			NSModalResponse resp = [alert runModal];
			NSInteger index = resp - NSAlertFirstButtonReturn;
			if (index >= 0 && (size_t) index < choices.size ())
				result = index;
		};

		if ([NSThread isMainThread])
			block ();
		else
			dispatch_sync (dispatch_get_main_queue (), block);

		return (int) result;
	}

	void CocoaOperationCallback::ShowInfo (const wstring &message)
	{
		dispatch_block_t block = ^{
			NSAlert *alert = [[NSAlert alloc] init];
			alert.messageText = ToNS (message);
			alert.alertStyle = NSAlertStyleInformational;
			[alert addButtonWithTitle:NSLocalizedString (@"OK", nil)];
			[alert runModal];
		};

		if ([NSThread isMainThread])
			block ();
		else
			dispatch_sync (dispatch_get_main_queue (), block);
	}

	void CocoaOperationCallback::ShowWarning (const wstring &message)
	{
		dispatch_block_t block = ^{
			NSAlert *alert = [[NSAlert alloc] init];
			alert.messageText = ToNS (message);
			alert.alertStyle = NSAlertStyleWarning;
			[alert addButtonWithTitle:NSLocalizedString (@"OK", nil)];
			[alert runModal];
		};

		if ([NSThread isMainThread])
			block ();
		else
			dispatch_sync (dispatch_get_main_queue (), block);
	}

	void CocoaOperationCallback::ShowError (const wstring &message)
	{
		dispatch_block_t block = ^{
			NSAlert *alert = [[NSAlert alloc] init];
			alert.messageText = ToNS (message);
			alert.alertStyle = NSAlertStyleCritical;
			[alert addButtonWithTitle:NSLocalizedString (@"OK", nil)];
			[alert runModal];
		};

		if ([NSThread isMainThread])
			block ();
		else
			dispatch_sync (dispatch_get_main_queue (), block);
	}

	void CocoaOperationCallback::BeginBusy ()
	{
		dispatch_async (dispatch_get_main_queue (), ^{
			[[NSCursor arrowCursor] push]; // Will be replaced with spinning cursor
		});
	}

	void CocoaOperationCallback::EndBusy ()
	{
		dispatch_async (dispatch_get_main_queue (), ^{
			[NSCursor pop];
		});
	}

	void CocoaOperationCallback::EnrichRandomPool (shared_ptr <Hash> hash)
	{
		RandomNumberGenerator::Start ();
		if (hash)
			RandomNumberGenerator::SetHash (hash);

		// For the Cocoa callback, we use system entropy rather than
		// requiring mouse movement (which is a wxWidgets pattern).
		// macOS provides high-quality entropy via /dev/urandom.
		// Future: could implement mouse-movement collection in SwiftUI.
		uint8_t entropy[64];
		arc4random_buf (entropy, sizeof (entropy));
		RandomNumberGenerator::AddToPool (ConstBufferPtr (entropy, sizeof (entropy)));
		memset (entropy, 0, sizeof (entropy));
	}
}
