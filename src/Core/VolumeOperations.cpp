/*
 Copyright (c) 2024-2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "VolumeOperations.h"
#include "Core.h"
#include "Volume/EncryptionAlgorithm.h"
#include "Volume/VolumeLayout.h"
#include "Platform/Finally.h"

#ifdef TC_UNIX
#include <unistd.h>
#endif

namespace Basalt
{
	void VolumeOperations::BackupVolumeHeaders (shared_ptr <CoreBase> core, VolumeOperationCallback &cb, shared_ptr <VolumePath> volumePath)
	{
		if (!volumePath || volumePath->IsEmpty())
		{
			FilePath selected = cb.AskFilePath (L"Select volume to back up");
			if (selected.IsEmpty())
				cb.ThrowUserAbort ();
			volumePath = make_shared <VolumePath> (selected);
		}

		if (volumePath->IsEmpty())
			cb.ThrowUserAbort ();

#ifdef TC_WINDOWS
		if (core->IsVolumeMounted (*volumePath))
		{
			cb.ShowInfo (L"DISMOUNT_FIRST");
			return;
		}
#endif

#ifdef TC_UNIX
		// Temporarily take ownership of a device if the user is not an administrator
		UserId origDeviceOwner ((uid_t) -1);

		if (!core->HasAdminPrivileges () && volumePath->IsDevice ())
		{
			origDeviceOwner = FilesystemPath (wstring (*volumePath)).GetOwner ();
			core->SetFileOwner (*volumePath, UserId (getuid ()));
		}

		finally_do_arg2 (FilesystemPath, *volumePath, UserId, origDeviceOwner,
		{
			if (finally_arg2.SystemId != (uid_t) -1)
				Core->SetFileOwner (finally_arg, finally_arg2);
		});
#endif

		cb.ShowInfo (L"EXTERNAL_VOL_HEADER_BAK_FIRST_INFO");

		shared_ptr <Volume> normalVolume;
		shared_ptr <Volume> hiddenVolume;

		MountOptions normalVolumeMountOptions;
		MountOptions hiddenVolumeMountOptions;

		normalVolumeMountOptions.Path = volumePath;
		hiddenVolumeMountOptions.Path = volumePath;

		VolumeType::Enum volumeType = VolumeType::Normal;

		// Open both types of volumes
		while (true)
		{
			shared_ptr <Volume> volume;
			MountOptions *options = (volumeType == VolumeType::Hidden ? &hiddenVolumeMountOptions : &normalVolumeMountOptions);

			wstring passwordPrompt = (volumeType == VolumeType::Hidden)
				? L"ENTER_HIDDEN_VOL_PASSWORD"
				: L"ENTER_NORMAL_VOL_PASSWORD";

			while (!volume)
			{
				cb.AskCredentials (*options, passwordPrompt);

				try
				{
					cb.BeginBusy ();
					volume = core->OpenVolume (
						options->Path,
						options->PreserveTimestamps,
						options->Password,
						options->Keyfiles,
						options->Protection,
						options->ProtectionPassword,
						options->ProtectionKeyfiles,
						true,
						volumeType,
						options->UseBackupHeaders
						);
					cb.EndBusy ();
				}
				catch (PasswordException &e)
				{
					cb.EndBusy ();
					cb.ShowWarning (StringConverter::ToWide (e.what ()));
				}
			}

			if (volumeType == VolumeType::Hidden)
				hiddenVolume = volume;
			else
				normalVolume = volume;

			// Ask whether a hidden volume is present
			if (volumeType == VolumeType::Normal)
			{
				vector <wstring> choices;
				choices.push_back (L"VOLUME_CONTAINS_HIDDEN");
				choices.push_back (L"VOLUME_DOES_NOT_CONTAIN_HIDDEN");

				int selection = cb.AskSelection (choices, L"DOES_VOLUME_CONTAIN_HIDDEN");

				if (selection == 0)
				{
					volumeType = VolumeType::Hidden;
					continue;
				}
				else if (selection < 0)
				{
					return; // User cancelled
				}
			}

			break;
		}

		if (hiddenVolume)
		{
			if (typeid (*normalVolume->GetLayout()) == typeid (VolumeLayoutV1Normal) && typeid (*hiddenVolume->GetLayout()) != typeid (VolumeLayoutV1Hidden))
				throw ParameterIncorrect (SRC_POS);

			if (typeid (*normalVolume->GetLayout()) == typeid (VolumeLayoutV2Normal) && typeid (*hiddenVolume->GetLayout()) != typeid (VolumeLayoutV2Hidden))
				throw ParameterIncorrect (SRC_POS);
		}

		// Ask user to confirm and select backup file path
		if (!cb.AskYesNo (L"CONFIRM_VOL_HEADER_BAK", true))
			return;

		FilePath backupFilePath = cb.AskNewFilePath ();
		if (backupFilePath.IsEmpty ())
			cb.ThrowUserAbort ();

		File backupFile;
		backupFile.Open (backupFilePath, File::CreateWrite);

		RandomNumberGenerator::Start ();
		cb.EnrichRandomPool ();

		cb.BeginBusy ();

		// Re-encrypt volume header
		SecureBuffer newHeaderBuffer (normalVolume->GetLayout()->GetHeaderSize());
		core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, normalVolume->GetHeader(), normalVolumeMountOptions.Password, normalVolumeMountOptions.Keyfiles);

		backupFile.Write (newHeaderBuffer);

		if (hiddenVolume)
		{
			// Re-encrypt hidden volume header
			core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, hiddenVolume->GetHeader(), hiddenVolumeMountOptions.Password, hiddenVolumeMountOptions.Keyfiles);
		}
		else
		{
			// Store random data in place of hidden volume header
			shared_ptr <EncryptionAlgorithm> ea = normalVolume->GetEncryptionAlgorithm ();
			core->RandomizeEncryptionAlgorithmKey (ea);
			ea->Encrypt (newHeaderBuffer);
		}

		backupFile.Write (newHeaderBuffer);

		cb.EndBusy ();

		cb.ShowInfo (L"VOL_HEADER_BACKED_UP");
	}

	void VolumeOperations::RestoreVolumeHeaders (shared_ptr <CoreBase> core, VolumeOperationCallback &cb, shared_ptr <VolumePath> volumePath)
	{
		if (!volumePath || volumePath->IsEmpty())
		{
			FilePath selected = cb.AskFilePath (L"Select volume to restore");
			if (selected.IsEmpty ())
				cb.ThrowUserAbort ();
			volumePath = make_shared <VolumePath> (selected);
		}

		if (volumePath->IsEmpty())
			cb.ThrowUserAbort ();

#ifdef TC_WINDOWS
		if (core->IsVolumeMounted (*volumePath))
		{
			cb.ShowInfo (L"DISMOUNT_FIRST");
			return;
		}
#endif

#ifdef TC_UNIX
		// Temporarily take ownership of a device if the user is not an administrator
		UserId origDeviceOwner ((uid_t) -1);

		if (!core->HasAdminPrivileges () && volumePath->IsDevice ())
		{
			origDeviceOwner = FilesystemPath (wstring (*volumePath)).GetOwner ();
			core->SetFileOwner (*volumePath, UserId (getuid ()));
		}

		finally_do_arg2 (FilesystemPath, *volumePath, UserId, origDeviceOwner,
		{
			if (finally_arg2.SystemId != (uid_t) -1)
				Core->SetFileOwner (finally_arg, finally_arg2);
		});
#endif

		// Ask whether to restore internal or external backup
		vector <wstring> choices;
		choices.push_back (L"HEADER_RESTORE_INTERNAL");
		choices.push_back (L"HEADER_RESTORE_EXTERNAL");

		int selection = cb.AskSelection (choices, L"HEADER_RESTORE_EXTERNAL_INTERNAL");
		if (selection < 0)
			return;

		bool restoreInternalBackup = (selection == 0);

		if (restoreInternalBackup)
		{
			// Restore header from the internal backup
			shared_ptr <Volume> volume;
			MountOptions options;
			options.Path = volumePath;

			while (!volume)
			{
				cb.AskCredentials (options);

				try
				{
					cb.BeginBusy ();
					volume = core->OpenVolume (
						options.Path,
						options.PreserveTimestamps,
						options.Password,
						options.Keyfiles,
						options.Protection,
						options.ProtectionPassword,
						options.ProtectionKeyfiles,
						options.SharedAccessAllowed,
						VolumeType::Unknown,
						true
						);
					cb.EndBusy ();
				}
				catch (PasswordException &e)
				{
					cb.EndBusy ();
					cb.ShowWarning (StringConverter::ToWide (e.what ()));
				}
			}

			shared_ptr <VolumeLayout> layout = volume->GetLayout();
			if (typeid (*layout) == typeid (VolumeLayoutV1Normal) || typeid (*layout) == typeid (VolumeLayoutV1Hidden))
			{
				cb.ShowError (L"VOLUME_HAS_NO_BACKUP_HEADER");
				return;
			}

			RandomNumberGenerator::Start ();
			cb.EnrichRandomPool ();

			cb.BeginBusy ();

			// Re-encrypt volume header
			SecureBuffer newHeaderBuffer (volume->GetLayout()->GetHeaderSize());
			core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, volume->GetHeader(), options.Password, options.Keyfiles);

			// Write volume header
			int headerOffset = volume->GetLayout()->GetHeaderOffset();
			shared_ptr <File> volumeFile = volume->GetFile();

			if (headerOffset >= 0)
				volumeFile->SeekAt (headerOffset);
			else
				volumeFile->SeekEnd (headerOffset);

			volumeFile->Write (newHeaderBuffer);

			cb.EndBusy ();
		}
		else
		{
			// Restore header from an external backup
			if (!cb.AskYesNo (L"CONFIRM_VOL_HEADER_RESTORE", true, true))
				return;

			FilePath backupFilePath = cb.AskFilePath (L"Select backup file");
			if (backupFilePath.IsEmpty ())
				cb.ThrowUserAbort ();

			File backupFile;
			backupFile.Open (backupFilePath, File::OpenRead);

			bool legacyBackup;

			// Determine the format of the backup file
			switch (backupFile.Length())
			{
			case TC_VOLUME_HEADER_GROUP_SIZE:
				legacyBackup = false;
				break;

			case TC_VOLUME_HEADER_SIZE_LEGACY * 2:
				legacyBackup = true;
				break;

			default:
				cb.ShowError (L"HEADER_BACKUP_SIZE_INCORRECT");
				return;
			}

			// Open the volume header stored in the backup file
			MountOptions options;
			shared_ptr <VolumeLayout> decryptedLayout;

			while (!decryptedLayout)
			{
				cb.AskCredentials (options, L"ENTER_HEADER_BACKUP_PASSWORD");

				try
				{
					cb.BeginBusy ();

					// Test volume layouts
					for (const auto &layout : VolumeLayout::GetAvailableLayouts ())
					{
						if (layout->HasDriveHeader ())
							continue;

						if (!legacyBackup && (typeid (*layout) == typeid (VolumeLayoutV1Normal) || typeid (*layout) == typeid (VolumeLayoutV1Hidden)))
							continue;

						if (legacyBackup && (typeid (*layout) == typeid (VolumeLayoutV2Normal) || typeid (*layout) == typeid (VolumeLayoutV2Hidden)))
							continue;

						SecureBuffer headerBuffer (layout->GetHeaderSize());
						backupFile.ReadAt (headerBuffer, layout->GetType() == VolumeType::Hidden ? layout->GetHeaderSize() : 0);

						// Decrypt header
						shared_ptr <VolumePassword> passwordKey = Keyfile::ApplyListToPassword (options.Keyfiles, options.Password);
						if (layout->GetHeader()->Decrypt (headerBuffer, *passwordKey, layout->GetSupportedKeyDerivationFunctions(), layout->GetSupportedEncryptionAlgorithms(), layout->GetSupportedEncryptionModes()))
						{
							decryptedLayout = layout;
							break;
						}
					}

					cb.EndBusy ();

					if (!decryptedLayout)
						throw PasswordIncorrect (SRC_POS);
				}
				catch (PasswordException &e)
				{
					cb.EndBusy ();
					cb.ShowWarning (StringConverter::ToWide (e.what ()));
				}
			}

			File volumeFile;
			volumeFile.Open (*volumePath, File::OpenReadWrite, File::ShareNone, File::PreserveTimestamps);

			RandomNumberGenerator::Start ();
			cb.EnrichRandomPool ();

			cb.BeginBusy ();

			// Re-encrypt volume header
			SecureBuffer newHeaderBuffer (decryptedLayout->GetHeaderSize());
			core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, decryptedLayout->GetHeader(), options.Password, options.Keyfiles);

			// Write volume header
			int headerOffset = decryptedLayout->GetHeaderOffset();
			if (headerOffset >= 0)
				volumeFile.SeekAt (headerOffset);
			else
				volumeFile.SeekEnd (headerOffset);

			volumeFile.Write (newHeaderBuffer);

			if (decryptedLayout->HasBackupHeader())
			{
				// Re-encrypt backup volume header
				core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, decryptedLayout->GetHeader(), options.Password, options.Keyfiles);

				// Write backup volume header
				headerOffset = decryptedLayout->GetBackupHeaderOffset();
				if (headerOffset >= 0)
					volumeFile.SeekAt (headerOffset);
				else
					volumeFile.SeekEnd (headerOffset);

				volumeFile.Write (newHeaderBuffer);
			}

			cb.EndBusy ();
		}

		cb.ShowInfo (L"VOL_HEADER_RESTORED");
	}

	bool VolumeOperations::UpgradeKdf (shared_ptr <CoreBase> core, VolumeOperationCallback &cb, shared_ptr <VolumeInfo> &mountedVolume, MountOptions &options, bool suppressPrompt)
	{
		if (!mountedVolume || suppressPrompt)
			return false;

		if (mountedVolume->Pkcs5IterationCount <= 0 || mountedVolume->Pkcs5IterationCount >= 10000)
			return false;

		// Argon2id variants use low t_cost (4) which is correct — not legacy
		if (mountedVolume->Pkcs5PrfName == L"Argon2id" || mountedVolume->Pkcs5PrfName == L"Argon2id-Max")
			return false;

		if (!options.Password || options.Password->IsEmpty())
			return false;

		try
		{
			shared_ptr <Pkcs5Kdf> newKdf = Pkcs5Kdf::GetAlgorithm (mountedVolume->Pkcs5PrfName);

			wstring message =
				L"This volume uses legacy key derivation (" + mountedVolume->Pkcs5PrfName +
				L", " + StringConverter::ToWide (StringConverter::ToSingle ((uint64) mountedVolume->Pkcs5IterationCount)) +
				L" iterations).\n\nModern iterations: " +
				StringConverter::ToWide (StringConverter::ToSingle ((uint64) newKdf->GetIterationCount ())) +
				L"\n\nUpgrade volume header to modern iterations?";

			if (!cb.AskYesNo (message, false))
				return false;

			cb.BeginBusy ();

			// RNG must be running for salt generation in ChangePassword
			RandomNumberGenerator::Start ();
			RandomNumberGenerator::SetHash (newKdf->GetHash ());

			// Dismount the volume first so the file is not locked by FUSE
			core->DismountVolume (mountedVolume);
			mountedVolume.reset ();

			// wipePassCount=1: KDF upgrade keeps the same master key,
			// so there is no old key material to securely erase.
			core->ChangePassword (
				make_shared <VolumePath> (*options.Path),
				options.PreserveTimestamps,
				options.Password, options.Keyfiles,
				options.Password, options.Keyfiles,
				newKdf, 1);

			// Remount the upgraded volume
			mountedVolume = core->MountVolume (options);

			cb.EndBusy ();

			cb.ShowInfo (
				L"Volume header upgraded successfully.\nNew iterations: " +
				StringConverter::ToWide (StringConverter::ToSingle ((uint64) newKdf->GetIterationCount ())));

			return true;
		}
		catch (exception &e)
		{
			cb.EndBusy ();
			cb.ShowWarning (L"Header upgrade failed: " + StringConverter::ToWide (e.what ()));
			return false;
		}
	}
}
