/*
 Copyright (c) 2024-2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

// Standalone CLI for Basalt — no wxWidgets dependency.
// Links only against libTrueCryptCore.a + libfuse + system libraries.

#include "Core/CorePublicAPI.h"
#ifdef TC_WINDOWS
#include "Core/Windows/CoreWindows.h"
#include "Platform/Windows/Process.h"
#else
#include "Core/Unix/CoreService.h"
#include "Platform/Unix/Process.h"
#endif
#include "Core/VolumeOperations.h"
#include "Core/VolumeCreator.h"
#include "Core/RandomNumberGenerator.h"
#include "Volume/Version.h"
#include "Volume/EncryptionTest.h"
#include "Platform/PlatformTest.h"
#include "CLICallback.h"

#ifdef TC_WINDOWS
#include "CLI/getopt_win.h"
#else
#include <getopt.h>
#endif
#include <iostream>
#include <string>
#include <cstdlib>
#include <signal.h>
#include <list>

#ifdef TC_UNIX
#include <unistd.h>
#endif
#ifdef TC_WINDOWS
#include <io.h>
#endif

using namespace TrueCrypt;

// ---- Command IDs ----

enum CLICommand
{
	CmdNone = 0,
	CmdMount,
	CmdDismount,
	CmdCreate,
	CmdList,
	CmdTest,
	CmdBackupHeaders,
	CmdRestoreHeaders,
	CmdChangePassword,
	CmdCreateKeyfile,
	CmdVersion,
	CmdHelp
};

// ---- Signal handling ----

static volatile sig_atomic_t TerminationRequested = 0;

static void OnSignal (int sig)
{
	TerminationRequested = 1;
}

// ---- Size formatting ----

static wstring FormatSize (uint64 size)
{
	wstringstream s;
	if (size > 1024ULL*1024*1024)
		s << (size / (1024.0*1024*1024)) << L" GB";
	else if (size > 1024ULL*1024)
		s << (size / (1024.0*1024)) << L" MB";
	else if (size > 1024ULL)
		s << (size / 1024.0) << L" KB";
	else
		s << size << L" bytes";
	return s.str ();
}

// ---- Size parsing ----

static uint64 ParseSize (const string &s)
{
	if (s.empty ())
		throw ParameterIncorrect (SRC_POS);

	char *end = nullptr;
	unsigned long long val = strtoull (s.c_str (), &end, 10);

	if (end == s.c_str () || val == 0)
		throw ParameterIncorrect (SRC_POS);

	if (end && *end)
	{
		char suffix = *end;
		if (suffix == 'K' || suffix == 'k')
			val *= 1024ULL;
		else if (suffix == 'M' || suffix == 'm')
			val *= 1024ULL * 1024;
		else if (suffix == 'G' || suffix == 'g')
			val *= 1024ULL * 1024 * 1024;
		else
		{
			std::wcerr << L"Invalid size suffix: " << suffix << std::endl;
			throw ParameterIncorrect (SRC_POS);
		}
	}

	return (uint64) val;
}

// ---- HFS+ post-creation formatting (macOS) ----

#ifdef TC_MACOSX
static void FormatHfsPlus (const string &volumePath, shared_ptr <VolumePassword> password,
                            shared_ptr <KeyfileList> keyfiles)
{
	// Mount with NoFilesystem to get the virtual block device
	MountOptions opts;
	opts.Path = make_shared <VolumePath> (StringConverter::ToWide (volumePath));
	opts.Password = password;
	opts.Keyfiles = keyfiles;
	opts.NoFilesystem = true;

	shared_ptr <VolumeInfo> vol = Core->MountVolume (opts);
	if (!vol)
		throw ParameterIncorrect (SRC_POS);

	string virtualDev = vol->VirtualDevice;
	if (virtualDev.empty ())
	{
		Core->DismountVolume (vol, true);
		throw ParameterIncorrect (SRC_POS);
	}

	// Run newfs_hfs
	list <string> args;
	args.push_back ("-v");
	args.push_back ("Basalt");
	args.push_back (virtualDev);

	try
	{
		Process::Execute ("/sbin/newfs_hfs", args);
	}
	catch (...)
	{
		try { Core->DismountVolume (vol, true); } catch (...) { }
		throw;
	}

	Core->DismountVolume (vol, true);
}
#endif

// ---- ANSI terminal banner ----

static bool TerminalSupportsColor ()
{
#ifdef TC_WINDOWS
	// Windows 10 1607+ supports ANSI via Virtual Terminal Processing
	HANDLE hOut = GetStdHandle (STD_ERROR_HANDLE);
	if (hOut == INVALID_HANDLE_VALUE)
		return false;
	DWORD mode = 0;
	if (!GetConsoleMode (hOut, &mode))
		return false;  // redirected
	// Enable VT processing if not already on
	if (!(mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING))
	{
		mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
		SetConsoleMode (hOut, mode);
	}
	return true;
#else
	return isatty (fileno (stderr)) != 0;
#endif
}

static void ShowBanner ()
{
	// Block-letter "BASALT" in ANSI Shadow style (figlet).
	// Two-tone: solid blocks (██) in medium violet, box-drawing
	// shadow characters (╔╗╚╝═║) in deep violet.
	//
	// Color 99  = medium violet (block faces)
	// Color 54  = deep violet   (shadow / edges)
	// Color 240 = anthracite    (tagline)

	if (!TerminalSupportsColor ())
	{
		// Plain-text fallback for pipes / dumb terminals
		std::cerr <<
			"\n"
			u8" ██████╗  █████╗ ███████╗ █████╗ ██╗  ████████╗\n"
			u8" ██╔══██╗██╔══██╗██╔════╝██╔══██╗██║  ╚══██╔══╝\n"
			u8" ██████╔╝███████║███████╗███████║██║     ██║\n"
			u8" ██╔══██╗██╔══██║╚════██║██╔══██║██║     ██║\n"
			u8" ██████╔╝██║  ██║███████║██║  ██║███████╗██║\n"
			u8" ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝\n"
			"\n";
		return;
	}

	std::cerr <<
		"\n"
		"\033[38;5;99m ██████\033[38;5;54m╗\033[38;5;99m  █████\033[38;5;54m╗\033[38;5;99m ███████\033[38;5;54m╗\033[38;5;99m █████\033[38;5;54m╗\033[38;5;99m ██\033[38;5;54m╗\033[38;5;99m  ████████\033[38;5;54m╗\033[0m\n"
		"\033[38;5;99m ██\033[38;5;54m╔══\033[38;5;99m██\033[38;5;54m╗\033[38;5;99m██\033[38;5;54m╔══\033[38;5;99m██\033[38;5;54m╗\033[38;5;99m██\033[38;5;54m╔════╝\033[38;5;99m██\033[38;5;54m╔══\033[38;5;99m██\033[38;5;54m╗\033[38;5;99m██\033[38;5;54m║\033[38;5;99m  \033[38;5;54m╚══\033[38;5;99m██\033[38;5;54m╔══╝\033[0m\n"
		"\033[38;5;99m ██████\033[38;5;54m╔╝\033[38;5;99m███████\033[38;5;54m║\033[38;5;99m███████\033[38;5;54m╗\033[38;5;99m███████\033[38;5;54m║\033[38;5;99m██\033[38;5;54m║\033[38;5;99m     ██\033[38;5;54m║\033[0m\n"
		"\033[38;5;99m ██\033[38;5;54m╔══\033[38;5;99m██\033[38;5;54m╗\033[38;5;99m██\033[38;5;54m╔══\033[38;5;99m██\033[38;5;54m║╚════\033[38;5;99m██\033[38;5;54m║\033[38;5;99m██\033[38;5;54m╔══\033[38;5;99m██\033[38;5;54m║\033[38;5;99m██\033[38;5;54m║\033[38;5;99m     ██\033[38;5;54m║\033[0m\n"
		"\033[38;5;99m ██████\033[38;5;54m╔╝\033[38;5;99m██\033[38;5;54m║\033[38;5;99m  ██\033[38;5;54m║\033[38;5;99m███████\033[38;5;54m║\033[38;5;99m██\033[38;5;54m║\033[38;5;99m  ██\033[38;5;54m║\033[38;5;99m███████\033[38;5;54m╗\033[38;5;99m██\033[38;5;54m║\033[0m\n"
		"\033[38;5;54m ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝\033[0m\n"
		"\033[38;5;240m  encrypted volume management\033[0m\n"
		"\n";
}

// ---- Help text ----

static void ShowHelp (const char *argv0)
{
	std::cerr <<
		"Usage: " << argv0 << " [OPTIONS] COMMAND\n"
		"       " << argv0 << " [OPTIONS] VOLUME_PATH [MOUNT_POINT]\n"
		"\n"
		"Commands:\n"
		"  --create, -c PATH        Create a new volume\n"
		"  --mount, -m              Mount a volume\n"
		"  --dismount, -d [PATH]    Dismount volume(s)\n"
		"  --list, -l               List mounted volumes\n"
		"  --backup-headers PATH    Backup volume headers\n"
		"  --restore-headers PATH   Restore volume headers\n"
		"  --change, -C PATH        Change password/keyfiles\n"
		"  --create-keyfile PATH    Create a new keyfile\n"
		"  --test                   Run self-tests\n"
		"  --version                Display version\n"
		"  --help, -h               Display this help\n"
		"\n"
		"Options:\n"
		"  -p, --password=PASS      Volume password\n"
		"  -k, --keyfiles=K1[,K2]   Keyfile(s), comma-separated\n"
		"  --size=SIZE              Volume size for --create (e.g. 10M, 1G, 500K)\n"
		"  --encryption=ALG         Encryption algorithm (default: AES)\n"
		"  --hash=HASH              Hash algorithm (default: Argon2id-Max)\n"
		"  --filesystem=TYPE        Filesystem: fat, hfs, none (default: hfs on macOS)\n"
		"  --quick                  Quick format (skip random data fill)\n"
		"  --new-password=PASS      New password (for --change)\n"
		"  --new-keyfiles=K1[,K2]   New keyfiles (for --change)\n"
		"  --mount-options=OPTS     Mount options (readonly,headerbak,nokernelcrypto,timestamp)\n"
		"  --slot=N                 Volume slot number (1-64)\n"
		"  --force                  Force mount/dismount\n"
		"  --non-interactive        No user interaction\n"
		"  --verbose, -v            Verbose output\n"
		"\n"
		"Examples:\n"
		"  " << argv0 << " -c volume.tc --size=100M --password=secret\n"
		"  " << argv0 << " volume.tc /mnt/tc\n"
		"  " << argv0 << " -d volume.tc\n"
		"  " << argv0 << " -l\n"
		"  " << argv0 << " --test\n"
		;
}

// ---- Keyfile list parsing ----

static shared_ptr <KeyfileList> ParseKeyfiles (const string &arg)
{
	auto keyfiles = make_shared <KeyfileList> ();
	string current;
	bool prevComma = false;

	for (size_t i = 0; i < arg.size (); ++i)
	{
		if (arg[i] == ',')
		{
			if (prevComma)
			{
				// Escaped comma
				current += ',';
				prevComma = false;
			}
			else
			{
				prevComma = true;
			}
		}
		else
		{
			if (prevComma)
			{
				// Previous comma was a separator
				if (!current.empty ())
				{
					keyfiles->push_back (make_shared <Keyfile> (StringConverter::ToWide (current)));
					current.clear ();
				}
				prevComma = false;
			}
			current += arg[i];
		}
	}

	if (!current.empty ())
		keyfiles->push_back (make_shared <Keyfile> (StringConverter::ToWide (current)));

	return keyfiles->empty () ? shared_ptr <KeyfileList> () : keyfiles;
}

// ---- Mount options parsing ----

static void ParseMountOptions (MountOptions &options, const string &arg)
{
	string token;
	std::istringstream stream (arg);

	while (std::getline (stream, token, ','))
	{
		if (token == "readonly" || token == "ro")
			options.Protection = VolumeProtection::ReadOnly;
		else if (token == "headerbak")
			options.UseBackupHeaders = true;
		else if (token == "nokernelcrypto")
			options.NoKernelCrypto = true;
		else if (token == "system")
			options.PartitionInSystemEncryptionScope = true;
		else if (token == "timestamp" || token == "ts")
			options.PreserveTimestamps = false;
		else
		{
			std::wcerr << L"Unknown mount option: " << StringConverter::ToWide (token) << std::endl;
			exit (1);
		}
	}
}

// ---- Volume listing ----

static void ListMountedVolumes (bool verbose)
{
	VolumeInfoList volumes = Core->GetMountedVolumes ();

	if (volumes.empty ())
	{
		std::wcout << L"No volumes mounted." << std::endl;
		return;
	}

	for (const auto &vol : volumes)
	{
		std::wcout << vol->SlotNumber << L": " << wstring (vol->Path);

		if (!vol->VirtualDevice.IsEmpty ())
			std::wcout << L" " << wstring (vol->VirtualDevice);

		if (!vol->MountPoint.IsEmpty ())
			std::wcout << L" " << wstring (vol->MountPoint);

		std::wcout << std::endl;

		if (verbose)
		{
			std::wcout << L"  Type:           " << (vol->HiddenVolumeProtectionTriggered ? L"Hidden (protection triggered)" : (vol->Type == VolumeType::Hidden ? L"Hidden" : L"Normal")) << std::endl;
			std::wcout << L"  Size:           " << FormatSize (vol->Size) << std::endl;
			std::wcout << L"  Encryption:     " << vol->EncryptionAlgorithmName << std::endl;
			std::wcout << L"  PKCS-5 PRF:     " << vol->Pkcs5PrfName << std::endl;
			std::wcout << L"  Read-only:      " << (vol->Protection == VolumeProtection::ReadOnly ? L"Yes" : L"No") << std::endl;
			std::wcout << std::endl;
		}
	}
}

// ---- Volume properties ----

static void DisplayVolumeProperties (const VolumePath &path)
{
	shared_ptr <VolumeInfo> vol = Core->GetMountedVolume (path);
	if (!vol)
	{
		std::wcerr << L"Volume is not mounted." << std::endl;
		exit (1);
	}

	std::wcout << L"Slot:             " << vol->SlotNumber << std::endl;
	std::wcout << L"Volume:           " << wstring (vol->Path) << std::endl;
	std::wcout << L"Virtual Device:   " << wstring (vol->VirtualDevice) << std::endl;
	std::wcout << L"Mount Directory:  " << wstring (vol->MountPoint) << std::endl;
	std::wcout << L"Size:             " << FormatSize (vol->Size) << std::endl;
	std::wcout << L"Type:             " << (vol->Type == VolumeType::Hidden ? L"Hidden" : L"Normal") << std::endl;
	std::wcout << L"Encryption:       " << vol->EncryptionAlgorithmName << std::endl;
	std::wcout << L"PKCS-5 PRF:       " << vol->Pkcs5PrfName << std::endl;
	std::wcout << L"Protection:       " << (vol->Protection == VolumeProtection::ReadOnly ? L"Read-Only" : (vol->Protection == VolumeProtection::HiddenVolumeReadOnly ? L"Hidden Volume (read-only)" : L"None")) << std::endl;
}

// ---- Main ----

int main (int argc, char *argv[])
{
	// Signal handlers
	signal (SIGINT, OnSignal);
	signal (SIGTERM, OnSignal);
#ifdef TC_UNIX
	signal (SIGHUP, OnSignal);
	signal (SIGQUIT, OnSignal);
#endif

	// Options
	static struct option longOptions[] =
	{
		{ "backup-headers",  required_argument, nullptr, 'B' },
		{ "change",          optional_argument, nullptr, 'C' },
		{ "create",          required_argument, nullptr, 'c' },
		{ "create-keyfile",  required_argument, nullptr, 'K' },
		{ "dismount",        optional_argument, nullptr, 'd' },
		{ "encryption",      required_argument, nullptr, 'E' },
		{ "filesystem",      required_argument, nullptr, 'F' },
		{ "force",           no_argument,       nullptr, 'f' },
		{ "hash",            required_argument, nullptr, 'H' },
		{ "help",            no_argument,       nullptr, 'h' },
		{ "keyfiles",        required_argument, nullptr, 'k' },
		{ "list",            no_argument,       nullptr, 'l' },
		{ "mount",           no_argument,       nullptr, 'm' },
		{ "mount-options",   required_argument, nullptr, 'M' },
		{ "new-keyfiles",    required_argument, nullptr, 'N' },
		{ "new-password",    required_argument, nullptr, 'P' },
		{ "non-interactive", no_argument,       nullptr, 'I' },
		{ "password",        required_argument, nullptr, 'p' },
		{ "quick",           no_argument,       nullptr, 'Q' },
		{ "restore-headers", required_argument, nullptr, 'R' },
		{ "size",            required_argument, nullptr, 'Z' },
		{ "slot",            required_argument, nullptr, 'S' },
		{ "test",            no_argument,       nullptr, 'T' },
		{ "verbose",         no_argument,       nullptr, 'v' },
		{ "version",         no_argument,       nullptr, 'V' },
		{ nullptr,           0,                 nullptr, 0   }
	};

	CLICommand command = CmdNone;
	MountOptions mountOptions;
	string argPassword;
	string argKeyfiles;
	string argNewPassword;
	string argNewKeyfiles;
	string argHash;
	string argVolumePath;
	string argMountPoint;
	string argFilePath;
	string argSize;
	string argEncryption;
	string argFilesystem;
	bool verbose = false;
	bool force = false;
	bool nonInteractive = false;
	bool quickFormat = false;

	int opt;
	int optIndex = 0;

	// Reset getopt
	optind = 1;

	while ((opt = getopt_long (argc, argv, "B:C::c:d::hk:lmp:vK:", longOptions, &optIndex)) != -1)
	{
		switch (opt)
		{
		case 'B':  // --backup-headers
			command = CmdBackupHeaders;
			argVolumePath = optarg;
			break;

		case 'c':  // --create
			command = CmdCreate;
			argVolumePath = optarg;
			break;

		case 'C':  // --change
			command = CmdChangePassword;
			if (optarg)
				argVolumePath = optarg;
			break;

		case 'd':  // --dismount
			command = CmdDismount;
			if (optarg)
				argVolumePath = optarg;
			break;

		case 'f':  // --force
			force = true;
			break;

		case 'E':  // --encryption
			argEncryption = optarg;
			break;

		case 'F':  // --filesystem
			{
				string fs = optarg;
				argFilesystem = fs;
				if (fs == "none")
					mountOptions.NoFilesystem = true;
				else
					mountOptions.FilesystemType = StringConverter::ToWide (fs);
			}
			break;

		case 'h':  // --help
			command = CmdHelp;
			break;

		case 'H':  // --hash
			argHash = optarg;
			break;

		case 'I':  // --non-interactive
			nonInteractive = true;
			break;

		case 'k':  // --keyfiles
			argKeyfiles = optarg;
			break;

		case 'K':  // --create-keyfile
			command = CmdCreateKeyfile;
			argFilePath = optarg;
			break;

		case 'l':  // --list
			command = CmdList;
			break;

		case 'm':  // --mount
			command = CmdMount;
			break;

		case 'M':  // --mount-options
			ParseMountOptions (mountOptions, optarg);
			break;

		case 'N':  // --new-keyfiles
			argNewKeyfiles = optarg;
			break;

		case 'p':  // --password
			argPassword = optarg;
			break;

		case 'P':  // --new-password
			argNewPassword = optarg;
			break;

		case 'Q':  // --quick
			quickFormat = true;
			break;

		case 'R':  // --restore-headers
			command = CmdRestoreHeaders;
			argVolumePath = optarg;
			break;

		case 'S':  // --slot
			{
				int slot = std::atoi (optarg);
				if (slot >= 1 && slot <= 64)
					mountOptions.SlotNumber = slot;
				else
				{
					std::cerr << "Invalid slot number: " << optarg << std::endl;
					return 1;
				}
			}
			break;

		case 'T':  // --test
			command = CmdTest;
			break;

		case 'Z':  // --size
			argSize = optarg;
			break;

		case 'v':  // --verbose
			verbose = true;
			break;

		case 'V':  // --version
			command = CmdVersion;
			break;

		case '?':
		default:
			return 1;
		}
	}

	// Positional arguments
	if (optind < argc)
	{
		if (argVolumePath.empty ())
		{
			argVolumePath = argv[optind++];
			if (command == CmdNone)
				command = CmdMount;
		}
	}

	if (optind < argc && argMountPoint.empty ())
		argMountPoint = argv[optind++];

	// ---- Quick commands that don't need Core ----

	if (command == CmdHelp)
	{
		ShowBanner ();
		ShowHelp (argv[0]);
		return 0;
	}

	if (command == CmdVersion)
	{
		ShowBanner ();
		std::cout << "Basalt " << Version::String () << std::endl;
		return 0;
	}

	if (command == CmdNone)
	{
		ShowBanner ();
		ShowHelp (argv[0]);
		return 1;
	}

	// ---- Initialize Core ----

	try
	{
#ifdef TC_WINDOWS
		// On Windows, CoreWindows is used directly — no privilege elevation needed.
		Core->Init ();
#else
		// Admin password callback for elevated operations
		struct CLIAdminPasswordFunctor : public GetStringFunctor
		{
			bool nonInteractive;
			CLIAdminPasswordFunctor (bool ni) : nonInteractive (ni) {}
			virtual void operator() (string &password)
			{
				if (nonInteractive)
					throw UserAbort (SRC_POS);

				std::wcerr << L"Enter admin password: ";
				wstring wpass;
				std::getline (std::wcin, wpass);
				if (std::wcin.fail ())
					throw UserAbort (SRC_POS);
				password = StringConverter::ToSingle (wpass);
			}
		};

		CoreService::SetAdminPasswordCallback (
			shared_ptr <GetStringFunctor> (new CLIAdminPasswordFunctor (nonInteractive)));

		CoreService::Start ();
		Core->Init ();
#endif

		// Apply parsed options to MountOptions
		if (!argPassword.empty ())
			mountOptions.Password = make_shared <VolumePassword> (StringConverter::ToWide (argPassword));

		if (!argKeyfiles.empty ())
			mountOptions.Keyfiles = ParseKeyfiles (argKeyfiles);

		if (!argVolumePath.empty ())
			mountOptions.Path = make_shared <VolumePath> (StringConverter::ToWide (argVolumePath));

		if (!argMountPoint.empty ())
			mountOptions.MountPoint = make_shared <DirectoryPath> (StringConverter::ToWide (argMountPoint));

		mountOptions.SharedAccessAllowed = force;

		CLICallback cb (nonInteractive);

		// ---- Execute command ----

		switch (command)
		{
		case CmdMount:
			{
				if (!mountOptions.Path && !nonInteractive)
				{
					std::wcerr << L"Enter volume path: ";
					wstring path = cb.AskFilePath ();
					mountOptions.Path = make_shared <VolumePath> (wstring (path));
				}

				if (!mountOptions.Path)
					throw ParameterIncorrect (SRC_POS);

				if (!mountOptions.Password)
					mountOptions.Password = cb.AskPassword ();

				shared_ptr <VolumeInfo> volume = Core->MountVolume (mountOptions);

				if (verbose && volume)
				{
					std::wcout << L"Volume \"" << wstring (volume->Path) << L"\" mounted at "
						<< wstring (volume->MountPoint) << L" (slot " << volume->SlotNumber << L")" << std::endl;
				}

				// Offer KDF upgrade for legacy volumes (low iteration count)
				if (volume && !nonInteractive)
					VolumeOperations::UpgradeKdf (Core, cb, volume, mountOptions, false);
			}
			break;

		case CmdDismount:
			{
				if (argVolumePath.empty ())
				{
					// Dismount all
					VolumeInfoList volumes = Core->GetMountedVolumes ();
					for (const auto &v : volumes)
					{
						Core->DismountVolume (v, force);
						if (verbose)
							std::wcout << L"Volume \"" << wstring (v->Path) << L"\" dismounted." << std::endl;
					}
				}
				else
				{
					shared_ptr <VolumeInfo> volume = Core->GetMountedVolume (VolumePath (StringConverter::ToWide (argVolumePath)));
					if (!volume)
					{
						std::wcerr << L"No such volume is mounted." << std::endl;
						return 1;
					}
					Core->DismountVolume (volume, force);
					if (verbose)
						std::wcout << L"Volume \"" << wstring (volume->Path) << L"\" dismounted." << std::endl;
				}
			}
			break;

		case CmdList:
			ListMountedVolumes (verbose);
			break;

		case CmdTest:
			{
				std::wcout << L"Testing encryption algorithms..." << std::endl;
				EncryptionTest::TestAll ();
				std::wcout << L"Encryption tests passed." << std::endl;

				std::wcout << L"Testing platform..." << std::endl;
				PlatformTest::TestAll ();
				std::wcout << L"Platform tests passed." << std::endl;

				std::wcout << L"Self-test passed." << std::endl;
			}
			break;

		case CmdBackupHeaders:
			{
				shared_ptr <VolumePath> path;
				if (!argVolumePath.empty ())
					path = make_shared <VolumePath> (StringConverter::ToWide (argVolumePath));
				VolumeOperations::BackupVolumeHeaders (Core, cb, path);
			}
			break;

		case CmdRestoreHeaders:
			{
				shared_ptr <VolumePath> path;
				if (!argVolumePath.empty ())
					path = make_shared <VolumePath> (StringConverter::ToWide (argVolumePath));
				VolumeOperations::RestoreVolumeHeaders (Core, cb, path);
			}
			break;

		case CmdChangePassword:
			{
				if (argVolumePath.empty ())
					throw ParameterIncorrect (SRC_POS);

				shared_ptr <VolumePath> path = make_shared <VolumePath> (StringConverter::ToWide (argVolumePath));

				// Current credentials
				shared_ptr <VolumePassword> password = mountOptions.Password;
				if (!password)
					password = cb.AskPassword (L"Enter current password: ");

				shared_ptr <KeyfileList> keyfiles = mountOptions.Keyfiles;

				// New credentials
				shared_ptr <VolumePassword> newPassword;
				if (!argNewPassword.empty ())
					newPassword = make_shared <VolumePassword> (StringConverter::ToWide (argNewPassword));
				else
					newPassword = cb.AskPassword (L"Enter new password: ");

				shared_ptr <KeyfileList> newKeyfiles;
				if (!argNewKeyfiles.empty ())
					newKeyfiles = ParseKeyfiles (argNewKeyfiles);

				shared_ptr <Pkcs5Kdf> newKdf;
				if (!argHash.empty ())
				{
					for (const auto &h : TrueCrypt::Hash::GetAvailableAlgorithms ())
					{
						if (StringConverter::ToSingle (h->GetName ()) == argHash)
						{
							newKdf = Pkcs5Kdf::GetAlgorithm (*h);
							break;
						}
					}
				}

				// Enrich RNG
				cb.EnrichRandomPool ();

				Core->ChangePassword (path, true, password, keyfiles, newPassword, newKeyfiles, newKdf);

				std::wcout << L"Password changed successfully." << std::endl;
			}
			break;

		case CmdCreate:
			{
				if (argVolumePath.empty ())
					throw ParameterIncorrect (SRC_POS);
				if (argSize.empty ())
				{
					std::wcerr << L"Error: --size is required for --create" << std::endl;
					return 1;
				}

				uint64 volumeSize;
				try { volumeSize = ParseSize (argSize); }
				catch (...)
				{
					std::wcerr << L"Error: Invalid size: " << StringConverter::ToWide (argSize) << std::endl;
					std::wcerr << L"  Use e.g. 10M, 1G, 500K, or size in bytes" << std::endl;
					return 1;
				}

				// Password
				shared_ptr <VolumePassword> password;
				if (!argPassword.empty ())
					password = make_shared <VolumePassword> (StringConverter::ToWide (argPassword));
				else
					password = cb.AskPassword ();

				// Keyfiles
				shared_ptr <KeyfileList> keyfiles;
				if (!argKeyfiles.empty ())
					keyfiles = ParseKeyfiles (argKeyfiles);

				// Encryption algorithm (default: AES)
				string encName = argEncryption.empty () ? "AES" : argEncryption;
				shared_ptr <TrueCrypt::EncryptionAlgorithm> ea;
				for (const auto &a : TrueCrypt::EncryptionAlgorithm::GetAvailableAlgorithms ())
				{
					if (!a->IsDeprecated () && StringConverter::ToSingle (a->GetName ()) == encName)
					{
						ea = a;
						break;
					}
				}
				if (!ea)
				{
					std::wcerr << L"Unknown encryption algorithm: " << StringConverter::ToWide (encName) << std::endl;
					std::wcerr << L"Available: ";
					for (const auto &a : TrueCrypt::EncryptionAlgorithm::GetAvailableAlgorithms ())
						if (!a->IsDeprecated ())
							std::wcerr << a->GetName () << L"  ";
					std::wcerr << std::endl;
					return 1;
				}

				// Hash / KDF (default: Argon2id-Max)
				string hashName = argHash.empty () ? "Argon2id-Max" : argHash;
				shared_ptr <TrueCrypt::Hash> hash;
				for (const auto &h : TrueCrypt::Hash::GetAvailableAlgorithms ())
				{
					if (!h->IsDeprecated () && StringConverter::ToSingle (h->GetName ()) == hashName)
					{
						hash = h;
						break;
					}
				}
				if (!hash)
				{
					std::wcerr << L"Unknown hash algorithm: " << StringConverter::ToWide (hashName) << std::endl;
					std::wcerr << L"Available: ";
					for (const auto &h : TrueCrypt::Hash::GetAvailableAlgorithms ())
						if (!h->IsDeprecated ())
							std::wcerr << h->GetName () << L"  ";
					std::wcerr << std::endl;
					return 1;
				}

				shared_ptr <Pkcs5Kdf> kdf = Pkcs5Kdf::GetAlgorithm (*hash);

				// Filesystem (default: HFS+ on macOS, FAT elsewhere)
#ifdef TC_MACOSX
				VolumeCreationOptions::FilesystemType::Enum fsType = VolumeCreationOptions::FilesystemType::MacOsExt;
#else
				VolumeCreationOptions::FilesystemType::Enum fsType = VolumeCreationOptions::FilesystemType::FAT;
#endif
				if (!argFilesystem.empty ())
				{
					if (argFilesystem == "none")
						fsType = VolumeCreationOptions::FilesystemType::None;
					else if (argFilesystem == "fat" || argFilesystem == "FAT")
						fsType = VolumeCreationOptions::FilesystemType::FAT;
#ifdef TC_MACOSX
					else if (argFilesystem == "hfs" || argFilesystem == "hfs+" || argFilesystem == "HFS+")
						fsType = VolumeCreationOptions::FilesystemType::MacOsExt;
#endif
					else
					{
						std::wcerr << L"Unknown filesystem: " << StringConverter::ToWide (argFilesystem) << std::endl;
						return 1;
					}
				}

				// For HFS+, use None during creation (format afterwards via newfs_hfs)
				VolumeCreationOptions::FilesystemType::Enum creationFsType = fsType;
#ifdef TC_MACOSX
				if (fsType == VolumeCreationOptions::FilesystemType::MacOsExt)
					creationFsType = VolumeCreationOptions::FilesystemType::None;
#endif

				// Enrich RNG
				cb.EnrichRandomPool (hash);
				RandomNumberGenerator::SetHash (hash);

				// Build creation options
				auto options = make_shared <VolumeCreationOptions> ();
				options->Path = VolumePath (StringConverter::ToWide (argVolumePath));
				options->Type = VolumeType::Normal;
				options->Size = volumeSize;
				options->Password = password;
				options->Keyfiles = keyfiles;
				options->VolumeHeaderKdf = kdf;
				options->EA = ea;
				options->Quick = quickFormat;
				options->Filesystem = creationFsType;
				options->FilesystemClusterSize = 0;  // auto
				options->SectorSize = 0;

				if (verbose)
				{
					std::wcout << L"Creating volume: " << StringConverter::ToWide (argVolumePath) << std::endl;
					std::wcout << L"  Size:       " << FormatSize (volumeSize) << std::endl;
					std::wcout << L"  Encryption: " << ea->GetName () << std::endl;
					std::wcout << L"  Hash:       " << hash->GetName () << std::endl;
					std::wcout << L"  Filesystem: " << (fsType == VolumeCreationOptions::FilesystemType::FAT ? L"FAT" :
						(fsType == VolumeCreationOptions::FilesystemType::MacOsExt ? L"HFS+" : L"None")) << std::endl;
					std::wcout << L"  Quick:      " << (quickFormat ? L"Yes" : L"No") << std::endl;
				}

				// Start creation (spawns background thread)
				VolumeCreator creator;
				creator.CreateVolume (options);

				// Poll progress
				VolumeCreator::ProgressInfo progress;
				while (true)
				{
					progress = creator.GetProgressInfo ();
					if (!progress.CreationInProgress)
						break;

					if (progress.TotalSize > 0)
					{
						int pct = (int) (progress.SizeDone * 100 / progress.TotalSize);
						std::wcerr << L"\rCreating... " << pct << L"%" << std::flush;
					}

					if (TerminationRequested)
					{
						creator.Abort ();
						std::wcerr << std::endl << L"Aborted." << std::endl;
						break;
					}

#ifdef TC_WINDOWS
					Sleep (200);
#else
					usleep (200000);  // 200ms
#endif
				}

				std::wcerr << L"\r                     \r" << std::flush;

				// Check for errors from the creation thread
				creator.CheckResult ();

				if (TerminationRequested)
					return 1;

				// HFS+ post-creation formatting
#ifdef TC_MACOSX
				if (fsType == VolumeCreationOptions::FilesystemType::MacOsExt)
				{
					if (verbose)
						std::wcout << L"Formatting as HFS+..." << std::endl;
					FormatHfsPlus (argVolumePath, password, keyfiles);
				}
#endif

				std::wcout << L"Volume created: " << StringConverter::ToWide (argVolumePath) << std::endl;
			}
			break;

		case CmdCreateKeyfile:
			{
				FilePath keyfilePath (StringConverter::ToWide (argFilePath));
				Core->CreateKeyfile (keyfilePath);
				std::wcout << L"Keyfile created: " << StringConverter::ToWide (argFilePath) << std::endl;
			}
			break;

		default:
			break;
		}
	}
	catch (UserAbort &)
	{
#ifndef TC_WINDOWS
		try { CoreService::Stop (); } catch (...) {}
#endif
		return 1;
	}
	catch (exception &e)
	{
		std::wcerr << L"Error: " << StringConverter::ToWide (e.what ()) << std::endl;
#ifndef TC_WINDOWS
		try { CoreService::Stop (); } catch (...) {}
#endif
		return 1;
	}

#ifndef TC_WINDOWS
	try { CoreService::Stop (); } catch (...) {}
#endif
	return 0;
}
