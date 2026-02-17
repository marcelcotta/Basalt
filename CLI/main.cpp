/*
 Copyright (c) 2024-2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

// Standalone CLI for Basalt — no wxWidgets dependency.
// Links only against libBasaltCore.a + libfuse + system libraries.

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
#include <cstdio>
#include "getopt_win.h"
#else
#include <getopt.h>
#endif
#include <chrono>
#include <iostream>
#include <string>
#include <cstdlib>
#include <clocale>
#include <signal.h>
#include <list>

#ifdef TC_UNIX
#include <termios.h>
#include <unistd.h>
#endif
#ifdef TC_WINDOWS
#include <io.h>
#endif

using namespace Basalt;

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
	CmdListDevices,
	CmdVersion,
	CmdHelp
};

// ---- Signal handling ----

static volatile sig_atomic_t TerminationRequested = 0;

static void OnSignal (int sig)
{
	TerminationRequested = 1;
}

// ---- ANSI color helpers ----

#ifdef TC_WINDOWS
static bool SupportsColor () { return false; }  // TODO: detect Windows 10+ VT100 support
#else
static bool SupportsColor () { return isatty (STDERR_FILENO); }
#endif

// ANSI escapes — narrow strings only.  std::wcerr on macOS breaks on
// non-ASCII wchar_t (e.g. ✓), so ALL output uses narrow std::cerr/cout
// with UTF-8 byte sequences and StringConverter::ToSingle() for wstrings.
static const char *ansiReset   = "";
static const char *ansiRed     = "";
static const char *ansiGreen   = "";
static const char *ansiYellow  = "";
static const char *ansiCyan    = "";
static const char *ansiBold    = "";
static const char *ansiDim     = "";

static void InitColors ()
{
	if (SupportsColor ())
	{
		ansiReset  = "\033[0m";
		ansiRed    = "\033[31m";
		ansiGreen  = "\033[32m";
		ansiYellow = "\033[33m";
		ansiCyan   = "\033[36m";
		ansiBold   = "\033[1m";
		ansiDim    = "\033[2m";
	}
}

static wstring FormatSize (uint64 size);  // forward declaration

// Shorthand for converting wstring to narrow UTF-8 for std::cerr/cout output
static inline string W (const wstring &ws) { return StringConverter::ToSingle (ws); }

// ---- Progress bar ----

static void DrawProgressBar (uint64 done, uint64 total, double elapsedSec)
{
	if (total == 0) return;
	int pct = (int) (done * 100 / total);
	const int barWidth = 30;
	int filled = (int) (done * barWidth / total);

	std::string bar;
	for (int i = 0; i < barWidth; ++i)
		bar += (i < filled) ? "\xe2\x96\x88" : "\xe2\x96\x91";  // █ and ░

	std::cerr << "\r  " << ansiCyan << bar << ansiReset
	          << "  " << ansiBold << pct << "%" << ansiReset
	          << "  " << ansiDim;

	// Size progress
	std::cerr << W (FormatSize (done)) << " / " << W (FormatSize (total));

	// ETA
	if (elapsedSec > 1.0 && done > 0)
	{
		double bytesPerSec = done / elapsedSec;
		uint64 remaining = total - done;
		int etaSec = (int) (remaining / bytesPerSec);
		int etaMin = etaSec / 60;
		etaSec %= 60;
		if (etaMin > 0)
			std::cerr << "  ETA " << etaMin << "m " << etaSec << "s";
		else
			std::cerr << "  ETA " << etaSec << "s";
	}

	std::cerr << ansiReset << "   " << std::flush;
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
			std::cerr << ansiRed << "Invalid size suffix: " << suffix << ansiReset << std::endl;
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

	// Format with HFS+ via diskutil (does not require root, unlike newfs_hfs)
	list <string> args;
	args.push_back ("eraseVolume");
	args.push_back ("HFS+");
	args.push_back ("Basalt");
	args.push_back (virtualDev);

	try
	{
		int retries = 5;
		while (true)
		{
			try
			{
				Process::Execute ("/usr/sbin/diskutil", args);
				break;
			}
			catch (...)
			{
				if (--retries <= 0)
					throw;
				Thread::Sleep (500);
			}
		}

		// diskutil eraseVolume auto-mounts the new filesystem (e.g. on
		// /Volumes/Basalt).  Unmount it before we dismount the Basalt
		// FUSE volume, otherwise hdiutil detach will fail with EBUSY.
		list <string> umArgs;
		umArgs.push_back ("unmount");
		umArgs.push_back ("force");
		umArgs.push_back (virtualDev);
		try { Process::Execute ("/usr/sbin/diskutil", umArgs); }
		catch (...) { }
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
	// Set console output codepage to UTF-8 so box-drawing characters
	// (██, ╔, ╗, ║, ╚, ╝, ═) render correctly instead of showing
	// garbled CP437 sequences like â-^â-^â.
	SetConsoleOutputCP (65001);  // CP_UTF8
	return true;
#else
	return isatty (fileno (stderr)) != 0;
#endif
}

// Write a UTF-8 string directly to the Windows console, bypassing the
// C/C++ runtime's locale-dependent conversion.  After SetConsoleOutputCP(65001),
// WriteConsoleA interprets the bytes as UTF-8 and renders them correctly —
// std::cerr / printf do not, because MinGW's C runtime still uses the
// process locale (typically CP1252 or the system ANSI codepage).
#ifdef TC_WINDOWS
static void WriteStderr (const char *utf8)
{
	HANDLE hErr = GetStdHandle (STD_ERROR_HANDLE);
	if (hErr != INVALID_HANDLE_VALUE)
	{
		DWORD written = 0;
		WriteConsoleA (hErr, utf8, (DWORD)strlen (utf8), &written, nullptr);
	}
}
#endif

static void ShowBanner ()
{
#ifdef TC_WINDOWS
	// Ensure UTF-8 output codepage even when TerminalSupportsColor() wasn't
	// called yet (e.g. plain-text fallback path).  Safe to call multiple times.
	SetConsoleOutputCP (65001);  // CP_UTF8
#endif

	// Block-letter "BASALT" in ANSI Shadow style (figlet).
	// Two-tone per line: solid blocks (██) in lighter anthracite,
	// box-drawing shadow chars (╔╗╚╝═║) in darker anthracite.
	//
	// Smooth anthracite gradient bright→dark (top-lit basalt slab):
	//   Line 1:  blocks 245, shadow 241  (lightest)
	//   Line 2:  blocks 243, shadow 240
	//   Line 3:  blocks 241, shadow 239
	//   Line 4:  blocks 240, shadow 238
	//   Line 5:  blocks 239, shadow 237
	//   Line 6:  blocks 238, shadow 236  (darkest)
	//   Tagline: 99 violet accent

	if (!TerminalSupportsColor ())
	{
		// Plain-text fallback for pipes / dumb terminals
		const char *plain =
			"\n"
			u8" ██████╗  █████╗ ███████╗ █████╗ ██╗  ████████╗\n"
			u8" ██╔══██╗██╔══██╗██╔════╝██╔══██╗██║  ╚══██╔══╝\n"
			u8" ██████╔╝███████║███████╗███████║██║     ██║\n"
			u8" ██╔══██╗██╔══██║╚════██║██╔══██║██║     ██║\n"
			u8" ██████╔╝██║  ██║███████║██║  ██║███████╗██║\n"
			u8" ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝\n"
			"\n";
#ifdef TC_WINDOWS
		WriteStderr (plain);
#else
		std::cerr << plain;
#endif
		return;
	}

	const char *colored =
		"\n"
		"\033[38;5;245m ██████\033[38;5;241m╗\033[38;5;245m  █████\033[38;5;241m╗\033[38;5;245m ███████\033[38;5;241m╗\033[38;5;245m █████\033[38;5;241m╗\033[38;5;245m ██\033[38;5;241m╗\033[38;5;245m  ████████\033[38;5;241m╗\033[0m\n"
		"\033[38;5;243m ██\033[38;5;240m╔══\033[38;5;243m██\033[38;5;240m╗\033[38;5;243m██\033[38;5;240m╔══\033[38;5;243m██\033[38;5;240m╗\033[38;5;243m██\033[38;5;240m╔════╝\033[38;5;243m██\033[38;5;240m╔══\033[38;5;243m██\033[38;5;240m╗\033[38;5;243m██\033[38;5;240m║\033[38;5;243m  \033[38;5;240m╚══\033[38;5;243m██\033[38;5;240m╔══╝\033[0m\n"
		"\033[38;5;241m ██████\033[38;5;239m╔╝\033[38;5;241m███████\033[38;5;239m║\033[38;5;241m███████\033[38;5;239m╗\033[38;5;241m███████\033[38;5;239m║\033[38;5;241m██\033[38;5;239m║\033[38;5;241m     ██\033[38;5;239m║\033[0m\n"
		"\033[38;5;240m ██\033[38;5;238m╔══\033[38;5;240m██\033[38;5;238m╗\033[38;5;240m██\033[38;5;238m╔══\033[38;5;240m██\033[38;5;238m║╚════\033[38;5;240m██\033[38;5;238m║\033[38;5;240m██\033[38;5;238m╔══\033[38;5;240m██\033[38;5;238m║\033[38;5;240m██\033[38;5;238m║\033[38;5;240m     ██\033[38;5;238m║\033[0m\n"
		"\033[38;5;239m ██████\033[38;5;237m╔╝\033[38;5;239m██\033[38;5;237m║\033[38;5;239m  ██\033[38;5;237m║\033[38;5;239m███████\033[38;5;237m║\033[38;5;239m██\033[38;5;237m║\033[38;5;239m  ██\033[38;5;237m║\033[38;5;239m███████\033[38;5;237m╗\033[38;5;239m██\033[38;5;237m║\033[0m\n"
		"\033[38;5;238m \033[38;5;236m╚═════╝\033[38;5;238m \033[38;5;236m╚═╝\033[38;5;238m  \033[38;5;236m╚═╝╚══════╝╚═╝\033[38;5;238m  \033[38;5;236m╚═╝╚══════╝╚═╝\033[0m\n"
		"\033[38;5;99m  encrypted volume management\033[0m\n"
		"\n";

#ifdef TC_WINDOWS
	WriteStderr (colored);
#else
	std::cerr << colored;
#endif
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
		"  --list-devices           List available devices/partitions\n"
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
		"  --hidden                 Create a hidden volume inside an existing container\n"
		"  --quick                  Quick format (skip random data fill)\n"
		"  --new-password=PASS      New password (for --change)\n"
		"  --new-keyfiles=K1[,K2]   New keyfiles (for --change)\n"
		"  --mount-options=OPTS     Mount options (readonly,headerbak,nokernelcrypto,timestamp)\n"
		"  --force                  Force mount/dismount\n"
		"  --non-interactive        No user interaction\n"
		"  --verbose, -v            Verbose output\n"
		"\n"
		"Mount point:\n"
#ifdef TC_WINDOWS
		"  On Windows, volumes are mounted as drive letters (e.g. Z:, M:).\n"
		"  If no mount point is given, the next free letter (Z: downwards) is used.\n"
#else
		"  On macOS/Linux, specify a directory as mount point.\n"
#endif
		"\n"
		"Examples:\n"
		"  " << argv0 << " -c volume.tc --size=100M --password=secret\n"
#ifdef TC_WINDOWS
		"  " << argv0 << " volume.tc                Mount on next free drive letter\n"
		"  " << argv0 << " volume.tc M:             Mount on M:\n"
#else
		"  " << argv0 << " volume.tc /mnt/tc\n"
#endif
		"  " << argv0 << " -c volume.tc --hidden --size=50M --password=hidden_pass\n"
		"  " << argv0 << " -d volume.tc\n"
		"  " << argv0 << " -l\n"
		"  " << argv0 << " --list-devices\n"
#ifdef TC_WINDOWS
		"  " << argv0 << " -c \\\\.\\PhysicalDrive2 --password=secret    Create on device\n"
		"  " << argv0 << " \\\\.\\PhysicalDrive2 F:                      Mount device\n"
#else
		"  " << argv0 << " -c /dev/disk2 --password=secret              Create on device\n"
		"  " << argv0 << " /dev/disk2 /mnt/tc                           Mount device\n"
#endif
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
			std::cerr << ansiRed << "Unknown mount option: " << token << ansiReset << std::endl;
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
		std::cerr << ansiDim << "No volumes mounted." << ansiReset << std::endl;
		return;
	}

	if (!verbose)
	{
		// Compact table: Slot  Volume  Mount Point  Size  Encryption
		// First pass: compute column widths
		size_t wSlot = 4, wPath = 6, wMount = 11, wSize = 4, wEnc = 10;
		for (const auto &vol : volumes)
		{
			wPath  = std::max (wPath,  wstring (vol->Path).size ());
			wMount = std::max (wMount, wstring (vol->MountPoint).size ());
			wSize  = std::max (wSize,  FormatSize (vol->Size).size ());
			wEnc   = std::max (wEnc,   wstring (vol->EncryptionAlgorithmName).size ());
		}

		// Header
		std::cerr << ansiBold;
		string hSlot = "Slot";   while (hSlot.size () < wSlot) hSlot += ' ';
		string hPath = "Volume"; while (hPath.size () < wPath) hPath += ' ';
		string hMount = "Mount Point"; while (hMount.size () < wMount) hMount += ' ';
		string hSize = "Size"; while (hSize.size () < wSize) hSize += ' ';
		string hEnc  = "Encryption";
		std::cerr << "  " << hSlot << "  " << hPath << "  " << hMount << "  " << hSize << "  " << hEnc << ansiReset << std::endl;

		// Separator
		std::cerr << ansiDim << "  ";
		for (size_t i = 0; i < wSlot; ++i) std::cerr << "\xe2\x94\x80";
		std::cerr << "  ";
		for (size_t i = 0; i < wPath; ++i) std::cerr << "\xe2\x94\x80";
		std::cerr << "  ";
		for (size_t i = 0; i < wMount; ++i) std::cerr << "\xe2\x94\x80";
		std::cerr << "  ";
		for (size_t i = 0; i < wSize; ++i) std::cerr << "\xe2\x94\x80";
		std::cerr << "  ";
		for (size_t i = 0; i < wEnc; ++i) std::cerr << "\xe2\x94\x80";
		std::cerr << ansiReset << std::endl;

		// Rows
		for (const auto &vol : volumes)
		{
			stringstream slotStr;
			slotStr << vol->SlotNumber;
			string sSlot = slotStr.str ();
			while (sSlot.size () < wSlot) sSlot += ' ';

			string sPath = W (wstring (vol->Path));
			while (sPath.size () < wPath) sPath += ' ';

			string sMount = W (wstring (vol->MountPoint));
			while (sMount.size () < wMount) sMount += ' ';

			string sSize = W (FormatSize (vol->Size));
			while (sSize.size () < wSize) sSize += ' ';

			string sEnc = W (vol->EncryptionAlgorithmName);

			std::cout << "  " << ansiDim << sSlot << ansiReset
			           << "  " << ansiBold << sPath << ansiReset
			           << "  " << ansiCyan << sMount << ansiReset
			           << "  " << sSize
			           << "  " << ansiDim << sEnc << ansiReset
			           << std::endl;

			if (vol->HiddenVolumeProtectionTriggered)
				std::cerr << "  " << ansiRed << ansiBold << "\xe2\x9a\xa0 PROTECTION TRIGGERED"
				           << ansiReset << " \xe2\x80\x94 hidden volume safe, outer filesystem may be corrupted" << std::endl;
		}
	}
	else
	{
		// Verbose: detailed per-volume output
		for (const auto &vol : volumes)
		{
			std::cout << ansiBold << ansiCyan << "\xe2\x96\x88 " << W (wstring (vol->Path)) << ansiReset << std::endl;
			std::cout << ansiDim << "  Slot:       " << ansiReset << vol->SlotNumber << std::endl;
			std::cout << ansiDim << "  Mount:      " << ansiReset << ansiCyan << W (wstring (vol->MountPoint)) << ansiReset << std::endl;
			std::cout << ansiDim << "  Device:     " << ansiReset << W (wstring (vol->VirtualDevice)) << std::endl;
			std::cout << ansiDim << "  Type:       " << ansiReset
			           << (vol->HiddenVolumeProtectionTriggered
			               ? (string (ansiRed) + ansiBold + "\xe2\x9a\xa0 PROTECTION TRIGGERED"
			                  + ansiReset + " \xe2\x80\x94 hidden volume safe, outer filesystem may be corrupted")
			               : (vol->Type == VolumeType::Hidden ? string ("Hidden") : string ("Normal"))) << std::endl;
			std::cout << ansiDim << "  Size:       " << ansiReset << W (FormatSize (vol->Size)) << std::endl;
			std::cout << ansiDim << "  Encryption: " << ansiReset << W (vol->EncryptionAlgorithmName) << std::endl;
			std::cout << ansiDim << "  KDF:        " << ansiReset << W (vol->Pkcs5PrfName) << std::endl;
			std::cout << ansiDim << "  Read-only:  " << ansiReset
			           << (vol->Protection == VolumeProtection::ReadOnly ? "Yes" : "No") << std::endl;
			std::cout << std::endl;
		}
	}
}

// ---- Main ----

int main (int argc, char *argv[])
{
	// Use system locale for correct UTF-8 handling of passwords and paths
	std::setlocale (LC_ALL, "");
	InitColors ();

#ifdef TC_UNIX
	// Elevated service mode — invoked by sudo from CoreService::StartElevated().
	// Must be checked before anything else (signal handlers, option parsing, etc.)
	// to avoid initializing the normal application when running as a privileged helper.
	if (argc > 1 && strcmp (argv[1], TC_CORE_SERVICE_CMDLINE_OPTION) == 0)
	{
		try
		{
			CoreService::ProcessElevatedRequests ();
			return 0;
		}
		catch (...) { }
		return 1;
	}
#endif

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
		{ "hidden",          no_argument,       nullptr, 'W' },
		{ "keyfiles",        required_argument, nullptr, 'k' },
		{ "list",            no_argument,       nullptr, 'l' },
		{ "list-devices",    no_argument,       nullptr, 'D' },
		{ "mount",           no_argument,       nullptr, 'm' },
		{ "mount-options",   required_argument, nullptr, 'M' },
		{ "new-keyfiles",    required_argument, nullptr, 'N' },
		{ "new-password",    required_argument, nullptr, 'P' },
		{ "non-interactive", no_argument,       nullptr, 'I' },
		{ "password",        required_argument, nullptr, 'p' },
		{ "quick",           no_argument,       nullptr, 'Q' },
		{ "restore-headers", required_argument, nullptr, 'R' },
		{ "size",            required_argument, nullptr, 'Z' },
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
	bool hiddenVolume = false;

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

		case 'W':  // --hidden
			hiddenVolume = true;
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

		case 'D':  // --list-devices
			command = CmdListDevices;
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

	if (command == CmdTest)
	{
		try
		{
			std::cerr << ansiDim << "Testing encryption algorithms..." << ansiReset << std::endl;
			EncryptionTest::TestAll ();
			std::cerr << ansiGreen << "\xe2\x9c\x93 " << ansiReset << "Encryption tests passed." << std::endl;

			std::cerr << ansiDim << "Testing platform..." << ansiReset << std::endl;
			PlatformTest::TestAll ();
			std::cerr << ansiGreen << "\xe2\x9c\x93 " << ansiReset << "Platform tests passed." << std::endl;

			std::cerr << ansiGreen << ansiBold << "\xe2\x9c\x93 Self-test passed." << ansiReset << std::endl;
		}
		catch (exception &e)
		{
			std::cerr << ansiRed << "Test failed: " << ansiReset << W (StringConverter::ToExceptionString (e)) << std::endl;
			return 1;
		}
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
		// Global Core/CoreDirect are default-constructed (null) to avoid static
		// init ordering issues with the GUI.  Create them here for the CLI.
		if (!Core)
		{
			Core.reset (new CoreWindows ());
			CoreDirect = Core;
		}
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

				std::cerr << "Enter admin password (empty to cancel): ";

				// Disable terminal echo for password input
				struct termios origTios, noEchoTios;
				bool tiosOk = (tcgetattr (STDIN_FILENO, &origTios) == 0);
				if (tiosOk)
				{
					noEchoTios = origTios;
					noEchoTios.c_lflag &= ~ECHO;
					tcsetattr (STDIN_FILENO, TCSADRAIN, &noEchoTios);
				}

				// Read password as raw bytes (std::cin) to preserve UTF-8 encoding.
				// Using std::wcin would mangle multi-byte characters depending on locale.
				std::getline (std::cin, password);

				if (tiosOk)
					tcsetattr (STDIN_FILENO, TCSADRAIN, &origTios);
				std::cerr << std::endl;

				if (std::cin.fail () || std::cin.eof () || password.empty ())
					throw UserAbort (SRC_POS);
			}
		};

		CoreService::SetAdminPasswordCallback (
			shared_ptr <GetStringFunctor> (new CLIAdminPasswordFunctor (nonInteractive)));

		// Handler to display elevation errors to the user
		CoreService::SetAdminPasswordRequestHandler ([] (const string &errOutput) {
			if (!errOutput.empty ())
				std::cerr << ansiRed << "Elevation failed: " << ansiReset << errOutput << std::endl;
			else
				std::cerr << ansiRed << "Incorrect password or elevation failed." << ansiReset << std::endl;
		});

		// Set executable path so CoreService can re-exec via sudo for elevation
		{
			char resolvedPath[PATH_MAX] = {};
			if (realpath (argv[0], resolvedPath))
				Core->SetApplicationExecutablePath (FilePath (StringConverter::ToWide (resolvedPath)));
		}

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
					std::cerr << "Enter volume path: ";
					wstring path = cb.AskFilePath ();
					mountOptions.Path = make_shared <VolumePath> (wstring (path));
				}

				if (!mountOptions.Path)
					throw ParameterIncorrect (SRC_POS);

				// Check that the volume file or device exists before asking for password
				{
					FilesystemPath volumeFilePath (wstring (*mountOptions.Path));
					if (!volumeFilePath.IsFile () && !volumeFilePath.IsDevice ())
					{
						std::cerr << ansiRed << "No such volume or device: " << ansiReset << W (wstring (*mountOptions.Path)) << std::endl;
						return 1;
					}

				}

				if (!mountOptions.Password)
					mountOptions.Password = cb.AskPassword ();

#if defined (TC_MACOSX)
				// Auto-dismount device filesystems before mounting.
				// macOS keeps devices busy while their filesystem is mounted.
				if (mountOptions.Path->IsDevice ())
				{
					string devPath = StringConverter::ToSingle (wstring (*mountOptions.Path));
					string diskutilPath = devPath;

					// Strip "r" from /dev/rdiskN → /dev/diskN
					if (diskutilPath.find ("/dev/rdisk") == 0)
						diskutilPath = "/dev/disk" + diskutilPath.substr (10);

					// Strip partition suffix (e.g. /dev/disk2s1 → /dev/disk2)
					size_t sPos = diskutilPath.find ('s', strlen ("/dev/disk"));
					if (sPos != string::npos && sPos > strlen ("/dev/disk"))
						diskutilPath = diskutilPath.substr (0, sPos);

					list <string> args;
					args.push_back ("unmountDisk");
					args.push_back ("force");
					args.push_back (diskutilPath);

					try { Process::Execute ("/usr/sbin/diskutil", args); }
					catch (...) { }
				}
#endif

				shared_ptr <VolumeInfo> volume = Core->MountVolume (mountOptions);

				if (volume)
				{
					std::cout << ansiGreen << "\xe2\x9c\x93 " << ansiReset
						<< "Volume \"" << ansiBold << W (wstring (volume->Path)) << ansiReset << "\" mounted at "
						<< ansiCyan << W (wstring (volume->MountPoint)) << ansiReset
						<< ansiDim << " (slot " << volume->SlotNumber << ")" << ansiReset << std::endl;
				}

				// Offer KDF upgrade for legacy volumes (low iteration count)
				if (volume && !nonInteractive)
					VolumeOperations::UpgradeKdf (Core, cb, volume, mountOptions, false);

#ifdef TC_WINDOWS
				// On Windows, fuse_main() is non-blocking — the iSCSI target runs
				// on a background thread.  The CLI process MUST stay alive to keep
				// the iSCSI server and crypto engine running.
				//
				// Dismount via: basalt-cli -d <volume>  (from another terminal)
				//           or: Ctrl+C in this terminal
				if (volume)
				{
					// Create a named event for cross-process dismount signaling.
					// basalt-cli -d opens this event by name and signals it.
					char eventName[64];
					snprintf (eventName, sizeof(eventName), "Global\\BasaltDismount_Slot%u",
					          (unsigned)volume->SlotNumber);
					HANDLE hDismountEvent = CreateEventA (NULL, TRUE, FALSE, eventName);

					std::cout << "To dismount: basalt-cli -d "
					           << W (wstring (volume->Path)) << std::endl;

					// Wait for dismount signal or Ctrl+C
					while (!TerminationRequested)
					{
						if (hDismountEvent)
						{
							DWORD wait = WaitForSingleObject (hDismountEvent, 500);
							if (wait == WAIT_OBJECT_0)
								break;
						}
						else
						{
							Sleep (500);
						}
					}

					std::cout << ansiDim << "Dismounting..." << ansiReset << std::endl;

					try
					{
						Core->DismountVolume (volume, true);
						std::cout << ansiGreen << "\xe2\x9c\x93 " << ansiReset << "Volume dismounted." << std::endl;
					}
					catch (exception &ex)
					{
						std::cerr << ansiRed << "Dismount error: " << ansiReset
						           << W (StringConverter::ToExceptionString (ex)) << std::endl;
					}

					if (hDismountEvent)
						CloseHandle (hDismountEvent);
				}
#endif
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
							std::cout << ansiGreen << "\xe2\x9c\x93 " << ansiReset << "Volume \"" << W (wstring (v->Path)) << "\" dismounted." << std::endl;
					}
				}
				else
				{
					shared_ptr <VolumeInfo> volume = Core->GetMountedVolume (VolumePath (StringConverter::ToWide (argVolumePath)));
					if (!volume)
					{
						std::cerr << ansiRed << "No such volume is mounted." << ansiReset << std::endl;
						return 1;
					}
					Core->DismountVolume (volume, force);
					if (verbose)
						std::cout << ansiGreen << "\xe2\x9c\x93 " << ansiReset << "Volume \"" << W (wstring (volume->Path)) << "\" dismounted." << std::endl;
				}
			}
			break;

		case CmdList:
			ListMountedVolumes (verbose);
			break;

		case CmdListDevices:
			{
				HostDeviceList devices = Core->GetHostDevices ();

				if (devices.empty ())
				{
					std::cerr << ansiDim << "No devices found." << ansiReset << std::endl;
				}
				else
				{
					std::cerr << ansiBold
					           << "  Device                         Size        Removable"
					           << ansiReset << std::endl;
					std::cerr << ansiDim
					           << "  \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80  \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80  \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"
					           << ansiReset << std::endl;

					for (const auto &dev : devices)
					{
						string path = W (wstring (dev->Path));
						while (path.size () < 30) path += ' ';

						string sizeStr = W (FormatSize (dev->Size));
						while (sizeStr.size () < 12) sizeStr += ' ';

						std::cout << "  " << ansiBold << path << ansiReset << " " << sizeStr
						           << (dev->Removable ? "Yes" : "No ");
						if (!wstring (dev->MountPoint).empty ())
							std::cout << "  " << ansiCyan << W (wstring (dev->MountPoint)) << ansiReset;
						std::cout << std::endl;

						// Partitions (indented)
						for (const auto &part : dev->Partitions)
						{
							string ppath = "  " + W (wstring (part->Path));
							while (ppath.size () < 30) ppath += ' ';

							string psizeStr = W (FormatSize (part->Size));
							while (psizeStr.size () < 12) psizeStr += ' ';

							std::cout << "  " << ansiDim << ppath << ansiReset << " " << psizeStr
							           << (part->Removable ? "Yes" : "No ");
							if (!wstring (part->MountPoint).empty ())
								std::cout << "  " << ansiCyan << W (wstring (part->MountPoint)) << ansiReset;
							std::cout << std::endl;
						}
					}
				}
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
					for (const auto &h : Basalt::Hash::GetAvailableAlgorithms ())
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

				std::cout << ansiGreen << "\xe2\x9c\x93 " << ansiReset << "Password changed successfully." << std::endl;
			}
			break;

		case CmdCreate:
			{
				if (argVolumePath.empty ())
					throw ParameterIncorrect (SRC_POS);

				// Detect device-hosted creation (e.g. /dev/disk2, \\.\PhysicalDrive1)
				FilesystemPath createPath (StringConverter::ToWide (argVolumePath));
				bool isDeviceCreate = createPath.IsDevice ();

				if (hiddenVolume)
				{
					// Hidden volumes always require an explicit size
					if (argSize.empty ())
					{
						std::cerr << ansiRed << "Error: " << ansiReset << "--size is required for hidden volumes" << std::endl;
						std::cerr << ansiDim << "  The hidden volume must fit inside the outer volume's free space." << ansiReset << std::endl;
						return 1;
					}
				}
				else if (argSize.empty () && !isDeviceCreate)
				{
					std::cerr << ansiRed << "Error: " << ansiReset << "--size is required for file containers" << std::endl;
					std::cerr << ansiDim << "  (not needed when creating on a device)" << ansiReset << std::endl;
					return 1;
				}

				// Safety confirmation for device creation — all data will be destroyed
				if (isDeviceCreate && !hiddenVolume && !nonInteractive)
				{
					std::cerr << ansiYellow << ansiBold << "WARNING: " << ansiReset << ansiYellow
					           << "All data on " << argVolumePath
					           << " will be irrecoverably overwritten!" << ansiReset << std::endl;
					std::cerr << "Type \"yes\" to continue: ";
					string confirm;
					std::getline (std::cin, confirm);
					if (confirm != "yes")
					{
						std::cerr << ansiYellow << "Aborted." << ansiReset << std::endl;
						return 1;
					}
				}

				uint64 volumeSize = 0;
				if (!argSize.empty ())
				{
					try { volumeSize = ParseSize (argSize); }
					catch (...)
					{
						std::cerr << ansiRed << "Error: " << ansiReset << "Invalid size: " << argSize << std::endl;
						std::cerr << ansiDim << "  Use e.g. 10M, 1G, 500K, or size in bytes" << ansiReset << std::endl;
						return 1;
					}
				}
				// For devices: volumeSize stays 0 — VolumeCreator uses the device's actual size

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
				shared_ptr <Basalt::EncryptionAlgorithm> ea;
				for (const auto &a : Basalt::EncryptionAlgorithm::GetAvailableAlgorithms ())
				{
					if (!a->IsDeprecated () && StringConverter::ToSingle (a->GetName ()) == encName)
					{
						ea = a;
						break;
					}
				}
				if (!ea)
				{
					std::cerr << ansiRed << "Unknown encryption algorithm: " << ansiReset << encName << std::endl;
					std::cerr << ansiDim << "Available: ";
					for (const auto &a : Basalt::EncryptionAlgorithm::GetAvailableAlgorithms ())
						if (!a->IsDeprecated ())
							std::cerr << W (a->GetName ()) << "  ";
					std::cerr << ansiReset << std::endl;
					return 1;
				}

				// Hash / KDF (default: Argon2id-Max)
				string hashName = argHash.empty () ? "Argon2id-Max" : argHash;
				shared_ptr <Basalt::Hash> hash;
				for (const auto &h : Basalt::Hash::GetAvailableAlgorithms ())
				{
					if (!h->IsDeprecated () && StringConverter::ToSingle (h->GetName ()) == hashName)
					{
						hash = h;
						break;
					}
				}
				if (!hash)
				{
					std::cerr << ansiRed << "Unknown hash algorithm: " << ansiReset << hashName << std::endl;
					std::cerr << ansiDim << "Available: ";
					for (const auto &h : Basalt::Hash::GetAvailableAlgorithms ())
						if (!h->IsDeprecated ())
							std::cerr << W (h->GetName ()) << "  ";
					std::cerr << ansiReset << std::endl;
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
						std::cerr << ansiRed << "Unknown filesystem: " << ansiReset << argFilesystem << std::endl;
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
				options->Type = hiddenVolume ? VolumeType::Hidden : VolumeType::Normal;
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
					std::cout << "Creating volume: " << argVolumePath << std::endl;
					std::cout << "  Type:       " << (hiddenVolume ? "Hidden" : (isDeviceCreate ? "Device" : "File container")) << std::endl;
					if (volumeSize > 0)
						std::cout << "  Size:       " << W (FormatSize (volumeSize)) << std::endl;
					else
						std::cout << "  Size:       (device size, determined at creation)" << std::endl;
					std::cout << "  Encryption: " << W (ea->GetName ()) << std::endl;
					std::cout << "  Hash:       " << W (hash->GetName ()) << std::endl;
					std::cout << "  Filesystem: " << (fsType == VolumeCreationOptions::FilesystemType::FAT ? "FAT" :
						(fsType == VolumeCreationOptions::FilesystemType::MacOsExt ? "HFS+" : "None")) << std::endl;
					std::cout << "  Quick:      " << (quickFormat ? "Yes" : "No") << std::endl;
				}

				// Auto-dismount device filesystems before creation
#if defined (TC_MACOSX)
				if (isDeviceCreate)
				{
					string diskutilPath = argVolumePath;

					// Strip "r" from /dev/rdiskN → /dev/diskN
					if (diskutilPath.find ("/dev/rdisk") == 0)
						diskutilPath = "/dev/disk" + diskutilPath.substr (10);

					// Strip partition suffix (e.g. /dev/disk2s1 → /dev/disk2)
					size_t sPos = diskutilPath.find ('s', strlen ("/dev/disk"));
					if (sPos != string::npos && sPos > strlen ("/dev/disk"))
						diskutilPath = diskutilPath.substr (0, sPos);

					list <string> dmArgs;
					dmArgs.push_back ("unmountDisk");
					dmArgs.push_back ("force");
					dmArgs.push_back (diskutilPath);

					try { Process::Execute ("/usr/sbin/diskutil", dmArgs); }
					catch (...) { }
				}
#endif

				// Start creation (spawns background thread)
				VolumeCreator creator;
				creator.CreateVolume (options);

				// Poll progress with visual bar
				VolumeCreator::ProgressInfo progress;
				auto startTime = std::chrono::steady_clock::now ();
				while (true)
				{
					progress = creator.GetProgressInfo ();
					if (!progress.CreationInProgress)
						break;

					if (progress.TotalSize > 0 && progress.SizeDone > 0)
					{
						auto elapsed = std::chrono::steady_clock::now () - startTime;
						double elapsedSec = std::chrono::duration <double> (elapsed).count ();
						DrawProgressBar (progress.SizeDone, progress.TotalSize, elapsedSec);
					}

					if (TerminationRequested)
					{
						creator.Abort ();
						std::cerr << std::endl << ansiYellow << "Aborted." << ansiReset << std::endl;
						break;
					}

#ifdef TC_WINDOWS
					Sleep (200);
#else
					usleep (200000);  // 200ms
#endif
				}

				// Clear the progress bar line
				std::cerr << "\r\033[K" << std::flush;

				// Check for errors from the creation thread
				creator.CheckResult ();

				if (TerminationRequested)
					return 1;

				// HFS+ post-creation formatting
#ifdef TC_MACOSX
				if (fsType == VolumeCreationOptions::FilesystemType::MacOsExt)
				{
					if (verbose)
						std::cout << "Formatting as HFS+..." << std::endl;
					FormatHfsPlus (argVolumePath, password, keyfiles);
				}
#endif

				if (hiddenVolume)
				{
					std::cout << ansiGreen << "\xe2\x9c\x93 " << ansiReset << "Hidden volume created inside: "
					           << ansiBold << argVolumePath << ansiReset << std::endl;
					std::cout << ansiDim << "  Use the hidden volume's password to mount it." << ansiReset << std::endl;
				}
				else
					std::cout << ansiGreen << "\xe2\x9c\x93 " << ansiReset << "Volume created: "
					           << ansiBold << argVolumePath << ansiReset << std::endl;
			}
			break;

		case CmdCreateKeyfile:
			{
				FilePath keyfilePath (StringConverter::ToWide (argFilePath));
				Core->CreateKeyfile (keyfilePath);
				std::cout << ansiGreen << "\xe2\x9c\x93 " << ansiReset << "Keyfile created: " << argFilePath << std::endl;
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
#ifdef TC_WINDOWS
	catch (DriveLetterUnavailable &)
	{
		string mountPoint = argMountPoint.empty () ? "(auto)" : argMountPoint;
		std::cerr << ansiRed << "Error: " << ansiReset << "Drive letter " << mountPoint << " is already in use." << std::endl;
		std::cerr << ansiDim << "  If this is a stale mount from a previous run, disconnect it first:" << std::endl;
		std::cerr << "    net use " << mountPoint << " /delete" << std::endl;
		std::cerr << "  Or try a different letter, e.g.: basalt-cli volume.tc Z:" << ansiReset << std::endl;
		return 1;
	}
#endif
	catch (exception &e)
	{
		std::cerr << ansiRed << "Error: " << ansiReset << W (StringConverter::ToExceptionString (e)) << std::endl;
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
