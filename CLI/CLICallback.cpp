/*
 Copyright (c) 2024-2026 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "CLICallback.h"
#include "Core/RandomNumberGenerator.h"

#ifdef TC_UNIX
#include <termios.h>
#include <unistd.h>
#endif

#include <iostream>
#include <cwchar>
#include <string>
#include <sstream>

namespace Basalt
{
	wstring CLICallback::ReadLine () const
	{
		string line;
		if (!std::getline (std::cin, line))
			throw UserAbort (SRC_POS);
		return StringConverter::ToWide (line);
	}

	void CLICallback::SetTerminalEcho (bool enable)
	{
#ifdef TC_UNIX
		struct termios tios;
		if (tcgetattr (STDIN_FILENO, &tios) == 0)
		{
			if (enable)
				tios.c_lflag |= ECHO;
			else
				tios.c_lflag &= ~ECHO;

			tcsetattr (STDIN_FILENO, TCSADRAIN, &tios);
		}
#endif
	}

	shared_ptr <VolumePassword> CLICallback::AskPassword (const wstring &message)
	{
		if (NonInteractive)
			throw ParameterIncorrect (SRC_POS);

		if (!message.empty ())
			std::wcerr << message << L" ";
		else
			std::wcerr << L"Enter password: ";

		SetTerminalEcho (false);
		wstring pw = ReadLine ();
		SetTerminalEcho (true);
		std::wcerr << std::endl;

		return make_shared <VolumePassword> (pw);
	}

	shared_ptr <KeyfileList> CLICallback::AskKeyfiles (const wstring &message)
	{
		if (NonInteractive)
			return shared_ptr <KeyfileList> ();

		auto keyfiles = make_shared <KeyfileList> ();

		std::wcerr << L"Enter keyfile path [none]: ";
		while (true)
		{
			wstring path = ReadLine ();
			if (path.empty ())
				break;

			keyfiles->push_back (make_shared <Keyfile> (path));
			std::wcerr << L"Enter next keyfile path [done]: ";
		}

		return keyfiles->empty () ? shared_ptr <KeyfileList> () : keyfiles;
	}

	void CLICallback::AskCredentials (MountOptions &options, const wstring &message)
	{
		options.Password = AskPassword (message);
		options.Keyfiles = AskKeyfiles ();
	}

	FilePath CLICallback::AskFilePath (const wstring &message)
	{
		if (NonInteractive)
			throw ParameterIncorrect (SRC_POS);

		if (!message.empty ())
			std::wcerr << message << L": ";
		else
			std::wcerr << L"Enter file path: ";

		wstring path = ReadLine ();
		return FilePath (path);
	}

	FilePath CLICallback::AskNewFilePath (const wstring &message)
	{
		if (NonInteractive)
			throw ParameterIncorrect (SRC_POS);

		if (!message.empty ())
			std::wcerr << message << L": ";
		else
			std::wcerr << L"Enter new file path: ";

		wstring path = ReadLine ();
		return FilePath (path);
	}

	bool CLICallback::AskYesNo (const wstring &message, bool defaultYes, bool warning)
	{
		if (NonInteractive)
			return defaultYes;

		std::wcerr << message;
		if (defaultYes)
			std::wcerr << L" [Y/n]: ";
		else
			std::wcerr << L" [y/N]: ";

		wstring answer = ReadLine ();
		if (answer.empty ())
			return defaultYes;

		return (answer[0] == L'y' || answer[0] == L'Y');
	}

	int CLICallback::AskSelection (const vector <wstring> &choices, const wstring &prompt)
	{
		if (NonInteractive)
			return 0;

		if (!prompt.empty ())
			std::wcerr << std::endl << prompt << std::endl;

		for (size_t i = 0; i < choices.size (); ++i)
			std::wcerr << L"  " << (i + 1) << L") " << choices[i] << std::endl;

		std::wcerr << L"Select [1]: ";
		wstring answer = ReadLine ();
		if (answer.empty ())
			return 0;

		try
		{
			int sel = std::stoi (StringConverter::ToSingle (answer));
			if (sel < 1 || (size_t) sel > choices.size ())
				return -1;
			return sel - 1;
		}
		catch (...)
		{
			return -1;
		}
	}

	void CLICallback::ShowInfo (const wstring &message)
	{
		std::wcout << message << std::endl;
	}

	void CLICallback::ShowWarning (const wstring &message)
	{
		std::wcerr << L"Warning: " << message << std::endl;
	}

	void CLICallback::ShowError (const wstring &message)
	{
		std::wcerr << L"Error: " << message << std::endl;
	}

	// ANSI color helpers (detect TTY once)
	static bool IsTTY ()
	{
#ifdef TC_UNIX
		return isatty (STDERR_FILENO) != 0;
#else
		return false;
#endif
	}

	void CLICallback::EnrichRandomPool (shared_ptr <Hash> hash)
	{
		RandomNumberGenerator::Start ();
		if (hash)
			RandomNumberGenerator::SetHash (hash);

		if (NonInteractive)
			return;

		const int goal = 64;  // recommended character count
		bool colorEnabled = IsTTY ();

		std::cerr << "Type random characters to add extra entropy, or press Enter to skip" << std::endl;
		std::cerr << "(system entropy from the OS is already sufficient)" << std::endl;

		if (colorEnabled)
			std::cerr << "\033[2m" << "  [" << goal << " chars recommended]" << "\033[0m" << std::endl;

		std::cerr << "  ";

		// Draw initial counter
		if (colorEnabled)
			std::cerr << "\033[31m" << "0/" << goal << "\033[0m" << " " << std::flush;

#ifdef TC_UNIX
		// Raw terminal mode: read one char at a time, no echo, no line buffering
		struct termios origTios, rawTios;
		bool tiosOk = (tcgetattr (STDIN_FILENO, &origTios) == 0);
		if (tiosOk)
		{
			rawTios = origTios;
			rawTios.c_lflag &= ~(ECHO | ICANON);  // no echo, no canonical mode
			rawTios.c_cc[VMIN] = 1;                 // read 1 byte at a time
			rawTios.c_cc[VTIME] = 0;                // no timeout
			tcsetattr (STDIN_FILENO, TCSADRAIN, &rawTios);
		}

		string collected;
		while (true)
		{
			char ch;
			ssize_t n = read (STDIN_FILENO, &ch, 1);
			if (n <= 0)
				break;

			// Enter = done
			if (ch == '\n' || ch == '\r')
				break;

			// Backspace handling (don't accumulate control chars)
			if (ch == 127 || ch == '\b')
			{
				if (!collected.empty ())
					collected.pop_back ();
			}
			else if (ch >= 32)  // printable only
			{
				collected += ch;
			}

			// Update live counter with color gradient
			if (colorEnabled)
			{
				int count = (int) collected.size ();
				int pct = std::min (count * 100 / goal, 100);

				// Color: red (0%) → yellow (50%) → green (100%)
				const char *color;
				if (pct < 33)
					color = "\033[31m";       // red
				else if (pct < 66)
					color = "\033[33m";       // yellow
				else if (pct < 100)
					color = "\033[32m";       // green
				else
					color = "\033[32m\033[1m"; // bright green (goal reached)

				// Build mini-bar: 10 segments
				const int barWidth = 10;
				int filled = std::min (count * barWidth / goal, barWidth);
				std::string bar;
				for (int i = 0; i < barWidth; ++i)
					bar += (i < filled) ? "\xe2\x96\x88" : "\xe2\x96\x91";

				std::cerr << "\r  " << color << bar << " " << count << "/" << goal;
				if (count >= goal)
					std::cerr << " \xe2\x9c\x93";
				std::cerr << "\033[0m" << "   " << std::flush;
			}
		}

		// Restore terminal
		if (tiosOk)
			tcsetattr (STDIN_FILENO, TCSADRAIN, &origTios);

		std::cerr << std::endl;

		if (!collected.empty ())
		{
			RandomNumberGenerator::AddToPool (ConstBufferPtr (
				reinterpret_cast <const byte *> (collected.data ()), collected.size ()));

			if (colorEnabled)
				std::cerr << "\033[32m" << "\xe2\x9c\x93 " << "\033[0m"
				          << "Added " << collected.size () << " bytes of user entropy." << std::endl;
			else
				std::cerr << "Added " << collected.size () << " bytes of user entropy." << std::endl;
		}
#else
		// Windows fallback: simple line-based input (no raw mode)
		SetTerminalEcho (false);
		wstring input = ReadLine ();
		SetTerminalEcho (true);

		if (!input.empty ())
		{
			string utf8 = StringConverter::ToSingle (input);
			RandomNumberGenerator::AddToPool (ConstBufferPtr (
				reinterpret_cast <const byte *> (utf8.data ()), utf8.size ()));
			std::cerr << "Added " << utf8.size () << " bytes of user entropy." << std::endl;
		}
		else
		{
			std::cerr << std::endl;
		}
#endif
	}
}
