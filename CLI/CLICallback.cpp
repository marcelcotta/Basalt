/*
 Copyright (c) 2024-2025 Basalt contributors. All rights reserved.

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

namespace TrueCrypt
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

	void CLICallback::EnrichRandomPool (shared_ptr <Hash> hash)
	{
		if (NonInteractive)
		{
			RandomNumberGenerator::Start ();
			if (hash)
				RandomNumberGenerator::SetHash (hash);
			return;
		}

		RandomNumberGenerator::Start ();
		if (hash)
			RandomNumberGenerator::SetHash (hash);

		std::wcerr << L"Please type at least 320 random characters and then press Enter:" << std::endl;

		SetTerminalEcho (false);
		wstring input = ReadLine ();
		SetTerminalEcho (true);

		if (!input.empty ())
		{
			string utf8 = StringConverter::ToSingle (input);
			RandomNumberGenerator::AddToPool (ConstBufferPtr (
				reinterpret_cast <const byte *> (utf8.data ()), utf8.size ()));
		}
	}
}
