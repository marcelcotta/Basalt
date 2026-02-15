/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <windows.h>
#include "Process.h"
#include "Platform/Exception.h"
#include "Platform/SystemException.h"
#include "Platform/StringConverter.h"

namespace Basalt
{
	string Process::Execute (const string &processName, const list <string> &arguments, int timeOut, ProcessExecFunctor *execFunctor, const Buffer *inputData)
	{
		// ProcessExecFunctor is a Unix-only concept (fork+exec in child).
		// On Windows, if an execFunctor is provided, call it directly in-process.
		if (execFunctor)
		{
			char *args[32];
			int argIndex = 0;

			for (list <string>::const_iterator it = arguments.begin(); it != arguments.end() && argIndex < 31; ++it)
				args[argIndex++] = const_cast <char*> (it->c_str());
			args[argIndex] = nullptr;

			(*execFunctor)(argIndex, args);
			return string();
		}

		// Build command line
		string cmdLine = "\"" + processName + "\"";
		for (const auto &arg : arguments)
		{
			cmdLine += " \"" + arg + "\"";
		}

		// Set up pipes for stdout/stderr capture
		SECURITY_ATTRIBUTES sa = {};
		sa.nLength = sizeof (sa);
		sa.bInheritHandle = TRUE;
		sa.lpSecurityDescriptor = NULL;

		HANDLE hStdOutRead = NULL, hStdOutWrite = NULL;
		HANDLE hStdErrRead = NULL, hStdErrWrite = NULL;
		HANDLE hStdInRead = NULL, hStdInWrite = NULL;

		throw_sys_if (!CreatePipe (&hStdOutRead, &hStdOutWrite, &sa, 0));
		throw_sys_if (!SetHandleInformation (hStdOutRead, HANDLE_FLAG_INHERIT, 0));

		throw_sys_if (!CreatePipe (&hStdErrRead, &hStdErrWrite, &sa, 0));
		throw_sys_if (!SetHandleInformation (hStdErrRead, HANDLE_FLAG_INHERIT, 0));

		if (inputData)
		{
			throw_sys_if (!CreatePipe (&hStdInRead, &hStdInWrite, &sa, 0));
			throw_sys_if (!SetHandleInformation (hStdInWrite, HANDLE_FLAG_INHERIT, 0));
		}

		STARTUPINFOA si = {};
		si.cb = sizeof (si);
		si.hStdOutput = hStdOutWrite;
		si.hStdError = hStdErrWrite;
		si.hStdInput = inputData ? hStdInRead : GetStdHandle (STD_INPUT_HANDLE);
		si.dwFlags = STARTF_USESTDHANDLES;

		PROCESS_INFORMATION pi = {};

		BOOL created = CreateProcessA (
			NULL,
			const_cast <char*> (cmdLine.c_str()),
			NULL, NULL, TRUE, CREATE_NO_WINDOW,
			NULL, NULL, &si, &pi);

		// Close write ends of pipes (they're now owned by the child)
		CloseHandle (hStdOutWrite);
		CloseHandle (hStdErrWrite);
		if (hStdInRead)
			CloseHandle (hStdInRead);

		if (!created)
		{
			CloseHandle (hStdOutRead);
			CloseHandle (hStdErrRead);
			if (hStdInWrite)
				CloseHandle (hStdInWrite);
			throw SystemException (SRC_POS, processName);
		}

		// Write input data
		if (inputData && hStdInWrite)
		{
			DWORD written;
			WriteFile (hStdInWrite, inputData->Ptr(), (DWORD) inputData->Size(), &written, NULL);
			CloseHandle (hStdInWrite);
			hStdInWrite = NULL;
		}

		// Read stdout and stderr
		string stdOutput, errOutput;
		char buffer[4096];
		DWORD bytesRead;

		// Read stdout
		while (ReadFile (hStdOutRead, buffer, sizeof (buffer), &bytesRead, NULL) && bytesRead > 0)
			stdOutput.append (buffer, bytesRead);

		// Read stderr
		while (ReadFile (hStdErrRead, buffer, sizeof (buffer), &bytesRead, NULL) && bytesRead > 0)
			errOutput.append (buffer, bytesRead);

		// Wait for process to exit
		DWORD waitTimeout = (timeOut >= 0) ? (DWORD) timeOut : INFINITE;
		DWORD waitResult = WaitForSingleObject (pi.hProcess, waitTimeout);

		if (waitResult == WAIT_TIMEOUT)
		{
			TerminateProcess (pi.hProcess, 1);
			CloseHandle (pi.hProcess);
			CloseHandle (pi.hThread);
			CloseHandle (hStdOutRead);
			CloseHandle (hStdErrRead);
			throw TimeOut (SRC_POS);
		}

		DWORD exitCode = 1;
		GetExitCodeProcess (pi.hProcess, &exitCode);

		CloseHandle (pi.hProcess);
		CloseHandle (pi.hThread);
		CloseHandle (hStdOutRead);
		CloseHandle (hStdErrRead);

		if (exitCode != 0)
			throw ExecutedProcessFailed (SRC_POS, processName, exitCode, errOutput);

		return stdOutput;
	}
}
