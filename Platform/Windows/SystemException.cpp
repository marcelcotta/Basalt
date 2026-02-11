/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include <string.h>
#include "Platform/SerializerFactory.h"
#include "Platform/SystemException.h"
#include "Platform/StringConverter.h"

namespace TrueCrypt
{
	SystemException::SystemException ()
		: ErrorCode ((int64) GetLastError ())
	{
	}

	SystemException::SystemException (const string &message)
		: Exception (message), ErrorCode ((int64) GetLastError ())
	{
	}

	SystemException::SystemException (const string &message, const string &subject)
		: Exception (message, StringConverter::ToWide (subject)), ErrorCode ((int64) GetLastError ())
	{
	}

	SystemException::SystemException (const string &message, const wstring &subject)
		: Exception (message, subject), ErrorCode ((int64) GetLastError ())
	{
	}

	void SystemException::Deserialize (shared_ptr <Stream> stream)
	{
		Exception::Deserialize (stream);
		Serializer sr (stream);
		sr.Deserialize ("ErrorCode", ErrorCode);
	}

	bool SystemException::IsError () const
	{
		return ErrorCode != 0;
	}

	void SystemException::Serialize (shared_ptr <Stream> stream) const
	{
		Exception::Serialize (stream);
		Serializer sr (stream);
		sr.Serialize ("ErrorCode", ErrorCode);
	}

	wstring SystemException::SystemText () const
	{
		wchar_t *msgBuf = nullptr;
		DWORD len = FormatMessageW (
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			(DWORD) ErrorCode,
			MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPWSTR) &msgBuf,
			0,
			NULL);

		wstring result;
		if (len > 0 && msgBuf)
		{
			result = msgBuf;

			// Remove trailing \r\n
			while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n'))
				result.pop_back();

			LocalFree (msgBuf);
		}
		else
		{
			wstringstream s;
			s << L"Error code " << ErrorCode;
			result = s.str();
		}

		return result;
	}

#define TC_EXCEPTION(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)
#undef TC_EXCEPTION_NODECL
#define TC_EXCEPTION_NODECL(TYPE) TC_SERIALIZER_FACTORY_ADD(TYPE)

	TC_SERIALIZER_FACTORY_ADD_EXCEPTION_SET (SystemException);
}
