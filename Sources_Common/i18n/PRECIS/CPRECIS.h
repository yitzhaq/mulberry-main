/*
    Copyright (c) 2026 Mulberry contributors. All rights reserved.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/


// Header for CPRECIS class
//
// RFC 8265 — PRECIS profiles for usernames and passwords
// RFC 8264 — PRECIS framework (derived property algorithm)

#ifndef __CPRECIS__MULBERRY__
#define __CPRECIS__MULBERRY__

#include "cdstring.h"

namespace precis
{

class CPRECIS
{
public:
	static cdstring EnforceUsernameCasePreserved(const cdstring& input);
	static cdstring EnforceUsernameCaseMapped(const cdstring& input);
	static cdstring EnforceOpaqueString(const cdstring& input);

private:
	enum EPRECISProperty
	{
		ePVALID,
		eFreePval,
		eCONTEXTJ,
		eCONTEXTO,
		eDISALLOWED,
		eUNASSIGNED
	};

	static EPRECISProperty	GetDerivedProperty(uint32_t cp);
	static EPRECISProperty	GetException(uint32_t cp);
	static bool				IsOldHangulJamo(uint32_t cp);
	static bool				HasCompat(uint32_t cp);

	static cdstring			WidthMap(const cdstring& input);
	static cdstring			MapNonASCIISpace(const cdstring& input);
	static cdstring			NormalizeNFC(const cdstring& input);
	static cdstring			CaseMapLower(const cdstring& input);

	static void				ValidateIdentifierClass(const uint32_t* cps, size_t len);
	static void				ValidateFreeformClass(const uint32_t* cps, size_t len);
	static bool				CheckBidiRule(const uint32_t* cps, size_t len);

	static bool				ValidateContextJ(const uint32_t* cps, size_t len, size_t pos);
	static bool				ValidateContextO(const uint32_t* cps, size_t len, size_t pos);

	static void				UTF8ToUCS4(const cdstring& input, uint32_t*& cps, size_t& len);
	static cdstring			UCS4ToUTF8(const uint32_t* cps, size_t len);
};

}
#endif
