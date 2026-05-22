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


// CAuthenticationResults.h — RFC 8601 Authentication-Results parser

#ifndef __CAUTHENTICATIONRESULTS__MULBERRY__
#define __CAUTHENTICATIONRESULTS__MULBERRY__

#include "cdstring.h"

#include <vector>

struct SAuthMethod
{
	cdstring mMethod;				// "dkim", "spf", "dmarc", etc.
	cdstring mResult;				// "pass", "fail", "none", etc.
	cdstrmap mProperties;			// "header.d" → "example.com"
	int mVersion;					// method version, 0 if absent

	SAuthMethod() : mVersion(0) {}
};

class CAuthenticationResults
{
public:
			CAuthenticationResults() : mVersion(0) {}
			~CAuthenticationResults() {}

	const cdstring&					GetAuthservId() const { return mAuthservId; }
	int								GetVersion() const { return mVersion; }
	const std::vector<SAuthMethod>&	GetResults() const { return mResults; }

	bool	Parse(const char* value);

	bool	HasPassingDMARC(const cdstring& domain) const;
	bool	HasPassingDKIM(const cdstring& domain) const;
	bool	HasPassingSPF(const cdstring& domain) const;
	bool	HasPassingARC() const;

	// 2 = DMARC/DKIM/ARC pass, 1 = SPF-only pass, 0 = no pass
	int		GetAuthLevel(const cdstring& domain) const;

	cdstring GetDKIMDomain() const;
	cdstring GetDMARCDomain() const;
	cdstring GetSPFDomain() const;

private:
	cdstring mAuthservId;
	int mVersion;
	std::vector<SAuthMethod> mResults;

	static bool IsKnownMethod(const cdstring& method);
	static bool IsKnownResult(const cdstring& result);
	static bool IsKnownPtype(const cdstring& ptype);

	static void SkipCFWS(const char*& p);
	static bool ParseToken(const char*& p, cdstring& token);
	static bool ParseQuotedOrToken(const char*& p, cdstring& value);
	bool ParseMethodResult(const char*& p);

	cdstring GetPropertyValue(const cdstring& method, const cdstring& ptype_property) const;
};

#endif
