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


// CAuthenticationResults.cp — RFC 8601 Authentication-Results parser

#include "CAuthenticationResults.h"

#include <cstring>
#include <cctype>

// IANA-registered authentication methods (RFC 8601 §2.7)
static const char* sKnownMethods[] = {
	"dkim", "spf", "sender-id", "auth", "dmarc",
	"iprev", "arc", "smime", "dkim-adsp",
	NULL
};

// IANA-registered result codes
static const char* sKnownResults[] = {
	"none", "pass", "fail", "softfail", "policy",
	"neutral", "temperror", "permerror", "hardfail",
	NULL
};

// IANA-registered property types (ptypes)
static const char* sKnownPtypes[] = {
	"smtp", "header", "body", "policy",
	NULL
};

static bool InList(const char** list, const cdstring& value)
{
	for (const char** p = list; *p != NULL; p++)
	{
		if (value.compare(*p, true) == 0)
			return true;
	}
	return false;
}

bool CAuthenticationResults::IsKnownMethod(const cdstring& method)
{
	return InList(sKnownMethods, method);
}

bool CAuthenticationResults::IsKnownResult(const cdstring& result)
{
	return InList(sKnownResults, result);
}

bool CAuthenticationResults::IsKnownPtype(const cdstring& ptype)
{
	return InList(sKnownPtypes, ptype);
}

void CAuthenticationResults::SkipCFWS(const char*& p)
{
	while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
		p++;

	// Skip RFC 5322 comments (may be consecutive)
	while (*p == '(')
	{
		int depth = 1;
		p++;
		while (*p && depth > 0)
		{
			if (*p == '(')
				depth++;
			else if (*p == ')')
				depth--;
			else if (*p == '\\' && *(p + 1))
				p++;
			p++;
		}
		// Skip trailing whitespace after comment
		while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
			p++;
	}
}

bool CAuthenticationResults::ParseToken(const char*& p, cdstring& token)
{
	SkipCFWS(p);
	const char* start = p;
	while (*p && *p != ' ' && *p != '\t' && *p != ';' && *p != '='
		&& *p != '/' && *p != '(' && *p != ')' && *p != '\r' && *p != '\n')
		p++;
	if (p == start)
		return false;
	token.assign(start, p - start);
	return true;
}

bool CAuthenticationResults::ParseQuotedOrToken(const char*& p, cdstring& value)
{
	SkipCFWS(p);
	if (*p == '"')
	{
		p++;
		const char* start = p;
		while (*p && *p != '"')
		{
			if (*p == '\\' && *(p + 1))
				p++;
			p++;
		}
		value.assign(start, p - start);
		if (*p == '"')
			p++;
		return true;
	}
	return ParseToken(p, value);
}

// Parse: method ["/" version] "=" result
//        *( [CFWS] ptype "." property "=" pvalue )
bool CAuthenticationResults::ParseMethodResult(const char*& p)
{
	SAuthMethod method;

	// Parse method name
	if (!ParseToken(p, method.mMethod))
		return false;

	// Optional version: "/" version
	SkipCFWS(p);
	if (*p == '/')
	{
		p++;
		cdstring version_str;
		if (ParseToken(p, version_str))
			method.mVersion = ::atol(version_str.c_str());
	}

	// Expect "="
	SkipCFWS(p);
	if (*p != '=')
		return false;
	p++;

	// Parse result
	if (!ParseToken(p, method.mResult))
		return false;

	// RFC 8601 §4.1: MUST ignore unknown methods and results
	// RFC 8601 §2.6: SHOULD ignore results for unsupported method versions
	if (!IsKnownMethod(method.mMethod) || !IsKnownResult(method.mResult) || method.mVersion > 1)
		return true;  // skip this method but continue parsing

	// Parse optional reason
	SkipCFWS(p);
	if (*p == '(')
	{
		// Skip comment (reason string)
		SkipCFWS(p);
	}

	// Parse properties: ptype "." property "=" pvalue
	while (*p && *p != ';')
	{
		SkipCFWS(p);
		if (!*p || *p == ';')
			break;

		cdstring ptype_property;
		const char* prop_start = p;
		if (!ParseToken(p, ptype_property))
			break;

		// Must contain a dot separating ptype from property
		const char* dot = ::strchr(ptype_property.c_str(), '.');
		if (!dot)
		{
			// Not a ptype.property — might be a reason keyword, skip
			continue;
		}

		// Extract ptype
		cdstring ptype;
		ptype.assign(ptype_property.c_str(), dot - ptype_property.c_str());

		// RFC 8601 §4.1: MUST ignore unknown ptypes
		SkipCFWS(p);
		if (*p != '=')
			continue;
		p++;

		cdstring pvalue;
		ParseQuotedOrToken(p, pvalue);

		if (IsKnownPtype(ptype))
			method.mProperties.insert(cdstrmap::value_type(ptype_property, pvalue));
	}

	mResults.push_back(method);
	return true;
}

// Parse an Authentication-Results header value (after the field name)
//
// authserv-id [cfws version] ; method = result [props] [; method = result [props]] ...
//
// Also handles "authserv-id; none" (no authentication performed)
bool CAuthenticationResults::Parse(const char* value)
{
	if (!value || !*value)
		return false;

	const char* p = value;
	mResults.clear();

	// Parse authserv-id
	SkipCFWS(p);
	if (!ParseToken(p, mAuthservId))
		return false;

	// Optional header-field version
	SkipCFWS(p);
	if (*p && *p != ';')
	{
		cdstring maybe_version;
		const char* save = p;
		if (ParseToken(p, maybe_version))
		{
			// Check if it looks like a version number
			bool is_version = true;
			for (const char* c = maybe_version.c_str(); *c; c++)
			{
				if (!::isdigit(*c) && *c != '.')
				{
					is_version = false;
					break;
				}
			}
			if (is_version)
				mVersion = ::atol(maybe_version.c_str());
			else
				p = save;  // not a version, restore position
		}
	}

	// Expect ";"
	SkipCFWS(p);
	if (*p != ';')
		return mAuthservId.length() > 0;
	p++;

	// Check for "none" — no authentication performed
	SkipCFWS(p);
	{
		const char* save = p;
		cdstring token;
		if (ParseToken(p, token) && token.compare("none", true) == 0)
		{
			SkipCFWS(p);
			if (!*p || *p == ';')
				return true;  // valid: authserv-id; none
		}
		p = save;
	}

	// Parse method/result pairs separated by ";"
	int max_methods = 50;
	while (*p && max_methods-- > 0)
	{
		SkipCFWS(p);
		if (!*p)
			break;

		ParseMethodResult(p);

		// Skip to next ";" or end
		SkipCFWS(p);
		if (*p == ';')
			p++;
	}

	return mAuthservId.length() > 0;
}

cdstring CAuthenticationResults::GetPropertyValue(const cdstring& method, const cdstring& ptype_property) const
{
	for (std::vector<SAuthMethod>::const_iterator iter = mResults.begin();
		iter != mResults.end(); iter++)
	{
		if ((*iter).mMethod.compare(method, true) == 0)
		{
			cdstrmap::const_iterator found = (*iter).mProperties.find(ptype_property);
			if (found != (*iter).mProperties.end())
				return (*found).second;
		}
	}
	return cdstring::null_str;
}

cdstring CAuthenticationResults::GetDKIMDomain() const
{
	return GetPropertyValue("dkim", "header.d");
}

cdstring CAuthenticationResults::GetDMARCDomain() const
{
	return GetPropertyValue("dmarc", "header.from");
}

cdstring CAuthenticationResults::GetSPFDomain() const
{
	cdstring result = GetPropertyValue("spf", "smtp.mailfrom");
	if (result.empty())
		result = GetPropertyValue("spf", "smtp.helo");
	return result;
}

static cdstring ExtractDomain(const cdstring& addr)
{
	const char* at = ::strchr(addr.c_str(), '@');
	if (at)
		return cdstring(at + 1);
	return addr;
}

static bool DomainMatch(const cdstring& domain, const cdstring& target)
{
	if (domain.empty() || target.empty())
		return false;

	// Case-insensitive exact match
	if (domain.compare(target, true) == 0)
		return true;

	// Check if domain is a subdomain of target (e.g., "mx.example.com" matches "example.com")
	if (domain.length() > target.length() + 1)
	{
		const char* tail = domain.c_str() + domain.length() - target.length();
		if (*(tail - 1) == '.' && ::strcasecmp(tail, target.c_str()) == 0)
			return true;
	}

	// Check reverse: target is subdomain of domain
	if (target.length() > domain.length() + 1)
	{
		const char* tail = target.c_str() + target.length() - domain.length();
		if (*(tail - 1) == '.' && ::strcasecmp(tail, domain.c_str()) == 0)
			return true;
	}

	return false;
}

bool CAuthenticationResults::HasPassingDMARC(const cdstring& domain) const
{
	for (std::vector<SAuthMethod>::const_iterator iter = mResults.begin();
		iter != mResults.end(); iter++)
	{
		if ((*iter).mMethod.compare("dmarc", true) == 0 &&
			(*iter).mResult.compare("pass", true) == 0)
		{
			cdstring dmarc_domain = GetDMARCDomain();
			if (!dmarc_domain.empty())
				return DomainMatch(ExtractDomain(dmarc_domain), domain);
			return true;
		}
	}
	return false;
}

bool CAuthenticationResults::HasPassingDKIM(const cdstring& domain) const
{
	for (std::vector<SAuthMethod>::const_iterator iter = mResults.begin();
		iter != mResults.end(); iter++)
	{
		if ((*iter).mMethod.compare("dkim", true) == 0 &&
			(*iter).mResult.compare("pass", true) == 0)
		{
			cdstrmap::const_iterator found = (*iter).mProperties.find("header.d");
			if (found != (*iter).mProperties.end())
				return DomainMatch((*found).second, domain);
			return true;
		}
	}
	return false;
}

bool CAuthenticationResults::HasPassingSPF(const cdstring& domain) const
{
	for (std::vector<SAuthMethod>::const_iterator iter = mResults.begin();
		iter != mResults.end(); iter++)
	{
		if ((*iter).mMethod.compare("spf", true) == 0 &&
			(*iter).mResult.compare("pass", true) == 0)
		{
			cdstring spf_domain = GetSPFDomain();
			if (!spf_domain.empty())
				return DomainMatch(ExtractDomain(spf_domain), domain);
			return true;
		}
	}
	return false;
}

// RFC 8617: ARC chain validation pass recorded by the MTA.
// §5.2: arc=fail MUST be treated as no chain — we only match "pass".
bool CAuthenticationResults::HasPassingARC() const
{
	for (std::vector<SAuthMethod>::const_iterator iter = mResults.begin();
		iter != mResults.end(); iter++)
	{
		if ((*iter).mMethod.compare("arc", true) == 0 &&
			(*iter).mResult.compare("pass", true) == 0)
			return true;
	}
	return false;
}

int CAuthenticationResults::GetAuthLevel(const cdstring& domain) const
{
	if (HasPassingDMARC(domain))
		return 2;
	if (HasPassingDKIM(domain))
		return 2;
	if (HasPassingARC())
		return 2;
	if (HasPassingSPF(domain))
		return 1;
	return 0;
}
