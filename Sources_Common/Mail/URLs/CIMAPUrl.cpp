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


// CIMAPUrl.cpp — IMAP URL parser/builder per RFC 5092

#include "CIMAPUrl.h"

#include "CIMAPCommon.h"
#include "CURL.h"

#include <cstdlib>
#include <cstring>
#include <cctype>

static const char* cIMAPScheme = "imap://";
static const size_t cIMAPSchemeLen = 7;

CIMAPUrl::CIMAPUrl()
{
	_Init();
}

CIMAPUrl::CIMAPUrl(const cdstring& url)
{
	_Init();
	Parse(url);
}

CIMAPUrl::CIMAPUrl(const CIMAPUrl& copy)
{
	_Copy(copy);
}

CIMAPUrl::~CIMAPUrl()
{
}

CIMAPUrl& CIMAPUrl::operator=(const CIMAPUrl& copy)
{
	if (this != &copy)
		_Copy(copy);
	return *this;
}

void CIMAPUrl::_Init()
{
	mPort = 0;
	mUIDValidity = 0;
	mUID = 0;
	mHasPartial = false;
	mPartialOffset = 0;
	mPartialLength = 0;
	mHasUrlAuth = false;
	mAccess = eIMAPUrlAccessNone;
}

void CIMAPUrl::_Copy(const CIMAPUrl& copy)
{
	mUser = copy.mUser;
	mAuthMechanism = copy.mAuthMechanism;
	mServer = copy.mServer;
	mPort = copy.mPort;
	mMailbox = copy.mMailbox;
	mUIDValidity = copy.mUIDValidity;
	mUID = copy.mUID;
	mSection = copy.mSection;
	mSearch = copy.mSearch;
	mHasPartial = copy.mHasPartial;
	mPartialOffset = copy.mPartialOffset;
	mPartialLength = copy.mPartialLength;
	mHasUrlAuth = copy.mHasUrlAuth;
	mAccess = copy.mAccess;
	mAccessUser = copy.mAccessUser;
	mAccessApplication = copy.mAccessApplication;
	mExpire = copy.mExpire;
	mMechanism = copy.mMechanism;
	mToken = copy.mToken;
}

// RFC 5092 section 11 ABNF:
//   imapurl = "imap://" iserver ipath-query
//   iserver = [iuserinfo "@"] host [":" port]
//   iuserinfo = enc-user [iauth] / [enc-user] iauth
//   iauth = ";AUTH=" ("*" / enc-auth-type)
//   ipath-query = ["/" [icommand]]
//   icommand = imessagelist / imessagepart [iurlauth]
//   imailbox-ref = enc-mailbox [uidvalidity]
//   imessagelist = imailbox-ref ["?" enc-search]
//   imessagepart = imailbox-ref iuid [isection] [ipartial]
//   iuid = "/;UID=" nz-number
//   isection = "/;SECTION=" enc-section
//   ipartial = "/;PARTIAL=" partial-range
//   partial-range = number ["." nz-number]
//   iurlauth = iurlauth-rump iua-verifier
//   iurlauth-rump = [expire] ";URLAUTH=" access
//   expire = ";EXPIRE=" date-time
//   access = ("submit+" enc-user) / ("user+" enc-user) /
//            "authuser" / "anonymous" / application / (application "+" enc-user)
//   iua-verifier = ":" uauth-mechanism ":" enc-urlauth

void CIMAPUrl::Parse(const cdstring& url)
{
	_Init();

	if (url.empty())
		return;

	const char* p = url.c_str();

	// Absolute URL: starts with "imap://"
	if (::strncasecmp(p, cIMAPScheme, cIMAPSchemeLen) == 0)
	{
		p += cIMAPSchemeLen;
		ParseServerComponent(p);

		if (*p == '/')
		{
			p++;
			if (*p)
				ParsePathComponent(p);
		}
	}
	// Relative URL: starts with "/" (absolute-path reference)
	else if (*p == '/')
	{
		p++;
		if (*p)
			ParsePathComponent(p);
	}
}

// iserver = [iuserinfo "@"] host [":" port]
// iuserinfo = enc-user [iauth] / [enc-user] iauth
// iauth = ";AUTH=" ("*" / enc-auth-type)
void CIMAPUrl::ParseServerComponent(const char*& p)
{
	// Find the end of the server component (terminated by "/" or end)
	const char* server_end = ::strchr(p, '/');
	if (!server_end)
		server_end = p + ::strlen(p);

	// Extract the server portion as a working string
	cdstring server_str(p, server_end - p);
	const char* s = server_str.c_str();

	// Look for "@" to separate userinfo from host
	const char* at = NULL;
	for (const char* scan = s; scan < s + server_str.length(); scan++)
	{
		if (*scan == '@')
		{
			at = scan;
			break;
		}
	}

	if (at)
	{
		// Parse iuserinfo before the "@"
		cdstring userinfo(s, at - s);

		// Look for ";AUTH=" in userinfo
		const char* auth_pos = ::strcasestr(userinfo.c_str(), ";AUTH=");
		if (auth_pos)
		{
			// User is everything before ";AUTH="
			if (auth_pos > userinfo.c_str())
			{
				cdstring user(userinfo.c_str(), auth_pos - userinfo.c_str());
				user.DecodeURL();
				mUser = user;
			}

			// Auth mechanism is everything after ";AUTH="
			cdstring auth(auth_pos + 6);
			if (auth == "*")
				mAuthMechanism = "*";
			else
			{
				auth.DecodeURL();
				mAuthMechanism = auth;
			}
		}
		else
		{
			// No auth — entire userinfo is the user
			cdstring user(userinfo);
			user.DecodeURL();
			mUser = user;
		}

		s = at + 1;
	}

	// Parse host[:port] from remainder
	const char* colon = NULL;
	if (*s == '[')
	{
		// IPv6 literal: skip to closing ']'
		const char* bracket = ::strchr(s, ']');
		if (bracket)
		{
			mServer.assign(s, bracket + 1 - s);
			s = bracket + 1;
			if (*s == ':')
				colon = s;
		}
	}
	else
	{
		// Look for port separator
		colon = ::strrchr(s, ':');
	}

	if (colon)
	{
		mServer.assign(s, colon - s);
		mPort = (unsigned short)::strtoul(colon + 1, NULL, 10);
	}
	else
	{
		mServer = s;
	}

	p = server_end;
}

// Parse the path after the leading "/" in an absolute URL.
// imessagepart = imailbox-ref iuid [isection] [ipartial]
// imailbox-ref = enc-mailbox [uidvalidity]
// imessagelist = imailbox-ref ["?" enc-search]
void CIMAPUrl::ParsePathComponent(const char*& p)
{
	// The path contains: enc-mailbox [;UIDVALIDITY=n] [/;UID=n [/;SECTION=s] [/;PARTIAL=o.l]]
	//                    [;EXPIRE=datetime] [;URLAUTH=access[:mech:token]]
	//
	// Strategy: scan forward, collecting the mailbox name up to the first
	// recognized parameter delimiter (";UIDVALIDITY=", "/;UID=", ";EXPIRE=",
	// ";URLAUTH=", or "?")

	const char* start = p;

	// Find the end of the mailbox portion
	// The mailbox name is everything up to the first ";UIDVALIDITY=", "/;UID=",
	// ";EXPIRE=", ";URLAUTH=", or "?" at the path level
	const char* mbox_end = p;
	while (*mbox_end)
	{
		if (*mbox_end == '?')
			break;

		// Check for parameter delimiters
		if (*mbox_end == ';')
		{
			if (::strncasecmp(mbox_end, ";UIDVALIDITY=", 13) == 0)
				break;
			if (::strncasecmp(mbox_end, ";EXPIRE=", 8) == 0)
				break;
			if (::strncasecmp(mbox_end, ";URLAUTH=", 9) == 0)
				break;
		}

		if (*mbox_end == '/' && *(mbox_end + 1) == ';')
		{
			if (::strncasecmp(mbox_end + 1, ";UID=", 5) == 0)
				break;
			if (::strncasecmp(mbox_end + 1, ";SECTION=", 9) == 0)
				break;
			if (::strncasecmp(mbox_end + 1, ";PARTIAL=", 9) == 0)
				break;
		}

		mbox_end++;
	}

	if (mbox_end > start)
	{
		cdstring enc_mbox(start, mbox_end - start);
		mMailbox = DecodeMailboxFromUrl(enc_mbox);
	}

	p = mbox_end;

	// Parse optional components in order
	ParseUidValidity(p);

	// "?" enc-search — search query (imessagelist form, mutually exclusive with iuid)
	if (*p == '?')
	{
		p++;
		cdstring search(p);
		search.DecodeURL();
		mSearch = search;
		p += ::strlen(p);
		return;
	}

	ParseUid(p);
	ParseSection(p);
	ParsePartial(p);
	ParseExpire(p);
	ParseUrlAuth(p);
}

// ";UIDVALIDITY=" nz-number
void CIMAPUrl::ParseUidValidity(const char*& p)
{
	if (::strncasecmp(p, ";UIDVALIDITY=", 13) == 0)
	{
		p += 13;
		mUIDValidity = ::strtoul(p, const_cast<char**>(&p), 10);
	}
}

// "/;UID=" nz-number
void CIMAPUrl::ParseUid(const char*& p)
{
	if (::strncasecmp(p, "/;UID=", 6) == 0)
	{
		p += 6;
		mUID = ::strtoul(p, const_cast<char**>(&p), 10);
	}
}

// "/;SECTION=" enc-section
void CIMAPUrl::ParseSection(const char*& p)
{
	if (::strncasecmp(p, "/;SECTION=", 10) == 0)
	{
		p += 10;

		// Section value extends to the next "/" or ";" or end
		const char* end = p;
		while (*end && *end != '/')
		{
			if (*end == ';')
			{
				if (::strncasecmp(end, ";EXPIRE=", 8) == 0)
					break;
				if (::strncasecmp(end, ";URLAUTH=", 9) == 0)
					break;
			}
			end++;
		}

		cdstring section(p, end - p);
		section.DecodeURL();
		mSection = section;
		p = end;
	}
}

// "/;PARTIAL=" partial-range
// partial-range = number ["." nz-number]
void CIMAPUrl::ParsePartial(const char*& p)
{
	if (::strncasecmp(p, "/;PARTIAL=", 10) == 0)
	{
		p += 10;
		mHasPartial = true;
		mPartialOffset = ::strtoul(p, const_cast<char**>(&p), 10);
		if (*p == '.')
		{
			p++;
			mPartialLength = ::strtoul(p, const_cast<char**>(&p), 10);
		}
		else
		{
			mPartialLength = 0;
		}
	}
}

// ";EXPIRE=" date-time (RFC 3339)
void CIMAPUrl::ParseExpire(const char*& p)
{
	if (::strncasecmp(p, ";EXPIRE=", 8) == 0)
	{
		p += 8;

		// Date-time extends to the next ";" or end
		const char* end = p;
		while (*end && *end != ';')
			end++;

		mExpire.assign(p, end - p);
		p = end;
	}
}

// ";URLAUTH=" access [":" mechanism ":" token]
void CIMAPUrl::ParseUrlAuth(const char*& p)
{
	if (::strncasecmp(p, ";URLAUTH=", 9) == 0)
	{
		p += 9;
		mHasUrlAuth = true;

		ParseAccess(p);
		ParseMechToken(p);
	}
}

// access = ("submit+" enc-user) / ("user+" enc-user) /
//          "authuser" / "anonymous" /
//          application / (application "+" enc-user)   (RFC 5593)
void CIMAPUrl::ParseAccess(const char*& p)
{
	if (::strncasecmp(p, "submit+", 7) == 0)
	{
		p += 7;
		mAccess = eIMAPUrlAccessSubmit;

		const char* end = p;
		while (*end && *end != ':' && *end != ';')
			end++;
		cdstring user(p, end - p);
		user.DecodeURL();
		mAccessUser = user;
		p = end;
	}
	else if (::strncasecmp(p, "user+", 5) == 0)
	{
		p += 5;
		mAccess = eIMAPUrlAccessUser;

		const char* end = p;
		while (*end && *end != ':' && *end != ';')
			end++;
		cdstring user(p, end - p);
		user.DecodeURL();
		mAccessUser = user;
		p = end;
	}
	else if (::strncasecmp(p, "authuser", 8) == 0)
	{
		p += 8;
		mAccess = eIMAPUrlAccessAuthUser;
	}
	else if (::strncasecmp(p, "anonymous", 9) == 0)
	{
		p += 9;
		mAccess = eIMAPUrlAccessAnonymous;
	}
	else if (::strncasecmp(p, "stream", 6) == 0)
	{
		p += 6;
		mAccess = eIMAPUrlAccessStream;

		// "stream+" prefix with user?
		if (*p == '+')
		{
			p++;
			const char* end = p;
			while (*end && *end != ':' && *end != ';')
				end++;
			cdstring user(p, end - p);
			user.DecodeURL();
			mAccessUser = user;
			p = end;
		}
	}
	else
	{
		// RFC 5593: generic application / (application "+" enc-user)
		mAccess = eIMAPUrlAccessApplication;
		const char* end = p;
		while (*end && *end != ':' && *end != ';' && *end != '+')
			end++;

		cdstring app(p, end - p);
		mAccessApplication = app;
		p = end;

		if (*p == '+')
		{
			p++;
			end = p;
			while (*end && *end != ':' && *end != ';')
				end++;
			cdstring user(p, end - p);
			user.DecodeURL();
			mAccessUser = user;
			p = end;
		}
	}
}

// ":" uauth-mechanism ":" enc-urlauth
void CIMAPUrl::ParseMechToken(const char*& p)
{
	if (*p != ':')
		return;

	p++;

	// Mechanism extends to the next ":"
	const char* colon = ::strchr(p, ':');
	if (!colon)
		return;

	mMechanism.assign(p, colon - p);
	p = colon + 1;

	// Token is the rest — RFC 5092: enc-urlauth = 32*HEXDIG
	const char* t = p;
	size_t len = 0;
	bool valid = true;
	while (*t)
	{
		if (!::isxdigit((unsigned char)*t))
		{
			valid = false;
			break;
		}
		t++;
		len++;
	}

	if (valid && len >= 32)
		mToken.assign(p, len);

	p = t;
}

// imap://[user[;AUTH=mech]@]server[:port]/
void CIMAPUrl::BuildServerComponent(cdstring& result) const
{
	result += cIMAPScheme;

	if (!mUser.empty())
	{
		cdstring enc_user(mUser);
		enc_user.EncodeURL();
		result += enc_user;

		if (!mAuthMechanism.empty())
		{
			result += ";AUTH=";
			if (mAuthMechanism == "*")
				result += "*";
			else
			{
				cdstring enc_auth(mAuthMechanism);
				enc_auth.EncodeURL();
				result += enc_auth;
			}
		}

		result += "@";
	}
	else if (!mAuthMechanism.empty())
	{
		result += ";AUTH=";
		if (mAuthMechanism == "*")
			result += "*";
		else
		{
			cdstring enc_auth(mAuthMechanism);
			enc_auth.EncodeURL();
			result += enc_auth;
		}
		result += "@";
	}

	result += mServer;
	if (mPort != 0 && mPort != cIMAPServerPort)
	{
		result += ":";
		result += cdstring(static_cast<unsigned long>(mPort));
	}

	result += "/";
}

cdstring CIMAPUrl::ToFullUrl() const
{
	cdstring result;

	BuildServerComponent(result);
	BuildPathComponent(result);

	if (!mMechanism.empty() && !mToken.empty())
	{
		result += ":";
		result += mMechanism;
		result += ":";
		result += mToken;
	}

	return result;
}

cdstring CIMAPUrl::ToRumpUrl() const
{
	cdstring result;

	BuildServerComponent(result);
	BuildPathComponent(result);

	return result;
}

// Relative URL: path-only form for CATENATE references
// /mailbox;UIDVALIDITY=n/;UID=n/;SECTION=s/;PARTIAL=o.l
cdstring CIMAPUrl::ToRelativeUrl() const
{
	cdstring result("/");
	BuildPathComponent(result);
	return result;
}

// Common path builder used by all three serializers
void CIMAPUrl::BuildPathComponent(cdstring& result) const
{
	if (!mMailbox.empty())
	{
		result += EncodeMailboxForUrl(mMailbox);
	}

	if (mUIDValidity != 0)
	{
		result += ";UIDVALIDITY=";
		result += cdstring(mUIDValidity);
	}

	if (!mSearch.empty())
	{
		result += "?";
		cdstring enc_search(mSearch);
		enc_search.EncodeURL();
		result += enc_search;
		return;
	}

	if (mUID != 0)
	{
		result += "/;UID=";
		result += cdstring(mUID);
	}

	if (!mSection.empty())
	{
		result += "/;SECTION=";
		cdstring enc_section(mSection);
		enc_section.EncodeURL();
		result += enc_section;
	}

	if (mHasPartial)
	{
		result += "/;PARTIAL=";
		result += cdstring(mPartialOffset);
		if (mPartialLength != 0)
		{
			result += ".";
			result += cdstring(mPartialLength);
		}
	}

	if (!mExpire.empty())
	{
		result += ";EXPIRE=";
		result += mExpire;
	}

	if (mHasUrlAuth)
	{
		result += ";URLAUTH=";

		switch (mAccess)
		{
		case eIMAPUrlAccessAnonymous:
			result += "anonymous";
			break;
		case eIMAPUrlAccessAuthUser:
			result += "authuser";
			break;
		case eIMAPUrlAccessSubmit:
			{
				result += "submit+";
				cdstring enc_user(mAccessUser);
				enc_user.EncodeURL();
				result += enc_user;
			}
			break;
		case eIMAPUrlAccessUser:
			{
				result += "user+";
				cdstring enc_user(mAccessUser);
				enc_user.EncodeURL();
				result += enc_user;
			}
			break;
		case eIMAPUrlAccessStream:
			result += "stream";
			if (!mAccessUser.empty())
			{
				result += "+";
				cdstring enc_user(mAccessUser);
				enc_user.EncodeURL();
				result += enc_user;
			}
			break;
		case eIMAPUrlAccessApplication:
			result += mAccessApplication;
			if (!mAccessUser.empty())
			{
				result += "+";
				cdstring enc_user(mAccessUser);
				enc_user.EncodeURL();
				result += enc_user;
			}
			break;
		default:
			break;
		}
	}
}

void CIMAPUrl::SetAccess(EIMAPUrlAccess access, const cdstring& user)
{
	mHasUrlAuth = true;
	mAccess = access;
	mAccessUser = user;
	mAccessApplication.clear();
}

void CIMAPUrl::SetAccessApplication(const cdstring& app, const cdstring& user)
{
	mHasUrlAuth = true;
	mAccess = eIMAPUrlAccessApplication;
	mAccessApplication = app;
	mAccessUser = user;
}

bool CIMAPUrl::IsValid() const
{
	return !mServer.empty() || !mMailbox.empty();
}

bool CIMAPUrl::IsAbsoluteUrl() const
{
	return !mServer.empty();
}

bool CIMAPUrl::IsServerRef() const
{
	return !mServer.empty() && mMailbox.empty();
}

bool CIMAPUrl::IsMailboxRef() const
{
	return !mMailbox.empty() && mUID == 0 && mSearch.empty();
}

bool CIMAPUrl::IsSearchRef() const
{
	return !mMailbox.empty() && !mSearch.empty();
}

bool CIMAPUrl::IsMessageRef() const
{
	return !mMailbox.empty() && mUID != 0;
}

bool CIMAPUrl::Equal(const CIMAPUrl& comp) const
{
	return mServer == comp.mServer &&
		   mPort == comp.mPort &&
		   mUser == comp.mUser &&
		   mMailbox == comp.mMailbox &&
		   mUIDValidity == comp.mUIDValidity &&
		   mUID == comp.mUID &&
		   mSection == comp.mSection &&
		   mSearch == comp.mSearch &&
		   mHasPartial == comp.mHasPartial &&
		   mPartialOffset == comp.mPartialOffset &&
		   mPartialLength == comp.mPartialLength;
}

// RFC 5092 section 8: modified-UTF7 mailbox names must be converted to UTF-8,
// then percent-encoded for use in URLs
cdstring CIMAPUrl::EncodeMailboxForUrl(const cdstring& utf8_mbox)
{
	// Convert UTF-8 to modified-UTF7 for the wire, then percent-encode
	// Actually per RFC 5092: the URL carries UTF-8, not modified-UTF7
	// So we percent-encode the UTF-8 bytes directly
	cdstring result(utf8_mbox);
	result.EncodeURL('/');
	return result;
}

// Decode percent-encoded mailbox from URL.
// RFC 5092 says URLs carry UTF-8, but RFC 2192-era URLs may contain modified-UTF7.
cdstring CIMAPUrl::DecodeMailboxFromUrl(const cdstring& encoded_mbox)
{
	cdstring result(encoded_mbox);
	result.DecodeURL();

	// Detect modified-UTF7: contains '&' not followed by '-' (which would be literal '&')
	const char* p = result.c_str();
	bool has_mutf7 = false;
	while (*p)
	{
		if (*p == '&' && *(p + 1) != '-' && *(p + 1) != '\0')
		{
			has_mutf7 = true;
			break;
		}
		p++;
	}

	if (has_mutf7)
		result.FromModifiedUTF7(true);

	return result;
}

