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


// CIMAPUrl.h — IMAP URL parser/builder per RFC 5092, RFC 4467, RFC 5593, RFC 5524, RFC 5550

#ifndef __CIMAPURL__MULBERRY__
#define __CIMAPURL__MULBERRY__

#include "cdstring.h"

#include <vector>

// URLAUTH access identifiers (RFC 5092 section 6.1, RFC 5593)
enum EIMAPUrlAccess
{
	eIMAPUrlAccessNone = 0,
	eIMAPUrlAccessAnonymous,
	eIMAPUrlAccessAuthUser,
	eIMAPUrlAccessSubmit,
	eIMAPUrlAccessUser,
	eIMAPUrlAccessStream,
	eIMAPUrlAccessApplication
};

// CATENATE part (RFC 4469)
struct SCatenatePart
{
	bool		mIsUrl;
	cdstring	mData;
};
typedef std::vector<SCatenatePart> SCatenatePartList;

// URLFETCH result item (RFC 4467, RFC 5524)
struct SUrlFetchItem
{
	cdstring	mUrl;
	cdstring	mData;
	bool		mDataIsNil;
	cdstring	mBodyPartStructure;
	bool		mIsBinary;

	SUrlFetchItem()
		: mDataIsNil(false), mIsBinary(false) {}
};

typedef std::vector<SUrlFetchItem> SUrlFetchResults;

class CIMAPUrl
{
public:
	CIMAPUrl();
	CIMAPUrl(const cdstring& url);
	CIMAPUrl(const CIMAPUrl& copy);
	~CIMAPUrl();

	CIMAPUrl& operator=(const CIMAPUrl& copy);

	void Parse(const cdstring& url);

	cdstring ToFullUrl() const;
	cdstring ToRumpUrl() const;
	cdstring ToRelativeUrl() const;

	// Server component
	const cdstring& GetUser() const
		{ return mUser; }
	const cdstring& GetAuthMechanism() const
		{ return mAuthMechanism; }
	const cdstring& GetServer() const
		{ return mServer; }
	unsigned short GetPort() const
		{ return mPort; }

	void SetUser(const cdstring& user)
		{ mUser = user; }
	void SetAuthMechanism(const cdstring& auth)
		{ mAuthMechanism = auth; }
	void SetServer(const cdstring& server)
		{ mServer = server; }
	void SetPort(unsigned short port)
		{ mPort = port; }

	// Mailbox/message reference
	const cdstring& GetMailbox() const
		{ return mMailbox; }
	unsigned long GetUIDValidity() const
		{ return mUIDValidity; }
	unsigned long GetUID() const
		{ return mUID; }
	const cdstring& GetSection() const
		{ return mSection; }
	bool HasPartial() const
		{ return mHasPartial; }
	unsigned long GetPartialOffset() const
		{ return mPartialOffset; }
	unsigned long GetPartialLength() const
		{ return mPartialLength; }

	void SetMailbox(const cdstring& mbox)
		{ mMailbox = mbox; }
	void SetUIDValidity(unsigned long uidv)
		{ mUIDValidity = uidv; }
	void SetUID(unsigned long uid)
		{ mUID = uid; }
	void SetSection(const cdstring& section)
		{ mSection = section; }
	const cdstring& GetSearch() const
		{ return mSearch; }

	void SetSearch(const cdstring& search)
		{ mSearch = search; }
	void SetPartial(unsigned long offset, unsigned long length)
		{ mHasPartial = true; mPartialOffset = offset; mPartialLength = length; }
	void ClearPartial()
		{ mHasPartial = false; mPartialOffset = 0; mPartialLength = 0; }

	// URLAUTH components (RFC 4467, RFC 5593)
	bool HasUrlAuth() const
		{ return mHasUrlAuth; }
	EIMAPUrlAccess GetAccess() const
		{ return mAccess; }
	const cdstring& GetAccessUser() const
		{ return mAccessUser; }
	const cdstring& GetAccessApplication() const
		{ return mAccessApplication; }
	bool HasExpire() const
		{ return !mExpire.empty(); }
	const cdstring& GetExpire() const
		{ return mExpire; }
	const cdstring& GetMechanism() const
		{ return mMechanism; }
	const cdstring& GetToken() const
		{ return mToken; }

	void SetAccess(EIMAPUrlAccess access, const cdstring& user = cdstring::null_str);
	void SetAccessApplication(const cdstring& app, const cdstring& user = cdstring::null_str);
	void SetExpire(const cdstring& expire)
		{ mExpire = expire; }
	void SetMechanism(const cdstring& mech)
		{ mMechanism = mech; }
	void SetToken(const cdstring& token)
		{ mToken = token; }

	// Queries
	bool IsValid() const;
	bool IsAbsoluteUrl() const;
	bool IsServerRef() const;
	bool IsMailboxRef() const;
	bool IsSearchRef() const;
	bool IsMessageRef() const;
	bool HasToken() const
		{ return !mToken.empty(); }

	bool Equal(const CIMAPUrl& comp) const;

private:
	// Server component
	cdstring		mUser;
	cdstring		mAuthMechanism;
	cdstring		mServer;
	unsigned short	mPort;

	// Mailbox/message reference (mailbox stored as UTF-8)
	cdstring		mMailbox;
	unsigned long	mUIDValidity;
	unsigned long	mUID;
	cdstring		mSection;
	cdstring		mSearch;
	bool			mHasPartial;
	unsigned long	mPartialOffset;
	unsigned long	mPartialLength;

	// URLAUTH components
	bool			mHasUrlAuth;
	EIMAPUrlAccess	mAccess;
	cdstring		mAccessUser;
	cdstring		mAccessApplication;
	cdstring		mExpire;
	cdstring		mMechanism;
	cdstring		mToken;

	void _Init();
	void _Copy(const CIMAPUrl& copy);

	void ParseServerComponent(const char*& p);
	void ParsePathComponent(const char*& p);
	void ParseUidValidity(const char*& p);
	void ParseUid(const char*& p);
	void ParseSection(const char*& p);
	void ParsePartial(const char*& p);
	void ParseExpire(const char*& p);
	void ParseUrlAuth(const char*& p);
	void ParseAccess(const char*& p);
	void ParseMechToken(const char*& p);

	void BuildServerComponent(cdstring& result) const;
	void BuildPathComponent(cdstring& result) const;

	static cdstring EncodeMailboxForUrl(const cdstring& utf8_mbox);
	static cdstring DecodeMailboxFromUrl(const cdstring& encoded_mbox);
};

#endif
