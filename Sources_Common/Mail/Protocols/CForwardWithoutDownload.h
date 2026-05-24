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

#ifndef __CFORWARDWITHOUTDOWNLOAD__MULBERRY__
#define __CFORWARDWITHOUTDOWNLOAD__MULBERRY__

#include "cdstring.h"

#include <vector>

class CMboxProtocol;
class CSMTPSender;
class CMessage;
class CAttachment;
class CMbox;

struct SForwardPlan
{
	bool			mUseBurl;
	cdstring		mBurlUrl;
	unsigned long	mFccUid;
	cdstrvect		mPartUrls;
	cdstring		mLocalHeaders;

	SForwardPlan() : mUseBurl(false), mFccUid(0) {}
};

class CForwardWithoutDownload
{
public:
		CForwardWithoutDownload(CMboxProtocol* imap);

	bool	CanUseCatenateStrategy() const;
	bool	CanUseChunkingStrategy() const;

	bool	PlanCatenateForward(CMbox* source_mbox,
								CMessage* original,
								const cdstring& new_headers,
								CMbox* fcc_mbox,
								SForwardPlan& plan);

	bool	PlanChunkingForward(CMbox* source_mbox,
								CMessage* original,
								const cdstring& new_headers,
								SForwardPlan& plan);

private:
	CMboxProtocol*	mIMAP;
};

#endif
