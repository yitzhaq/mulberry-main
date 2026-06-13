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

#include "CForwardWithoutDownload.h"

#include "CAttachment.h"
#include "CIMAPUrl.h"
#include "CINETAccount.h"
#include "CMbox.h"
#include "CMboxProtocol.h"
#include "CMessage.h"

#include "CLog.h"

CForwardWithoutDownload::CForwardWithoutDownload(CMboxProtocol* imap)
	: mIMAP(imap)
{
}

bool CForwardWithoutDownload::CanUseCatenateStrategy() const
{
	return mIMAP &&
		   mIMAP->HasCatenate() &&
		   mIMAP->HasUrlAuth();
}

bool CForwardWithoutDownload::CanUseChunkingStrategy() const
{
	return mIMAP &&
		   mIMAP->HasUrlAuth();
}

// RFC 5550 §8.4.1: Build message on IMAP via CATENATE APPEND,
// generate URLAUTH URL. Caller handles SMTP MAIL/RCPT/BURL.
bool CForwardWithoutDownload::PlanCatenateForward(CMbox* source_mbox,
												   CMessage* original,
												   const cdstring& new_headers,
												   CMbox* fcc_mbox,
												   SForwardPlan& plan)
{
	plan = SForwardPlan();

	if (!CanUseCatenateStrategy())
		return false;

	if (!source_mbox || !original || !fcc_mbox)
		return false;

	try
	{
		SCatenatePartList parts;

		SCatenatePart header_part;
		header_part.mIsUrl = false;
		header_part.mData = new_headers;
		parts.push_back(header_part);

		CAttachment* body = original->GetBody();
		if (body && body->IsMultipart())
		{
			CAttachment::CAttachmentList* part_list = body->GetParts();
			if (part_list)
			{
				for (CAttachment::CAttachmentList::iterator iter = part_list->begin();
					 iter != part_list->end(); iter++)
				{
					cdstring section;
					(*iter)->GetPartNumber(section);

					SCatenatePart mime_part;
					mime_part.mIsUrl = true;
					CIMAPUrl mime_url;
					mime_url.SetMailbox(source_mbox->GetName());
					mime_url.SetUIDValidity(source_mbox->GetUIDValidity());
					mime_url.SetUID(original->GetUID());
					mime_url.SetSection(section + ".MIME");
					mime_part.mData = mime_url.ToRelativeUrl();
					parts.push_back(mime_part);

					SCatenatePart body_part;
					body_part.mIsUrl = true;
					CIMAPUrl body_url;
					body_url.SetMailbox(source_mbox->GetName());
					body_url.SetUIDValidity(source_mbox->GetUIDValidity());
					body_url.SetUID(original->GetUID());
					body_url.SetSection(section);
					body_part.mData = body_url.ToRelativeUrl();
					parts.push_back(body_part);
				}
			}
		}
		else if (body)
		{
			SCatenatePart text_part;
			text_part.mIsUrl = true;
			CIMAPUrl text_url;
			text_url.SetMailbox(source_mbox->GetName());
			text_url.SetUIDValidity(source_mbox->GetUIDValidity());
			text_url.SetUID(original->GetUID());
			text_url.SetSection("TEXT");
			text_part.mData = text_url.ToRelativeUrl();
			parts.push_back(text_part);
		}

		cdstring flags = "(\\Seen)";
		cdstring internaldate;

		mIMAP->AppendCatenate(fcc_mbox, flags, internaldate, parts, plan.mFccUid);
		if (plan.mFccUid == 0)
			return false;

		const CINETAccount* acct = mIMAP->GetAccount();
		CIMAPUrl auth_url;
		auth_url.SetServer(acct->GetServerIP());
		auth_url.SetUser(acct->GetAuthenticatorUserPswd()->GetUID());
		auth_url.SetMailbox(fcc_mbox->GetName());
		auth_url.SetUIDValidity(fcc_mbox->GetUIDValidity());
		auth_url.SetUID(plan.mFccUid);
		auth_url.SetAccess(eIMAPUrlAccessSubmit,
			acct->GetAuthenticatorUserPswd()->GetUID());

		cdstrvect rump_urls;
		rump_urls.push_back(auth_url.ToRumpUrl());
		cdstrvect auth_results;
		mIMAP->GenUrlAuth(rump_urls, "INTERNAL", auth_results);

		if (auth_results.empty())
			return false;

		plan.mBurlUrl = auth_results[0];
		plan.mUseBurl = true;
		return true;
	}
	catch (...)
	{
		CLOG_LOGCATCH(...);
		plan = SForwardPlan();
		return false;
	}
}

// RFC 5550 §8.4.2: Generate URLAUTH URLs for body parts.
// Caller handles SMTP MAIL/RCPT/BDAT+BURL interleaving.
bool CForwardWithoutDownload::PlanChunkingForward(CMbox* source_mbox,
												   CMessage* original,
												   const cdstring& new_headers,
												   SForwardPlan& plan)
{
	plan = SForwardPlan();

	if (!CanUseChunkingStrategy())
		return false;

	if (!source_mbox || !original)
		return false;

	try
	{
		const CINETAccount* acct = mIMAP->GetAccount();
		cdstrvect rump_urls;

		CAttachment* body = original->GetBody();
		if (body && body->IsMultipart())
		{
			CAttachment::CAttachmentList* part_list = body->GetParts();
			if (part_list)
			{
				for (CAttachment::CAttachmentList::iterator iter = part_list->begin();
					 iter != part_list->end(); iter++)
				{
					cdstring section;
					(*iter)->GetPartNumber(section);

					CIMAPUrl mime_url;
					mime_url.SetServer(acct->GetServerIP());
					mime_url.SetUser(acct->GetAuthenticatorUserPswd()->GetUID());
					mime_url.SetMailbox(source_mbox->GetName());
					mime_url.SetUIDValidity(source_mbox->GetUIDValidity());
					mime_url.SetUID(original->GetUID());
					mime_url.SetSection(section + ".MIME");
					mime_url.SetAccess(eIMAPUrlAccessSubmit,
						acct->GetAuthenticatorUserPswd()->GetUID());
					rump_urls.push_back(mime_url.ToRumpUrl());

					CIMAPUrl body_url;
					body_url.SetServer(acct->GetServerIP());
					body_url.SetUser(acct->GetAuthenticatorUserPswd()->GetUID());
					body_url.SetMailbox(source_mbox->GetName());
					body_url.SetUIDValidity(source_mbox->GetUIDValidity());
					body_url.SetUID(original->GetUID());
					body_url.SetSection(section);
					body_url.SetAccess(eIMAPUrlAccessSubmit,
						acct->GetAuthenticatorUserPswd()->GetUID());
					rump_urls.push_back(body_url.ToRumpUrl());
				}
			}
		}
		else if (body)
		{
			CIMAPUrl text_url;
			text_url.SetServer(acct->GetServerIP());
			text_url.SetUser(acct->GetAuthenticatorUserPswd()->GetUID());
			text_url.SetMailbox(source_mbox->GetName());
			text_url.SetUIDValidity(source_mbox->GetUIDValidity());
			text_url.SetUID(original->GetUID());
			text_url.SetSection("TEXT");
			text_url.SetAccess(eIMAPUrlAccessSubmit,
				acct->GetAuthenticatorUserPswd()->GetUID());
			rump_urls.push_back(text_url.ToRumpUrl());
		}

		cdstrvect auth_results;
		mIMAP->GenUrlAuth(rump_urls, "INTERNAL", auth_results);

		if (auth_results.size() != rump_urls.size())
			return false;

		plan.mPartUrls = auth_results;
		plan.mLocalHeaders = new_headers;
		plan.mUseBurl = true;
		return true;
	}
	catch (...)
	{
		CLOG_LOGCATCH(...);
		plan = SForwardPlan();
		return false;
	}
}
