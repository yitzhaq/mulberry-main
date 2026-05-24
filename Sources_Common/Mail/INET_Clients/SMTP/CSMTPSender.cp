/*
    Copyright (c) 2007 Cyrus Daboo. All rights reserved.
    
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


// Code for SMTP sender class

#include "CSMTPSender.h"

#include "CAddress.h"
#include "CAddressList.h"
#include "CAttachment.h"
#include "CAttachmentList.h"
#include "CAuthPlugin.h"
#include "CCertificateManager.h"
#include "CIMAPUrl.h"
#include "CINETAccount.h"
#include "CINETClient.h"
#include "CINETCommon.h"
#include "CMailAccountManager.h"
#include "CMailControl.h"
#include "CMbox.h"
#include "CMboxProtocol.h"
#include "CMessage.h"
#if __dest_os == __mac_os || __dest_os == __mac_os_x
#include "CMulberryCommon.h"
#endif
#include "CPasswordManager.h"
#include "CPluginManager.h"
#include "CRFC822.h"
#include "CSecurityPlugin.h"
#include "CStatusWindow.h"
#include "CStreamFilter.h"
#include "CStreamType.h"
#include "CStringUtils.h"
#include "CTaskClasses.h"
#include "CTCPException.h"
#if __dest_os == __mac_os || __dest_os == __mac_os_x
#include "CVisualProgress.h"
#endif
#include "CXStringResources.h"

#if __dest_os == __mac_os || __dest_os == __mac_os_x
#else
#include "StValueChanger.h"
#endif

#include "base64.h"

#include <algorithm>
#include <errno.h>
#include <string.h>
#include <stdio.h>

const int cSMTPBufferLen = 1024;

// C O N S T R U C T I O N / D E S T R U C T I O N  M E T H O D S

// Default constructor

CSMTPSender::CSMTPSender(CINETAccount* account)
{
	SetAccount(account);

	mReceiver = 0;
	mMessage = NULL;
	mMailState = cSMTPNotOpen;
	mLineData = new char[cSMTPBufferLen];
	mToCtr = 0;
	mCcCtr = 0;
	mBccCtr = 0;
	mAllowLog = true;
	mESMTP = false;
	mSize = false;
	mSizeLimit = -1;
	mSTARTTLS = false;
	mAUTH = false;
	m8BitMIME = false;
	mPipelining = false;
	mEnhancedStatus = false;
	mDSN = false;
	mChunking = false;
	mBinaryMIME = false;
	mBurl = false;
	mBurlImap = false;
	mUseBinaryCTE = false;

	mUseQueue = false;
	mQueueMbox = NULL;
}

CSMTPSender::~CSMTPSender()
{
	mAccount = NULL;
	mMessage = NULL;
	delete[] mLineData;
	mLineData = NULL;
	mQueueMbox = NULL;
}


// O T H E R  M E T H O D S _________________________________________________________________________

void CSMTPSender::SetAccount(CINETAccount* account)
{
	mAccount = account;
	mAccountName = account->GetName();
}

bool CSMTPSender::IsSecure() const
{
	// Check for TLS
	return (mAccount->GetTLSType() != CINETAccount::eNoTLS);
}

bool CSMTPSender::SMTPStartAsync()
{
	// Can only do if mailbox exists
	if (!mQueueMbox)
	{
		CLOG_LOGTHROW(CGeneralException, -1);
		throw CGeneralException(-1);
	}

	// Mailbox must be open
	mQueueMbox->Open();
	if (!mQueueMbox->IsFullOpen())
		return false;
	mQueueMbox->CacheAllMessages();

	// Look for suitable messages in async mailbox
	if (!SMTPAsyncMessage())
	{
		mQueueMbox->Close();
		return false;
	}

	// Always close the mailbox to remove thread lock
	mQueueMbox->Close();

	// Begin SMTP by logging in
	SMTPBegin();

	return true;
}

bool CSMTPSender::SMTPNextAsync(bool reset)
{
	bool result = false;
	bool opened = false;

	try
	{
		// Send RSET if required
		if (reset)
		{
			SMTPSendRset();
			SMTPReceiveData();
		}
		
		// Mailbox must be open
		mQueueMbox->Open();
		opened = true;
		if (!mQueueMbox->IsFullOpen())
		{
			CLOG_LOGTHROW(CGeneralException, -1);
			throw CGeneralException(-1);
		}
		mQueueMbox->CacheAllMessages();

		// Look for available message
		CMessage* found = SMTPAsyncMessage();
		if (found)
		{
			bool sent = false;
			bool tried_burl = false;
			try
			{
				found->ChangeFlags(NMessage::eSendingNow, true);

				// Check for BURL optimization: fcc APPEND + BURL at drain time
				ClearBurlUrl();
				unsigned long drain_fcc_uid = 0;
				CMbox* drain_fcc_mbox = NULL;
				if (mBurl && mBurlImap)
				{
					char* hdr = found->GetHeader();
					if (hdr)
					{
						const char* copyto = ::strstr(hdr, cHDR_XMULBERRY_COPYTO);
						if (copyto)
						{
							copyto += sizeof(cHDR_XMULBERRY_COPYTO) - 1;
							const char* end = copyto;
							while (*end && *end != '\r' && *end != '\n') end++;
							cdstring fcc_name(copyto, end - copyto);

							if (!fcc_name.empty() && CMailAccountManager::sMailAccountManager)
							{
								drain_fcc_mbox = CMailAccountManager::sMailAccountManager->FindMboxAccount(fcc_name);
								if (drain_fcc_mbox && drain_fcc_mbox != (CMbox*) -1 &&
									drain_fcc_mbox->GetProtocol()->IsLoggedOn() &&
									drain_fcc_mbox->GetProtocol()->HasUrlAuth())
								{
									try
									{
										found->GetFlags().Set(NMessage::eSubmitPending, true);
										drain_fcc_mbox->AppendMessage(found, drain_fcc_uid);
										found->GetFlags().Set(NMessage::eSubmitPending, false);

										if (drain_fcc_uid != 0)
										{
											const CINETAccount* acct = drain_fcc_mbox->GetProtocol()->GetAccount();
											CIMAPUrl url;
											url.SetServer(acct->GetServerIP());
											url.SetUser(acct->GetAuthenticatorUserPswd()->GetUID());
											url.SetMailbox(drain_fcc_mbox->GetName());
											url.SetUIDValidity(drain_fcc_mbox->GetUIDValidity());
											url.SetUID(drain_fcc_uid);
											url.SetAccess(eIMAPUrlAccessSubmit,
												acct->GetAuthenticatorUserPswd()->GetUID());

											cdstrvect rump_urls;
											rump_urls.push_back(url.ToRumpUrl());
											cdstrvect auth_results;
											drain_fcc_mbox->GetProtocol()->GenUrlAuth(
												rump_urls, "INTERNAL", auth_results);

											if (!auth_results.empty())
											{
												SetBurlUrl(auth_results[0]);

												ulvector uids;
												uids.push_back(drain_fcc_uid);
												try {
													drain_fcc_mbox->SetFlagMessage(
														uids, true, NMessage::eSubmitted, true);
												} catch (...) { CLOG_LOGCATCH(...); }
											}
										}
									}
									catch (...)
									{
										CLOG_LOGCATCH(...);
										ClearBurlUrl();
										drain_fcc_uid = 0;
										drain_fcc_mbox = NULL;
									}
								}
								else
									drain_fcc_mbox = NULL;
							}
						}
					}
				}

				tried_burl = !mBurlUrl.empty();

				// Must recreate send header - don't use the one in the message
				CRFC822::SendHeader(found, mMsgDSN, true);

				// Send it (uses BURL if mBurlUrl was set above)
				SMTPSendMessage(found);
				sent = true;

				if (drain_fcc_uid != 0 && drain_fcc_mbox)
				{
					ulvector uids;
					uids.push_back(drain_fcc_uid);
					try {
						drain_fcc_mbox->SetFlagMessage(
							uids, true, NMessage::eSubmitPending, false);
					} catch (...) { CLOG_LOGCATCH(...); }
				}

				// UID expunge it
				ulvector nums;
				nums.push_back(found->GetMessageNumber());
				mQueueMbox->ExpungeMessage(nums, false);

				// Safety check - if we get the same message back
				// something went very wrong. We MUST make sure it doesn't
				// get sent out again and again
				CMessage* next_found = SMTPAsyncMessage();
				if (next_found == found)
				{
					CLOG_LOGTHROW(CGeneralException, -1L);
					throw CGeneralException(-1L);
				}
			}
			catch (CSMTPException& smtp_ex)
			{
				CLOG_LOGCATCH(CSMTPException&);

				if (tried_burl)
				{
					// BURL failed or SMTP connection died — reconnect and retry with DATA
					ClearBurlUrl();
					try
					{
						try { SMTPClose(); } catch (...) { CLOG_LOGCATCH(...); }
						CRFC822::SendHeader(found, mMsgDSN, true);
						SMTPBegin();
						SMTPSendMessage(found);
						sent = true;
					}
					catch (...)
					{
						CLOG_LOGCATCH(...);
						found->ChangeFlags(NMessage::eSendingNow, false);
						found->ChangeFlags(NMessage::eSendError, true);
						found->ChangeFlags(NMessage::eHold, true);
					}
				}
				else
				{
					found->ChangeFlags(NMessage::eSendingNow, false);
					found->ChangeFlags(NMessage::eSendError, true);
					if (smtp_ex.IsPermanent())
						found->ChangeFlags(NMessage::eHold, true);
				}
			}
			catch (...)
			{
				CLOG_LOGCATCH(...);

				found->ChangeFlags(NMessage::eHold, true);
				found->ChangeFlags(NMessage::eSendError, true);
				found->ChangeFlags(NMessage::eSendingNow, false);
			}

			// Check if more to come
			result = (SMTPAsyncMessage() != NULL);
		}

		// Always close the mailbox to remove thread lock
		mQueueMbox->Close();
	}
	catch (...)
	{
		CLOG_LOGCATCH(...);

		if (opened)
			mQueueMbox->Close();

		CLOG_LOGRETHROW;
		throw;
	}

	return result;
}

void CSMTPSender::SMTPStopAsync()
{
	// Just close the connection
	SMTPEnd();
}

// Get first message available for sending
CMessage* CSMTPSender::SMTPAsyncMessage()
{
	// Policy:
	// deleted messages  : permanently removed from queue - ignore
	// hold/ mdnsent messages  : temporarily paused - ignore
	// priority/flagged messages  : high priority - send before anything else
	// send now/answered messages : set once processing starts

	// Look for first undeleted/draft message (try important ones first then the rest)
	CMessage* found = mQueueMbox->GetNextFlagMessage(NULL, NMessage::ePriority, static_cast<NMessage::EFlags>(NMessage::eDeleted | NMessage::eHold));
	if (!found)
		found = mQueueMbox->GetNextFlagMessage(NULL, NMessage::eNone, static_cast<NMessage::EFlags>(NMessage::eDeleted | NMessage::eHold));
	
	return found;
}

// Send mail with specified information
void CSMTPSender::SMTPSend(CMessage* theMsg, bool async, CMbox* fcc_mbox, bool* fcc_done)
{
	ClearBurlUrl();
	if (fcc_done)
		*fcc_done = false;

	// Must recreate send header - don't use the one in the message
	CRFC822::SendHeader(theMsg, mMsgDSN, false);

	SMTPBegin();

	// BURL optimization (RFC 5550 §8.6): if server supports BURL and
	// fcc mailbox supports URLAUTH, APPEND to fcc first, then submit
	// via BURL URL reference — one upload instead of two.
	bool fcc_appended = false;
	bool burl_ready = false;
	unsigned long fcc_uid = 0;
	bool has_bcc = theMsg->GetEnvelope()->GetBcc()->size() > 0;

	if (mBurl && mBurlImap && !has_bcc &&
		fcc_mbox && fcc_mbox != (CMbox*) -1 &&
		fcc_mbox->GetProtocol()->IsLoggedOn() &&
		fcc_mbox->GetProtocol()->HasUrlAuth())
	{
		try
		{
			theMsg->GetFlags().Set(NMessage::eSubmitPending, true);
			fcc_mbox->AppendMessage(theMsg, fcc_uid);
			theMsg->GetFlags().Set(NMessage::eSubmitPending, false);
			if (fcc_uid != 0)
				fcc_appended = true;
		}
		catch (...)
		{
			CLOG_LOGCATCH(...);
			fcc_uid = 0;
		}

		if (fcc_appended)
		{
			try
			{
				const CINETAccount* acct = fcc_mbox->GetProtocol()->GetAccount();
				CIMAPUrl url;
				url.SetServer(acct->GetServerIP());
				url.SetUser(acct->GetAuthenticatorUserPswd()->GetUID());
				url.SetMailbox(fcc_mbox->GetName());
				url.SetUIDValidity(fcc_mbox->GetUIDValidity());
				url.SetUID(fcc_uid);
				url.SetAccess(eIMAPUrlAccessSubmit,
					acct->GetAuthenticatorUserPswd()->GetUID());

				cdstrvect rump_urls;
				rump_urls.push_back(url.ToRumpUrl());
				cdstrvect auth_results;
				fcc_mbox->GetProtocol()->GenUrlAuth(rump_urls, "INTERNAL", auth_results);

				if (!auth_results.empty())
				{
					SetBurlUrl(auth_results[0]);
					burl_ready = true;

					ulvector uids;
					uids.push_back(fcc_uid);
					try {
						fcc_mbox->SetFlagMessage(uids, true, NMessage::eSubmitted, true);
					} catch (...) { CLOG_LOGCATCH(...); }
				}
			}
			catch (...)
			{
				CLOG_LOGCATCH(...);
				ClearBurlUrl();
				burl_ready = false;
			}
		}
	}

	try
	{
		SMTPSendMessage(theMsg);
	}
	catch (...)
	{
		CLOG_LOGCATCH(...);

		if (burl_ready)
		{
			// BURL failed or SMTP connection died during IMAP work.
			// Reconnect and retry with DATA/BDAT.
			ClearBurlUrl();
			try
			{
				try { SMTPClose(); } catch (...) { CLOG_LOGCATCH(...); }
				CRFC822::SendHeader(theMsg, mMsgDSN, false);
				SMTPBegin();
				SMTPSendMessage(theMsg);
			}
			catch (...)
			{
				CLOG_LOGCATCH(...);
				try { SMTPClose(); } catch (...) { CLOG_LOGCATCH(...); }
				throw;
			}
		}
		else
		{
			try { SMTPEnd(); } catch (...) { CLOG_LOGCATCH(...); }
			throw;
		}
	}

	if (fcc_appended && fcc_uid != 0 && fcc_mbox)
	{
		ulvector uids;
		uids.push_back(fcc_uid);
		try {
			fcc_mbox->SetFlagMessage(uids, true, NMessage::eSubmitPending, false);
		} catch (...) { CLOG_LOGCATCH(...); }
	}

	if (fcc_done)
		*fcc_done = fcc_appended;

	SMTPEnd();
}

// Send mail with specified information
void CSMTPSender::SMTPBegin()
{
	// Clear errors on stream from last time
	mStream.clear();

	// Clear any previous response
	*mLineData = 0;
	bool auth_ok = true;

	try
	{
		// Set Status
		SMTPSetStatus("Status::SMTP::Opening");

#if __dest_os == __mac_os || __dest_os == __mac_os_x
		// Start spinning
		//if (CTaskQueue::sTaskQueue.InMainThread())
		//	::BeginResSpinning(crsr_StdSpin);
#endif
		// Open SMTP sender
		SMTPOpen();

		// Update state
		mMailState = cSMTPOpen;

// -- Connect
		// Set Status
		SMTPSetStatus("Status::SMTP::Connecting");

		// Look for SSL and turn on here
		if ((GetAccount()->GetTLSType() == CINETAccount::eSSL) ||
			(GetAccount()->GetTLSType() == CINETAccount::eSSLv3))
		{
			mStream.TLSSetTLSOn(true, GetAccount()->GetTLSType());
			
			// Check for client cert
			if (GetAccount()->GetUseTLSClientCert())
			{
				// Try to load client certificate
				if (!SMTPTLSClientCertificate())
				{
					CLOG_LOGTHROW(unsigned long, 1UL);
					throw 1UL;
				}
			}
		}
		else
			mStream.TLSSetTLSOn(false);

		// Start connection
		mMailState = cSMTPOpeningReceiver;
		mStream.TCPStartConnection();

		// Get first info from server
		mMailState = cSMTPWaitingReceiverResponse;
		SMTPReceiveData();

// -- EHLO
		// Set status
		SMTPSetStatus("Status::SMTP::Begin");

		// Send data
		mMailState = cSMTPSendingEHello;
		SMTPSendEHello();

		// Get response - may fail if EHLO not supported
		mMailState = cSMTPWaitingEHelloResponse;
		try
		{
			// Process the EHLO response as capability
			SMTPReceiveCapability();
			mESMTP = true;
		}
		catch (CSMTPException& ex)
		{
			CLOG_LOGCATCH(CSMTPException&);

			// Allow to fail silently if ESMTP not supported
		}

		if (!mESMTP)
		{
			// Look for TLS and fail
			if ((GetAccount()->GetTLSType() == CINETAccount::eTLS) ||
				(GetAccount()->GetTLSType() == CINETAccount::eTLSBroken))
			{
				mMailState = cSMTPErrorNoTLS;
				CLOG_LOGTHROW(CSMTPException, FAIL_RESPONSE);
				throw CSMTPException(FAIL_RESPONSE);
			}

			// Check whether user wants AUTH if so fail
			if (GetAccount()->GetAuthenticatorType() != CAuthenticator::eNone)
			{
				mMailState = cSMTPErrorNoAUTH;
				CLOG_LOGTHROW(CSMTPException, FAIL_RESPONSE);
				throw CSMTPException(FAIL_RESPONSE);
			}

// -- HELO
			// Set status
			SMTPSetStatus("Status::SMTP::Begin");

			// Send data
			mMailState = cSMTPSendingHello;
			SMTPSendHello();

			// Get response
			mMailState = cSMTPWaitingHelloResponse;
			SMTPReceiveData();
		}
		else
		{
			// Look for TLS and do STARTTLS
			if ((GetAccount()->GetTLSType() == CINETAccount::eTLS) ||
				(GetAccount()->GetTLSType() == CINETAccount::eTLSBroken))
			{
				if (mSTARTTLS)
				{
					// Check for client cert
					if (GetAccount()->GetUseTLSClientCert())
					{
						// Try to load client certificate
						if (!SMTPTLSClientCertificate())
						{
							CLOG_LOGTHROW(unsigned long, 1UL);
							throw 1UL;
						}
					}
					
					SMTPStartTLS();
				}
				else
				{
					mMailState = cSMTPErrorNoTLS;
					CLOG_LOGTHROW(CSMTPException, FAIL_RESPONSE);
					throw CSMTPException(FAIL_RESPONSE);
				}
			}

			// Must check that AUTH is available
			if (!mAUTH && (GetAccount()->GetAuthenticatorType() != CAuthenticator::eNone))
			{
				mMailState = cSMTPErrorNoAUTH;
				CLOG_LOGTHROW(CSMTPException, FAIL_RESPONSE);
				throw CSMTPException(FAIL_RESPONSE);
			}

			// Must check that requested AUTH method is available
			if (mAUTH && (GetAccount()->GetAuthenticatorType() != CAuthenticator::eNone))
			{
				cdstring desc = GetAccount()->GetAuthenticator().GetSASLID();
				::strupper(desc.c_str_mod());
				cdstrvect::const_iterator found = std::find(mAUTHTypes.begin(), mAUTHTypes.end(), desc);

				// Special case - try LOGIN if PLAIN was specified and failed
				if ((found == mAUTHTypes.end()) && (desc == cPLAIN))
					found = std::find(mAUTHTypes.begin(), mAUTHTypes.end(), cLOGIN);

				if (found == mAUTHTypes.end())
				{
					mMailState = cSMTPErrorNoAUTHType;
					CLOG_LOGTHROW(CSMTPException, FAIL_RESPONSE);
					throw CSMTPException(FAIL_RESPONSE);
				}
			}

// -- AUTH
			// Set status
			SMTPSetStatus("Status::SMTP::Authenticate");

			// Do authentication
			mMailState = cSMTPSendingAuth;
			auth_ok = SMTPDoAuthentication();

			// Re-EHLO after successful AUTH (RFC 4954 Section 4)
			if (auth_ok)
			{
				mMailState = cSMTPSendingEHello;
				SMTPSendEHello();
				SMTPReceiveCapability();
			}

			// Reset status
			SMTPSetStatus("Status::SMTP::Begin");
		}

	}
	catch (unsigned long num)
	{
		CLOG_LOGCATCH(unsigned long num);

		// Fall through and treat like a failed auth
	}
	catch (CGeneralException& ex)
	{
		CLOG_LOGCATCH(CGeneralException&);

		// Handle it
		SMTPHandleGeneralException(ex);

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}
	catch (CSMTPException& ex)
	{
		CLOG_LOGCATCH(CSMTPException&);

		// Handle it
		SMTPHandleSMTPException(ex, true);

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}
	catch (CTCPException& ex)
	{
		CLOG_LOGCATCH(CTCPException&);

		// Handle it
		SMTPHandleTCPException(ex);

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}

#if __dest_os == __win32_os
	// Might catch exception when opening file attachment
	catch (CFileException* ex)
	{
		CLOG_LOGCATCH(CFileException*);

		// Handle it
		SMTPHandleFileException(ex);

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}
#endif

	// Any other exception must be caught and handled
	catch (...)
	{
		CLOG_LOGCATCH(...);

		// Handle it
		SMTPHandleUnknownException();

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}

	// Now, if authentication failed (maybe cancelled) then we must throw up
	// to prevent further processing
	if (!auth_ok)
	{
#if __dest_os == __mac_os || __dest_os == __mac_os_x
		// Make sure cursor has stopped spinning
		//if (CTaskQueue::sTaskQueue.InMainThread())
		//	::StopSpinning();
#endif
		CLOG_LOGTHROW(CGeneralException, -1);
		throw CGeneralException(-1);
	}
}

// Send mail with specified information
void CSMTPSender::SMTPSendMessage(CMessage* theMsg)
{
	// Cache message
	mMessage = theMsg;
	mToCtr = 0;
	mCcCtr = 0;
	mBccCtr = 0;

	// Determine binary CTE usage for this transaction (RFC 3030)
	bool is_queued = mMessage->GetMbox() && (mMessage->GetMbox() == mQueueMbox);
	mUseBinaryCTE = mBinaryMIME && mChunking && !is_queued &&
		mMessage->GetBody() && SMTPHasBase64Parts(mMessage->GetBody());

	// Clear any previous response
	try
	{
		// Check size limit first
		if (mSize && mMessage->GetSize() && (mMessage->GetSize() > mSizeLimit))
		{
			// Create fake error message
			cdstring error = rsrc::GetString("Error::SMTP::OversizeMessage");
			error += cdstring(mMessage->GetSize());
			
			// Copy into line buffer as error handling code will read error message from there
			::strcpy(mLineData, error.c_str());

			if (mAllowLog && mLog.DoLog())
				*mLog.GetLog() << error << os_endl << std::flush;

			// Force failure before even attempting SMTP commands as we know it will fail
			mMailState = cSMTPSendingMail;
			CLOG_LOGTHROW(CSMTPException, FAIL_RESPONSE);
			throw CSMTPException(FAIL_RESPONSE);
		}

// -- MAIL + RCPTs (pipelined when supported)
		if (mPipelining)
		{
			// Phase 1: Send MAIL FROM and all RCPT TO without waiting
			mMailState = cSMTPSendingMail;
			SMTPSendMail();

			unsigned long rcpt_count = 0;
			for(mToCtr = 0; mToCtr < mMessage->GetEnvelope()->GetTo()->size(); mToCtr++)
			{
				mMailState = cSMTPSendingToRcpt;
				SMTPSendToRcpt();
				rcpt_count++;
			}
			for(mCcCtr = 0; mCcCtr < mMessage->GetEnvelope()->GetCC()->size(); mCcCtr++)
			{
				mMailState = cSMTPSendingCCRcpt;
				SMTPSendCCRcpt();
				rcpt_count++;
			}
			for(mBccCtr = 0; mBccCtr < mMessage->GetEnvelope()->GetBcc()->size(); mBccCtr++)
			{
				mMailState = cSMTPSendingBCCRcpt;
				SMTPSendBCCRcpt();
				rcpt_count++;
			}
			mStream << std::flush;

			// Phase 2: Read MAIL FROM response
			mMailState = cSMTPWaitingMailResponse;
			SMTPReceiveData();

			// Phase 3: Read all RCPT TO responses, track accepted
			unsigned long accepted = 0;
			mMailState = cSMTPWaitingRcptResponse;
			for(unsigned long i = 0; i < rcpt_count; i++)
			{
				mStream.qgetline(mLineData, cSMTPBufferLen);
				while (SMTPContinuation())
					mStream.qgetline(mLineData, cSMTPBufferLen);
				if (*mLineData == OK_RESPONSE)
					accepted++;
			}

			if (accepted == 0)
			{
				CLOG_LOGTHROW(CSMTPException, FAIL_RESPONSE);
				throw CSMTPException(FAIL_RESPONSE);
			}
		}
		else
		{
			// Synchronous fallback — with partial failure handling
			mMailState = cSMTPSendingMail;
			SMTPSendMail();
			mMailState = cSMTPWaitingMailResponse;
			SMTPReceiveData();

			unsigned long accepted = 0;
			for(mToCtr = 0; mToCtr < mMessage->GetEnvelope()->GetTo()->size(); mToCtr++)
			{
				mMailState = cSMTPSendingToRcpt;
				SMTPSendToRcpt();
				mMailState = cSMTPWaitingRcptResponse;
				mStream.qgetline(mLineData, cSMTPBufferLen);
				while (SMTPContinuation())
					mStream.qgetline(mLineData, cSMTPBufferLen);
				if (*mLineData == OK_RESPONSE)
					accepted++;
			}
			for(mCcCtr = 0; mCcCtr < mMessage->GetEnvelope()->GetCC()->size(); mCcCtr++)
			{
				mMailState = cSMTPSendingCCRcpt;
				SMTPSendCCRcpt();
				mMailState = cSMTPWaitingRcptResponse;
				mStream.qgetline(mLineData, cSMTPBufferLen);
				while (SMTPContinuation())
					mStream.qgetline(mLineData, cSMTPBufferLen);
				if (*mLineData == OK_RESPONSE)
					accepted++;
			}
			for(mBccCtr = 0; mBccCtr < mMessage->GetEnvelope()->GetBcc()->size(); mBccCtr++)
			{
				mMailState = cSMTPSendingBCCRcpt;
				SMTPSendBCCRcpt();
				mMailState = cSMTPWaitingRcptResponse;
				mStream.qgetline(mLineData, cSMTPBufferLen);
				while (SMTPContinuation())
					mStream.qgetline(mLineData, cSMTPBufferLen);
				if (*mLineData == OK_RESPONSE)
					accepted++;
			}

			if (accepted == 0)
			{
				CLOG_LOGTHROW(CSMTPException, FAIL_RESPONSE);
				throw CSMTPException(FAIL_RESPONSE);
			}
		}

// -- BURL, BDAT, or DATA
		SMTPSetStatus("Status::SMTP::Sending");

		if (!mBurlUrl.empty() && mBurl && mBurlImap)
		{
			// BURL path (RFC 4468) — message already on IMAP, submit via URL
			cdstring url = mBurlUrl;
			mBurlUrl = cdstring::null_str;
			SMTPSendBurl(url, true);
		}
		else if (mChunking)
		{
			// BDAT path (RFC 3030) — message sent as length-prefixed chunks
			mMailState = cSMTPSendingBdat;
			SMTPSendBdat();
		}
		else
		{
			// Traditional DATA path
			mMailState = cSMTPSendingDataCmd;
			SMTPSendDataCmd();

			mMailState = cSMTPWaitingDataCmdResponse;
			SMTPReceiveData(DATA_RESPONSE);

			mMailState = cSMTPSendingData;
			SMTPSendData();

			mMailState = cSMTPWaitingDataResponse;
			SMTPReceiveData();
		}
	}
	catch (CGeneralException& ex)
	{
		CLOG_LOGCATCH(CGeneralException&);

		// Handle it
		SMTPHandleGeneralException(ex);

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}
	catch (CSMTPException& ex)
	{
		CLOG_LOGCATCH(CSMTPException&);

		// Handle it
		SMTPHandleSMTPException(ex, true);

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}
	catch (CTCPException& ex)
	{
		CLOG_LOGCATCH(CTCPException&);

		// Handle it
		SMTPHandleTCPException(ex);

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}

#if __dest_os == __win32_os
	// Might catch exception when opening file attachment
	catch (CFileException* ex)
	{
		CLOG_LOGCATCH(CFileException*);

		// Handle it
		SMTPHandleFileException(ex);

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}
#endif

	// Any other exception must be caught and handled
	catch (...)
	{
		CLOG_LOGCATCH(...);

		// Handle it
		SMTPHandleUnknownException();

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}
}

// Send mail with specified information
void CSMTPSender::SMTPEnd()
{
	// Clear errors on stream from last time
	mStream.clear();

	// May already be closed
	if (mMailState == cSMTPNotOpen)
		return;

	try
	{
// -- QUIT
		// Set Status
		SMTPSetStatus("Status::SMTP::Closing");

		// Send data
		mMailState = cSMTPSendingQuit;
		SMTPSendQuit();

		// Get response
		mMailState = cSMTPWaitingQuitResponse;
		SMTPReceiveData();

// -- close
		// Do action
		mMailState = cSMTPClosing;
		SMTPClose();
		mMailState = cSMTPNotOpen;

		// Set Status
		SMTPSetStatus("Status::IDLE");

#if __dest_os == __mac_os || __dest_os == __mac_os_x
		// Stop spinning
		//if (CTaskQueue::sTaskQueue.InMainThread())
		//	::StopSpinning();
#endif
	}
	catch (CGeneralException& ex)
	{
		CLOG_LOGCATCH(CGeneralException&);

		// Handle it
		SMTPHandleGeneralException(ex);

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}
	catch (CSMTPException& ex)
	{
		CLOG_LOGCATCH(CSMTPException&);

		// Handle it
		SMTPHandleSMTPException(ex, false);

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}
	catch (CTCPException& ex)
	{
		CLOG_LOGCATCH(CTCPException&);

		// Handle it
		SMTPHandleTCPException(ex);

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}

#if __dest_os == __win32_os
	// Might catch exception when opening file attachment
	catch (CFileException* ex)
	{
		CLOG_LOGCATCH(CFileException*);

		// Handle it
		SMTPHandleFileException(ex);

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}
#endif

	// Any other exception must be caught and handled
	catch (...)
	{
		CLOG_LOGCATCH(...);

		// Handle it
		SMTPHandleUnknownException();

		// Quit async operation with error
		CLOG_LOGRETHROW;
		throw;
	}
}

void CSMTPSender::SMTPSetStatus(const char* rsrcid)
{
	// Set status
	CStatusWindow::SetSMTPStatus(rsrcid);

	// Set busy status info
	{
		// Status string
		cdstring status = rsrc::GetString(rsrcid);
	
		// Add account descriptor
		status += os_endl2;
		status += "Account: ";
		status += GetAccountName();
		
		// Set this as the busy indicator
		mStream.SetBusyDescriptor(status);
	}
}

void CSMTPSender::SMTPHandleGeneralException(CGeneralException& ex)
{
	// Reset Status
	SMTPSetStatus("Status::IDLE");

#if __dest_os == __mac_os || __dest_os == __mac_os_x
	// Make sure cursor has stopped spinning
	//if (CTaskQueue::sTaskQueue.InMainThread())
	//	::StopSpinning();
#endif

	// Get Error context
	cdstring err_context;
	SMTPGetErrorContext(err_context);

	// Map state to error string id
	const char* err_id;
	const char* nobad_id;
	SMTPMapErrorStr(err_id, nobad_id);

	// Handle error with alert
	if (ex.GetErrorCode() < 0)
	{
		// Handle SysErr
		COSErrAlertRsrcTxtTask* task = new COSErrAlertRsrcTxtTask(err_id, ex.GetErrorCode(), err_context);
		task->Go();

		// Do recovery here
	}
	else
	{
		// Handle error
		cdstring errtxt = mLineData;
		errtxt += err_context;
		CStopAlertRsrcTxtTask* task = new CStopAlertRsrcTxtTask(nobad_id, errtxt);
		task->Go();
	}

	// Close SMTP
	SMTPClose();
	mMailState = cSMTPNotOpen;
}

void CSMTPSender::SMTPHandleSMTPException(CSMTPException& ex, bool do_quit)
{
	// Reset Status
	SMTPSetStatus("Status::IDLE");

#if __dest_os == __mac_os || __dest_os == __mac_os_x
	// Make sure cursor has stopped spinning
	//if (CTaskQueue::sTaskQueue.InMainThread())
	//	::StopSpinning();
#endif

	// Get Error context
	cdstring err_context;
	SMTPGetErrorContext(err_context);

	// Map state to error string id
	const char* err_id;
	const char* nobad_id;
	SMTPMapErrorStr(err_id, nobad_id);

	// Handle error
	cdstring errtxt = mLineData;
	const char* enhanced = GetEnhancedStatusText();
	if (enhanced)
	{
		errtxt += "\n(";
		errtxt += enhanced;
		errtxt += ")";
	}
	errtxt += err_context;
	CStopAlertRsrcTxtTask* task = new CStopAlertRsrcTxtTask(nobad_id, errtxt);
	task->Go();

	// Close SMTP
	if (do_quit)
		SMTPQuitClose();
	else
		SMTPClose();
	mMailState = cSMTPNotOpen;
}

void CSMTPSender::SMTPHandleTCPException(CTCPException& ex)
{
	// Reset Status
	SMTPSetStatus("Status::IDLE");

#if __dest_os == __mac_os || __dest_os == __mac_os_x
	// Make sure cursor has stopped spinning
	//if (CTaskQueue::sTaskQueue.InMainThread())
	//	::StopSpinning();
#endif

	// Get Error context
	cdstring err_context;
	SMTPGetErrorContext(err_context);

	// Map state to error string id
	const char* err_id;
	const char* nobad_id;
	SMTPMapErrorStr(err_id, nobad_id);

	// Handle network errors
	const char* mapped_errid = err_id;
	switch(ex.error())
	{
	case CTCPException::err_TCPAbort:
	case CTCPException::err_TCPFailed:
		mapped_errid = "Error::INET::ConnectionAborted";
		break;
	case CTCPException::err_TCPNoSSLPlugin:
		mapped_errid = "Error::INET::NoSSLPlugin";
		break;
	case CTCPException::err_TCPSSLError:
		mapped_errid = "Error::INET::NoSSLError";
		break;
	case CTCPException::err_TCPSSLCertError:
		mapped_errid = "Error::INET::NoSSLCertError";
		break;
	case CTCPException::err_TCPSSLCertNoAccept:
		mapped_errid = "Error::INET::NoSSLCertNoAccept";
		break;
	default:
		{
			COSErrAlertRsrcTxtTask* task = new COSErrAlertRsrcTxtTask(err_id, ex.error(), err_context);
			task->Go();
		}
		return;
	}

	CStopAlertRsrcTxtTask* task = new CStopAlertRsrcTxtTask(mapped_errid, err_context);
	task->Go();

	// Close SMTP
	SMTPClose();
	mMailState = cSMTPNotOpen;
}

#if __dest_os == __win32_os
void CSMTPSender::SMTPHandleFileException(CFileException* ex)
{
	// Reset Status
	SMTPSetStatus("Status::IDLE");

#if __dest_os == __mac_os || __dest_os == __mac_os_x
	// Make sure cursor has stopped spinning
	if (CTaskQueue::sTaskQueue.InMainThread())
		::StopSpinning();
#endif

	// Inform user
	//CErrorHandler::PutFileErrAlertRsrc("Alerts::Adbk::RevertError", *ex);
	CFileException fe(ex->m_cause, ex->m_lOsError, ex->m_strFileName);
	fe.ReportError();

	// Close SMTP
	SMTPClose();
	mMailState = cSMTPNotOpen;
}
#endif

void CSMTPSender::SMTPHandleUnknownException()
{
	// Reset Status
	SMTPSetStatus("Status::IDLE");

#if __dest_os == __mac_os || __dest_os == __mac_os_x
	// Make sure cursor has stopped spinning
	//if (CTaskQueue::sTaskQueue.InMainThread())
	//	::StopSpinning();
#endif

	// Close SMTP
	SMTPClose();
	mMailState = cSMTPNotOpen;
}

// Open SMTP sender
void CSMTPSender::SMTPOpen()
{
	// Init TCP if not already
	mStream.TCPOpen();

	// Do DNS lookup
	SMTPLookup();

	// Create log entry
	mLog.StartLog(CLog::eLogSMTP, mAccount->GetServerIP());
}

// Get error context string
void CSMTPSender::SMTPGetErrorContext(cdstring& error) const
{
	// Add account descriptor
	error += os_endl;
	error += os_endl;
	error += "Account: ";
	error += GetAccountName();
}

// Lookup SMTP sender
void CSMTPSender::SMTPLookup()
{
	// Socket descriptor is server address, authenticator descriptor and TLS type
	cdstring desc = mAccount->GetServerIP();
	desc += GetAccount()->GetAuthenticator().GetDescriptor();
	desc += cdstring((long) GetAccount()->GetTLSType());

	// Set receiver TCP info if different from before
	if (mStream.GetDescriptor() != desc)
	{
		// Copy current receiver for next call
		mStream.SetDescriptor(desc);

		// Set Status
		SMTPSetStatus("Status::SMTP::Lookingup");

		try
		{
			// Get default port based on SSL setting
			tcp_port default_port = 0;
			if ((GetAccount()->GetTLSType() == CINETAccount::eSSL) || (GetAccount()->GetTLSType() == CINETAccount::eSSLv3))
				default_port = kSMTPReceiverPort_SSL;
			else
				default_port = kSMTPReceiverPort;

			// Find out whether reverse lookup is required
			bool need_cname = false;
			switch(GetAccount()->GetAuthenticatorType())
			{
			case CAuthenticator::eNone:			// Actually ANONYMOUS!
			case CAuthenticator::ePlainText:
			case CAuthenticator::eSSL:			// Actually EXTERNAL
			default:;
				break;

			// These ones do AUTHENTICATE processing via plugin
			case CAuthenticator::ePlugin:
				{
					// See if plugin wants cname
					CAuthPlugin* plugin	= GetAccount()->GetAuthenticator().GetPlugin();
					need_cname = plugin ? plugin->NeedCNAME() : false;
				}
				break;
			}

			// Specify remote ip addr (will do reverse lookup if required by auth plugin)
			mStream.TCPSpecifyRemoteName(mAccount->GetServerIP(), default_port, need_cname);
			mReceiver = 0;
		}
		catch (...)
		{
			CLOG_LOGCATCH(...);

			// Failures must force reset of address to do lookup again
			mStream.SetDescriptor(cdstring::null_str);

			// Throw up
			CLOG_LOGRETHROW;
			throw;
		}
	}
}

// Quit and close SMTP sender
void CSMTPSender::SMTPQuitClose()
{
	// Do safe QUIT
	try
	{
		// Send data
		mMailState = cSMTPSendingQuit;
		SMTPSendQuit();

		// Get response
		mMailState = cSMTPWaitingQuitResponse;
		SMTPReceiveData();
	}
	catch (...)
	{
		CLOG_LOGCATCH(...);

		// Do not report error on closing connection
	}
	
	// Do close
	SMTPClose();
}

// Close SMTP sender
void CSMTPSender::SMTPClose()
{
	mMessage = NULL;

	try
	{
		// Release TCP
		mStream.TCPCloseConnection();
	}
	catch (...)
	{
		CLOG_LOGCATCH(...);

		// Do not report error on closing connection
	}

	// Create log entry
	mLog.StopLog();
}

// R E C E I V E  D A T A ___________________________________________________________________________

// Receive data - handle continuations
void CSMTPSender::SMTPReceiveData(char code)
{
	do
	{
		mStream.qgetline(mLineData, cSMTPBufferLen);
		if (mAllowLog && mLog.DoLog())
			*mLog.GetLog() << mLineData << os_endl << std::flush;
		if (!SMTPCheckResponse(code))
		{
			CLOG_LOGTHROW(CSMTPException, *mLineData);
			throw CSMTPException(*mLineData);
		}

	} while (SMTPContinuation());

}

// Initialise capability flags to empty set
void CSMTPSender::SMTPInitCapability()
{
	mAUTH = false;
	mAUTHTypes.clear();
	m8BitMIME = false;
	mPipelining = false;
	mEnhancedStatus = false;
	mDSN = false;
	mSTARTTLS = false;
	mSize = false;
	mSizeLimit = -1;
	mChunking = false;
	mBinaryMIME = false;
	mBurl = false;
	mBurlImap = false;
}

// Receive capability data - handle continuations
void CSMTPSender::SMTPReceiveCapability(char code)
{
	// Clear out existng capabilities before processing again
	SMTPInitCapability();
	
	do
	{
		mStream.qgetline(mLineData, cSMTPBufferLen);
		if (mAllowLog && mLog.DoLog())
			*mLog.GetLog() << mLineData << os_endl << std::flush;
		if (!SMTPCheckResponse(code))
		{
			CLOG_LOGTHROW(CSMTPException, *mLineData);
			throw CSMTPException(*mLineData);
		}

		// Look for capability
		const char* p = mLineData + 4;

		// Punt to fist tag
		while(*p && (*p == ' ')) p++;
		if (*p)
		{
			if (::strncmp(p, "AUTH", 4) == 0)
			{
				mAUTH = true;
				const char* q = (p + 5);
				char* r = ::strtok(const_cast<char*>(q), " ");
				while(r)
				{
					::strupper(r);
					mAUTHTypes.push_back(r);
					r = ::strtok(NULL, " ");
				}
			}
			else if (::strcmp(p, "DSN") == 0)
				mDSN = true;
			else if (::strcmp(p, STARTTLS) == 0)
				mSTARTTLS = true;
			else if (::strcmp(p, ESMTP_8BITMIME) == 0)
				m8BitMIME = true;
			else if (::strcmp(p, ESMTP_PIPELINING) == 0)
				mPipelining = true;
			else if (::strcmp(p, ESMTP_CHUNKING) == 0)
				mChunking = true;
			else if (::strcmp(p, ESMTP_BINARYMIME) == 0)
				mBinaryMIME = true;
			else if (::strcmp(p, ESMTP_ENHANCEDSTATUS) == 0)
				mEnhancedStatus = true;
			else if (::strncmp(p, ESMTP_BURL, 4) == 0)
			{
				mBurl = true;
				const char* q = p + 4;
				while (*q == ' ')
					q++;
				while (*q)
				{
					if (::strncmp(q, "imap", 4) == 0 && (q[4] == '\0' || q[4] == ' '))
						mBurlImap = true;
					while (*q && *q != ' ')
						q++;
					while (*q == ' ')
						q++;
				}
			}
			else if (::strncmp(p, ESMTP_SIZE, 4) == 0)
			{
				mSize = true;
				
				// Look for max. size specifier
				const char* q = p + 4;
				if (*q == ' ')
				{
					while(*q && (*q == ' ')) q++;
					if (*q)
					{
						// Convert to number
						mSizeLimit = ::strtoul(q, NULL, 10);
						
						// SIZE 0 implies no limit so set to max_ulong
						if ((errno == ERANGE) || (mSizeLimit == 0))
							mSizeLimit = -1;
					}
				}
			}
		}

	} while (SMTPContinuation());

}

// Check that received data response is correct
bool CSMTPSender::SMTPCheckResponse(char code)
{
	// Check for positive reply
	return ((*mLineData==code) ? true : false);
}

// Check for continuation of data
bool CSMTPSender::SMTPContinuation()
{
	// Check for positive reply
	return ((mLineData[3] == CONTINUATION) ? true : false);
}

// RFC 3463 enhanced status code descriptions
struct SEnhancedCode { int subject; int detail; const char* text; };

static const SEnhancedCode cEnhancedCodes[] = {
	{ 0, 0, "Other" },
	{ 1, 0, "Other address status" },
	{ 1, 1, "Bad destination mailbox address" },
	{ 1, 2, "Bad destination system address" },
	{ 1, 3, "Bad destination mailbox address syntax" },
	{ 1, 4, "Destination mailbox address ambiguous" },
	{ 1, 5, "Destination address valid" },
	{ 1, 6, "Destination mailbox has moved" },
	{ 1, 7, "Bad sender's mailbox address syntax" },
	{ 1, 8, "Bad sender's system address" },
	{ 1, 9, "Message relayed to non-compliant mailer" },
	{ 1, 10, "Recipient address has null MX" },
	{ 2, 0, "Other mailbox status" },
	{ 2, 1, "Mailbox disabled, not accepting messages" },
	{ 2, 2, "Mailbox full" },
	{ 2, 3, "Message length exceeds limit" },
	{ 2, 4, "Mailing list expansion problem" },
	{ 3, 0, "Other mail system status" },
	{ 3, 1, "Mail system full" },
	{ 3, 2, "System not accepting messages" },
	{ 3, 3, "System not capable of selected features" },
	{ 3, 4, "Message too big for system" },
	{ 3, 5, "System incorrectly configured" },
	{ 3, 6, "Requested priority was changed" },
	{ 4, 0, "Other network/routing status" },
	{ 4, 1, "No answer from host" },
	{ 4, 2, "Bad connection" },
	{ 4, 3, "Directory server failure" },
	{ 4, 4, "Unable to route" },
	{ 4, 5, "Mail system congestion" },
	{ 4, 6, "Routing loop detected" },
	{ 4, 7, "Delivery time expired" },
	{ 5, 0, "Other protocol status" },
	{ 5, 1, "Invalid command" },
	{ 5, 2, "Syntax error" },
	{ 5, 3, "Too many recipients" },
	{ 5, 4, "Invalid command arguments" },
	{ 5, 5, "Wrong protocol version" },
	{ 5, 6, "Authentication exchange line too long" },
	{ 6, 0, "Other media error" },
	{ 6, 1, "Media not supported" },
	{ 6, 2, "Conversion required and prohibited" },
	{ 6, 3, "Conversion required but not supported" },
	{ 6, 4, "Conversion with loss performed" },
	{ 6, 5, "Conversion failed" },
	{ 6, 6, "Message content could not be fetched from remote" },
	{ 6, 7, "Non-ASCII addresses not permitted for this sender/recipient" },
	{ 6, 8, "UTF-8 string reply required but not permitted by SMTP session" },
	{ 6, 9, "UTF-8 header message cannot be transferred to non-UTF-8 session" },
	{ 7, 0, "Other security status" },
	{ 7, 1, "Delivery not authorized, message refused" },
	{ 7, 2, "Mailing list expansion prohibited" },
	{ 7, 3, "Security conversion required but not possible" },
	{ 7, 4, "Security features not supported" },
	{ 7, 5, "Cryptographic failure" },
	{ 7, 6, "Cryptographic algorithm not supported" },
	{ 7, 7, "Message integrity failure" },
	{ 7, 8, "Authentication credentials invalid" },
	{ 7, 9, "Authentication mechanism too weak" },
	{ 7, 10, "Encryption needed" },
	{ 7, 11, "Encryption required for requested authentication" },
	{ 7, 12, "Password transition needed" },
	{ 7, 13, "Account disabled" },
	{ 7, 14, "Trust relationship required" },
	{ 7, 15, "Priority level too low" },
	{ 7, 16, "Message too big for specified priority" },
	{ 7, 17, "Mailbox owner has changed" },
	{ 7, 18, "Domain owner has changed" },
	{ 7, 19, "RRVS test cannot be completed" },
	{ 7, 20, "No passing DKIM signature found" },
	{ 7, 21, "No acceptable DKIM signature found" },
	{ 7, 22, "No valid author-matched DKIM signature found" },
	{ 7, 23, "SPF validation failed" },
	{ 7, 24, "SPF validation error" },
	{ 7, 25, "Reverse DNS validation failed" },
	{ 7, 26, "Multiple authentication checks failed" },
	{ 7, 27, "Sender address has null MX" },
	{ 7, 28, "Mail flood detected" },
	{ 7, 29, "ARC validation failure" },
	{ 7, 30, "REQUIRETLS support required" },
	{ -1, -1, NULL }
};

const char* CSMTPSender::GetEnhancedStatusText() const
{
	if (!mEnhancedStatus)
		return NULL;

	const char* p = mLineData + 4;
	if (!*p || !::isdigit(*p))
		return NULL;

	int eclass = *p - '0';
	if (*(p+1) != '.')
		return NULL;

	int esubject = ::atoi(p + 2);
	const char* dot2 = ::strchr(p + 2, '.');
	if (!dot2)
		return NULL;
	int edetail = ::atoi(dot2 + 1);

	const char* subject_fallback = NULL;
	for (const SEnhancedCode* code = cEnhancedCodes; code->subject >= 0; code++)
	{
		if (code->subject == esubject && code->detail == edetail)
			return code->text;
		if (code->subject == esubject && code->detail == 0)
			subject_fallback = code->text;
	}

	return subject_fallback;
}

void CSMTPSender::SMTPMapErrorStr(const char*& syserr_id, const char*& protobad_id)
{
	// Handle error or warning condition
	switch (mMailState)
	{

		case cSMTPOpen:
		case cSMTPOpeningReceiver:
		case cSMTPWaitingReceiverResponse:
			syserr_id = "Error::SMTP::OSErrOpen";
			protobad_id = "Error::SMTP::NoBadOpen";
			break;

		case cSMTPSendingEHello:
		case cSMTPWaitingEHelloResponse:
			syserr_id = "Error::SMTP::OSErrEHello";
			protobad_id = "Error::SMTP::NoBadEHello";
			break;

		case cSMTPSendingHello:
		case cSMTPWaitingHelloResponse:
			syserr_id = "Error::SMTP::OSErrHello";
			protobad_id = "Error::SMTP::NoBadHello";
			break;

		case cSMTPSendingAuth:
		case cSMTPWaitingAuthResponse:
			syserr_id = "Error::SMTP::OSErrAuth";
			protobad_id = "Error::SMTP::NoBadAuth";
			break;

		case cSMTPSendingStartTLS:
		case cSMTPWaitingStartTLSResponse:
			syserr_id = "Error::SMTP::OSErrStartTLS";
			protobad_id = "Error::SMTP::NoBadStartTLS";
			break;

		case cSMTPTLSClientCert:
			syserr_id = "Error::SMTP::OSErrTLSClientCert";
			protobad_id = "Error::SMTP::NoBadTLSClientCert";
			break;

		case cSMTPSendingMail:
		case cSMTPWaitingMailResponse:
			syserr_id = "Error::SMTP::OSErrMail";
			protobad_id = "Error::SMTP::NoBadMail";
			break;

		case cSMTPSendingToRcpt:
		case cSMTPSendingCCRcpt:
		case cSMTPSendingBCCRcpt:
		case cSMTPWaitingRcptResponse:
			syserr_id = "Error::SMTP::OSErrRcpt";
			protobad_id = "Error::SMTP::NoBadRcpt";
			break;

		case cSMTPSendingDataCmd:
		case cSMTPWaitingDataCmdResponse:
		case cSMTPSendingData:
		case cSMTPWaitingDataResponse:
		case cSMTPSendingBdat:
		case cSMTPWaitingBdatResponse:
		case cSMTPSendingBurl:
		case cSMTPWaitingBurlResponse:
			syserr_id = "Error::SMTP::OSErrData";
			protobad_id = "Error::SMTP::NoBadData";
			break;

		case cSMTPSendingQuit:
		case cSMTPWaitingQuitResponse:
			syserr_id = "Error::SMTP::OSErrQuit";
			protobad_id = "Error::SMTP::NoBadQuit";
			break;

		case cSMTPClosing:
			syserr_id = "Error::SMTP::OSErrClose";
			protobad_id = "Error::SMTP::NoBadClose";
			break;

		case cSMTPErrorNoAUTH:
			syserr_id = "Error::SMTP::NoBadAUTH";
			protobad_id = "Error::SMTP::NoBadAUTH";
			*mLineData = 0;		// No text to append
			break;

		case cSMTPErrorNoAUTHType:
			syserr_id = "Error::SMTP::NoBadAUTHType";
			protobad_id = "Error::SMTP::NoBadAUTHType";
			*mLineData = 0;		// No text to append
			break;

		case cSMTPErrorNoTLS:
			syserr_id = "Error::SMTP::NoBadTLS";
			protobad_id = "Error::SMTP::NoBadTLS";
			*mLineData = 0;		// No text to append
			break;
		default:
			// Always NULL out if no mapping found
			syserr_id = NULL;
			protobad_id = NULL;
			break;

	}
}

// S E N D  D A T A _________________________________________________________________________________

// Send 'HELO'/'EHLO' to receiver
void CSMTPSender::SMTPSendHello(bool extend)
{
	// Must check for correct format of <domain> in RFC821
	cdstring domain(mStream.TCPGetSocketName());
	if (!CTCPSocket::TCPIsHostName(domain))
	{
		domain = "[";
		domain += mStream.TCPGetSocketName();
		domain += "]";
	}

	// Use host machines canonical name/ip name for domain
	mStream << (extend ? EHLO : HELO) << domain << CRLF << std::flush;

	// Write to log file
	if (mLog.DoLog())
		*mLog.GetLog() << (extend ? EHLO : HELO) << domain << os_endl << std::flush;
}

// Setup TLS certificate
bool CSMTPSender::SMTPTLSClientCertificate()
{
	bool result = false;

	// Get client certificate name from account
	cdstring certfingerprint = GetAccount()->GetTLSClientCert();
	
	// Get the subject of the cert with this fingerprint
	cdstring certname;
	if (!CCertificateManager::sCertificateManager->GetSubject(certfingerprint, certname, CCertificateManager::eByFingerprint))
		return false;
	
	// Get a passphrase for this certificate
	cdstrvect users;
	users.push_back(certname);
	const char** user_list = cdstring::ToArray(users);

	cdstring passphrase;
	passphrase.reserve(512);
	unsigned long chosen;
	while(true)
	{
		if (CSecurityPlugin::GetPassphrase(user_list, passphrase.c_str_mod(), chosen))
		{
			// Try to load private key (this will verify that the password etc is valid)
			if (mStream.TLSSetClientCert(certfingerprint, passphrase))
			{
				result = true;
				break;
			}

			// Display cert error alert
			mMailState = cSMTPTLSClientCert;
			CTCPException ex(CTCPException::err_TCPSSLClientCertLoad);
			SMTPHandleTCPException(ex);
			
			// Clear password cache
			CSecurityPlugin::ClearLastPassphrase();
		}
		else
			break;
	}

	// Clean-up	
	cdstring::FreeArray(user_list);

	return result;
}

// Do TLS
void CSMTPSender::SMTPStartTLS()
{
	// Use host machines canonical name/ip name for domain
	mMailState = cSMTPSendingStartTLS;
	mStream << STARTTLS << CRLF << std::flush;

	// Write to log file
	if (mLog.DoLog())
		*mLog.GetLog() << STARTTLS << os_endl << std::flush;

	// Get response
	mMailState = cSMTPWaitingStartTLSResponse;
	SMTPReceiveData();

	// Now force TLS negotiation
	mStream.TLSSetTLSOn(true, GetAccount()->GetTLSType());
	mStream.TLSStartConnection();
	
	// Now redo EHLO so that we get updated capabilities
	if (mESMTP)
	{
		mMailState = cSMTPSendingEHello;
		SMTPSendEHello();

		// Get response - may fail if EHLO not supported
		mMailState = cSMTPWaitingEHelloResponse;

		// Process the EHLO response as capability
		SMTPReceiveCapability();
	}	
}

// Run authentication loop to try and login
bool CSMTPSender::SMTPDoAuthentication()
{
	bool first = true;
	bool done = false;

	// Loop while trying to authentciate
	CAuthenticator* acct_auth = GetAccount()->GetAuthenticator().GetAuthenticator();

	while(CMailControl::PromptUser(acct_auth, GetAccount(), IsSecure(), false, true, false, false, false, false, first))
	{
		first = false;

		// Do authentication, but trap protocol failures
		try
		{
			SMTPAuthenticate();
			done = true;

			// Recache user id & password after successful logon
			if (GetAccount()->GetAuthenticator().RequiresUserPswd())
			{
				CAuthenticatorUserPswd* auth = GetAccount()->GetAuthenticatorUserPswd();

				// Only bother if it contains something
				if (!auth->GetPswd().empty())
				{
					CPasswordManager::GetManager()->AddPassword(GetAccount(), auth->GetPswd());
				}
			}
		}
		catch (CSMTPException& ex)
		{
			CLOG_LOGCATCH(CSMTPException&);

			// Do visual alert
			const char* err_id;
			const char* nobad_id;

			SMTPMapErrorStr(err_id, nobad_id);

			// Handle error
			CStopAlertRsrcTxtTask* task = new CStopAlertRsrcTxtTask(nobad_id, mLineData);
			task->Go();

			// Force it to recycle
			done = false;
		}

		if (done)
			break;
	}

	return done;
}

// Send 'AUTH' to receiver
void CSMTPSender::SMTPAuthenticate()
{
	//bool first = true;

	CAuthenticator* acct_auth = GetAccount()->GetAuthenticator().GetAuthenticator();

	switch(GetAccount()->GetAuthenticatorType())
	{
	case CAuthenticator::ePlainText:
		{
			CAuthenticatorUserPswd* auth = static_cast<CAuthenticatorUserPswd*>(acct_auth);

			// RFC 4954: MUST NOT use PLAIN/LOGIN without TLS
			if (!mStream.TLSIsTLSOn())
			{
				cdstring error = rsrc::GetString("Error::SMTP::AuthRequiresTLS");
				::strcpy(mLineData, error.c_str());
				CLOG_LOGTHROW(CSMTPException, FAIL_RESPONSE);
				throw CSMTPException(FAIL_RESPONSE);
			}

			// Look for AUTH PLAIN
			cdstrvect::const_iterator found1 = std::find(mAUTHTypes.begin(), mAUTHTypes.end(), cPLAIN);
			cdstrvect::const_iterator found2 = std::find(mAUTHTypes.begin(), mAUTHTypes.end(), cLOGIN);
			if (found1 != mAUTHTypes.end())
			{
				// Form buffer of plain text SASL response
				// \0userid\0pswd
				size_t buflen = auth->GetUID().length() + auth->GetPswd().length() + 2;
				char* buffer = new char[buflen];
				char* p = buffer;
				*p++ = 0;
				::memcpy(p, auth->GetUID().c_str(), auth->GetUID().length());
				p += auth->GetUID().length();
				*p++ = 0;
				::memcpy(p, auth->GetPswd().c_str(), auth->GetPswd().length());

				// Base64 encode it
				cdstring b64;
				b64.steal(::base64_encode(reinterpret_cast<unsigned char*>(buffer), buflen));
				delete[] buffer;

				// Do not allow logging of auth details
				StValueChanger<bool> value(mAllowLog, CLog::AllowAuthenticationLog());

				// Use host machines canonical name/ip name for domain
				mStream << AUTHPLAIN << b64 << CRLF << std::flush;

				// Write to log file
				if (mAllowLog && mLog.DoLog())
					*mLog.GetLog() << AUTHPLAIN << b64 << os_endl << std::flush;

				// Get response
				mMailState = cSMTPWaitingAuthResponse;
				SMTPReceiveData();
			}
			else if (found2 != mAUTHTypes.end())
			{
				// Use host machines canonical name/ip name for domain
				mStream << AUTHLOGIN << CRLF << std::flush;

				// Write to log file
				if (mAllowLog && mLog.DoLog())
					*mLog.GetLog() << AUTHLOGIN << os_endl << std::flush;

				try
				{
				// Wait for data response
				SMTPReceiveData(DATA_RESPONSE);

				// Send base64 encoded user id
				cdstring buffer = auth->GetUID();
				cdstring b64;
				b64.steal(::base64_encode(reinterpret_cast<const unsigned char*>(buffer.c_str()), buffer.length()));
				mStream << b64 << CRLF << std::flush;

				// Write to log file
				if (mAllowLog && mLog.DoLog())
					*mLog.GetLog() << b64 << os_endl << std::flush;

				// Wait for data response
				SMTPReceiveData(DATA_RESPONSE);

				// Send base64 encoded password
				buffer = auth->GetPswd();
				b64.steal(::base64_encode(reinterpret_cast<const unsigned char*>(buffer.c_str()), buffer.length()));
				mStream << b64 << CRLF << std::flush;

				// Write to log file
				if (mAllowLog && mLog.DoLog())
					*mLog.GetLog() << b64 << os_endl << std::flush;
				
				// Wait for success response
				SMTPReceiveData();
				}
				catch(...)
				{
					CLOG_LOGCATCH(...);
					// Cancel AUTH exchange (RFC 4954)
					mStream << "*" << CRLF << std::flush;
					CLOG_LOGRETHROW;
					throw;
				}
			}
		}
		break;

	case CAuthenticator::eSSL:
		{
			//CAuthenticatorUserPswd* auth = static_cast<CAuthenticatorUserPswd*>(acct_auth);

			// Do not allow logging of auth details
			StValueChanger<bool> value(mAllowLog, CLog::AllowAuthenticationLog());

			// RFC 4954: zero-length initial response MUST be sent as "="
			mStream << AUTHEXTERNAL << "=" << CRLF << std::flush;

			// Write to log file
			if (mAllowLog && mLog.DoLog())
				*mLog.GetLog() << AUTHEXTERNAL << "=" << os_endl << std::flush;

			// Get response
			mMailState = cSMTPWaitingAuthResponse;
			SMTPReceiveData();
		}
		break;

	// These ones do AUTHENTICATE processing via plugin
	case CAuthenticator::ePlugin:
		{
			// Find CRAM-MD5 plugin
			CAuthPlugin* plugin	= GetAccount()->GetAuthenticator().GetPlugin();

			if (plugin)
			{
				cdstring capability;
				if (!plugin->DoAuthentication(&GetAccount()->GetAuthenticator(),
											GetAccount()->GetServerType(),
											GetAccount()->GetServerTypeString(),
											mStream, mLog, mLineData, cSMTPBufferLen,
											capability))
				{
					const char* p = mLineData;

					// Bump past tag & space "a " if there
					if (::strncmp(p, "a ", 2) == 0)
						p += 2;

					// Fake response
					CLOG_LOGTHROW(CSMTPException, *mLineData);
					throw CSMTPException(*mLineData);
				}
			}
			else
			{
				// Fake bad response
				::strcpy(mLineData, "Authentication plugin not found\r");
				CLOG_LOGTHROW(CSMTPException, '5');
				throw CSMTPException('5');
			}

			break;
		}
	default:;
	}
}

// Send 'RSET' from
bool CSMTPSender::SMTPVerifyAddress(const cdstring& addr, cdstring& result)
{
	mStream << "VRFY " << addr << CRLF << std::flush;

	if (mAllowLog && mLog.DoLog())
		*mLog.GetLog() << "VRFY " << addr << os_endl << std::flush;

	mStream.qgetline(mLineData, cSMTPBufferLen);
	while (SMTPContinuation())
		mStream.qgetline(mLineData, cSMTPBufferLen);

	if (mAllowLog && mLog.DoLog())
		*mLog.GetLog() << mLineData << os_endl << std::flush;

	if (*mLineData == OK_RESPONSE)
	{
		result = mLineData + 4;
		return true;
	}

	result = cdstring::null_str;
	return false;
}

void CSMTPSender::SMTPSendRset()
{
	mStream << RSET << CRLF << std::flush;

	// Write to log file
	if (mLog.DoLog())
		*mLog.GetLog() << RSET << os_endl << std::flush;
}

// Send 'MAIL' from
void CSMTPSender::SMTPSendMail()
{
	cdstring theTxt;

	// RFC 8098: MDN envelope sender MUST be null (<>) to prevent DSN bounce loops
	if (mMessage->GetBody() && mMessage->GetBody()->IsMDN())
	{
		// Leave theTxt empty — produces MAIL FROM:<>
	}
	else if (mMessage->GetEnvelope()->GetFrom()->size())
		 theTxt = mMessage->GetEnvelope()->GetFrom()->front()->GetMailAddress();

	mStream << MAILFROM << theTxt << '>';

	// Write to log file
	if (mLog.DoLog())
		*mLog.GetLog() << MAILFROM << theTxt << '>';

	// Declare body type: BINARYMIME (RFC 3030) takes precedence over 8BITMIME (RFC 6152)
	if (mUseBinaryCTE)
	{
		mStream << " BODY=BINARYMIME";

		if (mLog.DoLog())
			*mLog.GetLog() << " BODY=BINARYMIME";
	}
	else if (m8BitMIME)
	{
		mStream << " BODY=8BITMIME";

		if (mLog.DoLog())
			*mLog.GetLog() << " BODY=8BITMIME";
	}

	// Look for size
	if (mSize && mMessage->GetSize())
	{
		mStream << " " << ESMTP_SIZE << "=" << cdstring(mMessage->GetSize());

		// Write to log file
		if (mLog.DoLog())
			*mLog.GetLog() << " " << ESMTP_SIZE << "=" << cdstring(mMessage->GetSize());
	}

	// Look for DSN
	if (mDSN && mMsgDSN.GetRequest())
	{
		mStream << " " << RET << (mMsgDSN.GetFull() ? RET_FULL : RET_HDRS);

		// Write to log file
		if (mLog.DoLog())
			*mLog.GetLog() << " " << RET << (mMsgDSN.GetFull() ? RET_FULL : RET_HDRS);
	}

	// Finished
	mStream << CRLF << std::flush;

	// Write to log file
	if (mLog.DoLog())
		*mLog.GetLog() << os_endl << std::flush;
}

// Send 'RCPT'
void CSMTPSender::SMTPSendRcpt(const cdstring& addr)
{
	mStream << RCPTTO << addr << '>';

	// Write to log file
	if (mLog.DoLog())
		*mLog.GetLog() << RCPTTO << addr << '>';

	// Look for DSN
	if (mDSN && mMsgDSN.GetRequest())
	{
		mStream << " " << NOTIFY;
		// Write to log file
		if (mLog.DoLog())
			*mLog.GetLog() << " " << NOTIFY;
		if (mMsgDSN.GetSuccess() ||
			mMsgDSN.GetFailure() ||
			mMsgDSN.GetDelay())
		{
			bool done = false;
			if (mMsgDSN.GetSuccess())
			{
				mStream << NOTIFY_SUCCESS;
				if (mLog.DoLog())
					*mLog.GetLog() << NOTIFY_SUCCESS;
				done = true;
			}
			if (mMsgDSN.GetFailure())
			{
				if (done)
					mStream << ',';
				mStream << NOTIFY_FAILURE;
				if (mLog.DoLog())
				{
					if (done)
						*mLog.GetLog() << ",";
					*mLog.GetLog() << NOTIFY_FAILURE;
				}
				done = true;
			}
			if (mMsgDSN.GetDelay())
			{
				if (done)
					mStream << ',';
				mStream << NOTIFY_DELAY;
				if (mLog.DoLog())
				{
					if (done)
						*mLog.GetLog() << ",";
					*mLog.GetLog() <<  NOTIFY_DELAY;
				}
				done = true;
			}
		}
		else
		{
			mStream << NOTIFY_NEVER;
			if (mLog.DoLog())
				*mLog.GetLog() << " " << NOTIFY_NEVER;
		}
	}

	// Finished
	mStream << CRLF << std::flush;

	// Write to log file
	if (mLog.DoLog())
		*mLog.GetLog() << os_endl << std::flush;
}

// Send 'RCPT' for all To's
void CSMTPSender::SMTPSendToRcpt()
{
	cdstring theTxt = mMessage->GetEnvelope()->GetTo()->at(mToCtr)->GetMailAddress();
	SMTPSendRcpt(theTxt);
}

// Send 'RCPT' for all CC's
void CSMTPSender::SMTPSendCCRcpt()
{
	cdstring theTxt = mMessage->GetEnvelope()->GetCC()->at(mCcCtr)->GetMailAddress();
	SMTPSendRcpt(theTxt);
}

// Send 'RCPT' for all BCC's
void CSMTPSender::SMTPSendBCCRcpt()
{
	cdstring theTxt = mMessage->GetEnvelope()->GetBcc()->at(mBccCtr)->GetMailAddress();
	SMTPSendRcpt(theTxt);
}

// Send 'DATA' to receiver
void CSMTPSender::SMTPSendDataCmd()
{
	mStream << DATA << CRLF << std::flush;

	// Write to log file
	if (mLog.DoLog())
		*mLog.GetLog() << DATA << os_endl << std::flush;
}

// Send text to receiver (remember to add header)
void CSMTPSender::SMTPSendData()
{
	//OSErr err = noErr;
	//unsigned long part_count = 1;
	//unsigned long part_offset = 0;

	// Need to dot-stuff
	bool body_ended_crlf = true;
	{
		dotstuff_filterbuf* ds_buf = new dotstuff_filterbuf(true);
		CStreamFilter dot_stuff(ds_buf, static_cast<std::ostream*>(&mStream));

		// Create stream type for output
		costream stream_out(&dot_stuff, eEndl_CRLF);

		// Send header (with LFs after CRs)
		// Use appropraite filter
		const char* hdr = mMessage->GetHeader();
		if (stream_out.IsLocalType())
		{
			mStream.write(hdr, ::strlen(hdr));
		}
		else
		{
			CStreamFilter filter(new crlf_filterbuf(stream_out.GetEndlType()), static_cast<std::ostream*>(&mStream));
			filter.write(hdr, ::strlen(hdr));
		}

		// Write to log file
		if (mLog.DoLog())
			*mLog.GetLog() << hdr;

		if (mMessage->GetBody())
		{
			CSMTPAttachProgress progress;
			progress.SetTotal(mMessage->GetBody()->CountParts());
			unsigned long level = 0;

			// Write as an unowned draft or a mailbox-based message
			if (mMessage->GetMbox() && (mMessage->GetMbox() == mQueueMbox))
			{
				// Always add CRLF since async message is not reconstructed
				mStream << CRLF;
				if (mLog.DoLog())
					*mLog.GetLog() << os_endl;

				// Copy message body direct to stream
				mQueueMbox->CopyAttachment(mMessage, mMessage->GetBody(), &stream_out);

				// Write to log file
				if (mLog.DoLog())
				{
					// Create stream type for output
					costream log_out(mLog.GetLog(), lendl);
					mQueueMbox->CopyAttachment(mMessage, mMessage->GetBody(), &log_out);
				}
			}
			else
			{
				mMessage->GetBody()->WriteToStream(stream_out, level, false, &progress);
				// Write to log file
				if (mLog.DoLog())
				{
					// Create stream type for output
					costream log_out(mLog.GetLog(), lendl);
					mMessage->GetBody()->WriteToStream(log_out, level, false, NULL);
				}
			}
		}
		body_ended_crlf = ds_buf->EndedWithCRLF();
	}

	// Send mail terminator — only prepend CRLF if body didn't end with one
	if (body_ended_crlf)
		mStream << DOT_CRLF << std::flush;
	else
		mStream << CRLF_DOT_CRLF << std::flush;

	// Write to log file
	if (mLog.DoLog())
		*mLog.GetLog() << os_endl << "." << os_endl << std::flush;
}

// Send message via BDAT (RFC 3030 CHUNKING)
void CSMTPSender::SMTPSendBdat()
{
	// Temporarily switch non-text parts to binary encoding if BINARYMIME available
	if (mUseBinaryCTE)
		SMTPSetBinaryEncodings(mMessage->GetBody());

	// Serialize entire message to buffer — no dot-stuffing needed for BDAT
	std::string data;
	{
		std::ostringstream buf;
		try
		{
			costream stream_out(&buf, eEndl_CRLF);

			// Write header with CRLF conversion
			const char* hdr = mMessage->GetHeader();
			if (stream_out.IsLocalType())
			{
				buf.write(hdr, ::strlen(hdr));
			}
			else
			{
				CStreamFilter filter(new crlf_filterbuf(stream_out.GetEndlType()), static_cast<std::ostream*>(&buf));
				filter.write(hdr, ::strlen(hdr));
			}

			if (mLog.DoLog())
				*mLog.GetLog() << hdr;

			// Write body
			if (mMessage->GetBody())
			{
				CSMTPAttachProgress progress;
				progress.SetTotal(mMessage->GetBody()->CountParts());
				unsigned long level = 0;

				if (mMessage->GetMbox() && (mMessage->GetMbox() == mQueueMbox))
				{
					buf << CRLF;
					if (mLog.DoLog())
						*mLog.GetLog() << os_endl;

					mQueueMbox->CopyAttachment(mMessage, mMessage->GetBody(), &stream_out);

					if (mLog.DoLog())
					{
						costream log_out(mLog.GetLog(), lendl);
						mQueueMbox->CopyAttachment(mMessage, mMessage->GetBody(), &log_out);
					}
				}
				else
				{
					mMessage->GetBody()->WriteToStream(stream_out, level, false, &progress);
					if (mLog.DoLog())
					{
						costream log_out(mLog.GetLog(), lendl);
						mMessage->GetBody()->WriteToStream(log_out, level, false, NULL);
					}
				}
			}
		}
		catch(...)
		{
			CLOG_LOGCATCH(...);

			if (mUseBinaryCTE)
				SMTPRestoreEncodings();

			CLOG_LOGRETHROW;
			throw;
		}

		// Restore original encodings now that serialization is complete
		if (mUseBinaryCTE)
			SMTPRestoreEncodings();

		data = buf.str();
	}

	unsigned long total_size = data.size();

	// Send BDAT chunks — pipelined when supported, single BDAT LAST otherwise
	if (mPipelining && (total_size > kSMTPBdatChunkSize))
	{
		// Pipeline multiple BDAT chunks
		unsigned long offset = 0;
		unsigned long chunk_count = 0;
		while(offset < total_size)
		{
			unsigned long remaining = total_size - offset;
			unsigned long chunk_size = (remaining > kSMTPBdatChunkSize) ? kSMTPBdatChunkSize : remaining;
			bool is_last = (offset + chunk_size >= total_size);

			if (is_last)
				mStream << BDAT << chunk_size << " LAST" << CRLF;
			else
				mStream << BDAT << chunk_size << CRLF;

			if (mLog.DoLog())
			{
				if (is_last)
					*mLog.GetLog() << os_endl << BDAT << chunk_size << " LAST" << os_endl;
				else
					*mLog.GetLog() << os_endl << BDAT << chunk_size << os_endl;
			}

			mStream.write(data.data() + offset, chunk_size);
			offset += chunk_size;
			chunk_count++;
		}
		mStream << std::flush;

		if (mLog.DoLog())
			*mLog.GetLog() << std::flush;

		// Read all pipelined BDAT responses — drain on failure then RSET (RFC 3030)
		mMailState = cSMTPWaitingBdatResponse;
		for(unsigned long i = 0; i < chunk_count; i++)
		{
			try
			{
				SMTPReceiveData();
			}
			catch(CSMTPException&)
			{
				CLOG_LOGCATCH(CSMTPException&);

				// Drain remaining pipelined BDAT responses
				for(unsigned long j = i + 1; j < chunk_count; j++)
				{
					try
					{
						mStream.qgetline(mLineData, cSMTPBufferLen);
						while (SMTPContinuation())
							mStream.qgetline(mLineData, cSMTPBufferLen);
					}
					catch(...) {}
				}

				// RSET to clear indeterminate transaction state (RFC 3030 §2)
				try
				{
					SMTPSendRset();
					SMTPReceiveData();
				}
				catch(...) {}

				CLOG_LOGRETHROW;
				throw;
			}
		}
	}
	else
	{
		// Single BDAT LAST
		mStream << BDAT << total_size << " LAST" << CRLF;

		if (mLog.DoLog())
			*mLog.GetLog() << os_endl << BDAT << total_size << " LAST" << os_endl;

		mStream.write(data.data(), total_size);
		mStream << std::flush;

		if (mLog.DoLog())
			*mLog.GetLog() << std::flush;

		// Read single BDAT response
		mMailState = cSMTPWaitingBdatResponse;
		SMTPReceiveData();
	}
}

// Send BURL command (RFC 4468)
void CSMTPSender::SMTPSendBurl(const cdstring& url, bool last)
{
	mMailState = cSMTPSendingBurl;

	mStream << BURL_CMD << url;
	if (last)
		mStream << BURL_LAST;
	mStream << CRLF << std::flush;

	if (mAllowLog && mLog.DoLog())
	{
		*mLog.GetLog() << BURL_CMD << url;
		if (last)
			*mLog.GetLog() << BURL_LAST;
		*mLog.GetLog() << os_endl << std::flush;
	}

	mMailState = cSMTPWaitingBurlResponse;
	SMTPReceiveData();
}

// Send one or more BURL commands for message submission (RFC 4468)
void CSMTPSender::SMTPSendBurlMessage(const cdstrvect& urls)
{
	for (size_t i = 0; i < urls.size(); i++)
	{
		bool is_last = (i == urls.size() - 1);
		SMTPSendBurl(urls[i], is_last);
	}
}

// Set binary encoding on non-text parts for BINARYMIME (RFC 3030)
void CSMTPSender::SMTPSetBinaryEncodings(CAttachment* attach)
{
	if (!attach)
		return;

	// Never modify CTE inside signed or encrypted envelopes —
	// the signature was computed over the original encoding
	if (attach->IsSigned() || attach->IsEncrypted())
		return;

	// Recurse into multipart children
	if (attach->GetParts())
	{
		for(CAttachmentList::iterator iter = attach->GetParts()->begin();
			iter != attach->GetParts()->end(); iter++)
		{
			SMTPSetBinaryEncodings(*iter);
		}
	}
	else if (!attach->IsText() &&
		(attach->GetContent().GetTransferEncoding() == eBase64Encoding))
	{
		// Save original encoding and switch to binary
		mSavedEncodings.push_back(CSavedEncoding(attach, eBase64Encoding));
		attach->GetContent().SetTransferEncoding(eBinaryEncoding);
	}
}

// Restore original encodings after BDAT serialization
void CSMTPSender::SMTPRestoreEncodings()
{
	for(std::vector<CSavedEncoding>::iterator iter = mSavedEncodings.begin();
		iter != mSavedEncodings.end(); iter++)
	{
		iter->first->GetContent().SetTransferEncoding(iter->second);
	}
	mSavedEncodings.clear();
}

// Check if message body has any non-text parts with base64 encoding
bool CSMTPSender::SMTPHasBase64Parts(const CAttachment* attach) const
{
	if (!attach)
		return false;

	if (attach->GetParts())
	{
		for(CAttachmentList::const_iterator iter = attach->GetParts()->begin();
			iter != attach->GetParts()->end(); iter++)
		{
			if (SMTPHasBase64Parts(*iter))
				return true;
		}
	}
	else if (!attach->IsText() &&
		(attach->GetContent().GetTransferEncoding() == eBase64Encoding))
	{
		return true;
	}

	return false;
}

// Send 'QUIT' to receiver
void CSMTPSender::SMTPSendQuit()
{
	mStream << QUIT << CRLF << std::flush;

	// Write to log file
	if (mLog.DoLog())
		*mLog.GetLog() << QUIT << os_endl << std::flush;
}
