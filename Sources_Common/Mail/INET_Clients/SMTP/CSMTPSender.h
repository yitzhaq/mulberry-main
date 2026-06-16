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


// Header for SMTP sender class

#ifndef __CSMTPSENDER__MULBERRY__
#define __CSMTPSENDER__MULBERRY__

#include "CLog.h"
#include "CGeneralException.h"
#include "CNetworkException.h"
#include "CTCPStream.h"

#include "CSMTPCommon.h"

#include "CDSN.h"
#include "CMIMETypes.h"

#include "cdstring.h"

#include <sstream>
#include <utility>
#include <vector>

#include <stdio.h>

#define	kSMTPRcvLen			8192
#define	kSMTPSendLen		8192
#define kSMTPAttachBuffer	32768L

// consts

enum SMTPSenderState
{
	cSMTPNotOpen,
	cSMTPOpen,
	cSMTPOpeningReceiver,
	cSMTPWaitingReceiverResponse,
	cSMTPSendingEHello,
	cSMTPWaitingEHelloResponse,
	cSMTPSendingHello,
	cSMTPWaitingHelloResponse,
	cSMTPSendingAuth,
	cSMTPWaitingAuthResponse,
	cSMTPSendingStartTLS,
	cSMTPWaitingStartTLSResponse,
	cSMTPTLSClientCert,
	cSMTPSendingMail,
	cSMTPWaitingMailResponse,
	cSMTPSendingToRcpt,
	cSMTPSendingCCRcpt,
	cSMTPSendingBCCRcpt,
	cSMTPWaitingRcptResponse,
	cSMTPSendingDataCmd,
	cSMTPWaitingDataCmdResponse,
	cSMTPSendingData,
	cSMTPWaitingDataResponse,
	cSMTPSendingBdat,
	cSMTPWaitingBdatResponse,
	cSMTPSendingBurl,
	cSMTPWaitingBurlResponse,
	cSMTPSendingQuit,
	cSMTPWaitingQuitResponse,
	cSMTPClosing,
	cSMTPErrorNoAUTH,
	cSMTPErrorNoAUTHType,
	cSMTPErrorNoTLS
};

class CAttachment;
class CMbox;
class CMessage;
class CINETAccount;
class CFileAttachment;
class CTCPException;

class CSMTPSender
{
	class CSMTPException : public CNetworkException
	{
	public:
		enum { class_ID = 'smtp' };

		CSMTPException(char err_code) : CNetworkException(err_code) { _class = class_ID; }
		bool IsTemporary() const { return _err == '4'; }
		bool IsPermanent() const { return _err == '5'; }
	};

	// I N S T A N C E  V A R I A B L E S

private:
	CINETAccount*		mAccount;						// Account info
	cdstring			mAccountName;					// Account info
	CTCPStream			mStream;
	ip_addr				mReceiver;
	CMessage*			mMessage;
	SMTPSenderState		mMailState;
	char*				mLineData;
	unsigned long		mToCtr;
	unsigned long		mCcCtr;
	unsigned long		mBccCtr;
	CLog				mLog;							// Logging class
	bool				mAllowLog;						// Allow logging
	bool				mESMTP;							// ESMTP protocol supported
	bool				mSize;							// SIZE supported
	unsigned long		mSizeLimit;						// SIZE limit specified
	bool				mSTARTTLS;						// STARTTLS supported
	bool				mAUTH;							// SMTP-AUTH available
	cdstrvect			mAUTHTypes;						// Available AUTH types
	bool				m8BitMIME;						// 8BITMIME supported (RFC 6152)
	bool				mPipelining;					// PIPELINING supported (RFC 2920)
	bool				mEnhancedStatus;				// ENHANCEDSTATUSCODES (RFC 2034)
	bool				mDSN;							// Does DSNs
	CDSN				mMsgDSN;						// DSN requested for message
	bool				mChunking;						// CHUNKING supported (RFC 3030)
	bool				mBinaryMIME;					// BINARYMIME supported (RFC 3030)
	bool				mBurl;							// BURL supported (RFC 4468)
	bool				mBurlImap;						// BURL imap option present
	cdstring			mBurlUrl;						// BURL URL for current transaction (empty = use DATA/BDAT)
	bool				mUseBinaryCTE;					// Use binary CTE for this transaction

	typedef std::pair<CAttachment*, EContentTransferEncoding> CSavedEncoding;
	std::vector<CSavedEncoding>	mSavedEncodings;		// Saved encodings for restore after BDAT
	
	// Async items
	bool				mUseQueue;						// Uses queue for sending
	CMbox*				mQueueMbox;						// Queue mailbox

	// C O N S T R U C T I O N / D E S T R U C T I O N  M E T H O D S

public:
			CSMTPSender(CINETAccount* account);
			~CSMTPSender();

	// Account
	const CINETAccount* GetAccount() const
		{ return mAccount; }
	CINETAccount* GetAccount()
		{ return mAccount; }
	const cdstring& GetAccountName() const
		{ return mAccountName; }
	void SetAccount(CINETAccount* account);

	// O T H E R  M E T H O D S
	bool GetUseQueue() const
		{ return mUseQueue; }
	void SetUseQueue(bool use_queue)
		{ mUseQueue = use_queue; }

	CMbox* GetQueueMbox()
		{ return mQueueMbox; }
	void SetQueueMbox(CMbox* mbox)
		{ mQueueMbox = mbox; }

	virtual bool	IsSecure() const;

	bool	HasBurl() const { return mBurl; }
	bool	HasBurlImap() const { return mBurlImap; }
	bool	HasChunking() const { return mChunking; }

	void	SetBurlUrl(const cdstring& url) { mBurlUrl = url; }
	void	ClearBurlUrl() { mBurlUrl = cdstring::null_str; }

	void SMTPSend(CMessage* theMsg, bool async,
				  CMbox* fcc_mbox = NULL, bool* fcc_done = NULL);	// Send message

	bool SMTPVerifyAddress(const cdstring& addr, cdstring& result);

	bool SMTPStartAsync();
	bool SMTPNextAsync(bool reset = true);
	void SMTPStopAsync();

private:
	CMessage* SMTPAsyncMessage();

	void SMTPBegin();
	void SMTPSendMessage(CMessage* theMsg);
	void SMTPEnd();

	void SMTPSetStatus(const char* rsrc);
	void SMTPHandleGeneralException(CGeneralException& ex);
	void SMTPHandleSMTPException(CSMTPException& ex, bool do_quit);
	void SMTPHandleTCPException(CTCPException& ex);
#if __dest_os == __win32_os
	void SMTPHandleFileException(CFileException* ex);
#endif
	void SMTPHandleUnknownException();
	void SMTPGetErrorContext(cdstring& error) const;		// Get error context string

	void SMTPOpen();
	void SMTPLookup();
	void SMTPQuitClose();
	void SMTPClose();
	bool SMTPTLSClientCertificate();					// Setup TLS certificate
	void SMTPStartTLS();
	bool SMTPDoAuthentication();
	void SMTPAuthenticate();

	// R E C E I V E  D A T A
	void SMTPReceiveData(char code = OK_RESPONSE);
	void SMTPInitCapability();
	void SMTPReceiveCapability(char code = OK_RESPONSE);
	bool SMTPCheckResponse(char code);
	bool SMTPContinuation();
	cdstring GetEnhancedStatusText() const;

	// S E N D  D A T A
	void SMTPSendEHello()
		{ SMTPSendHello(true); }
	void SMTPSendHello(bool extend = false);
	void SMTPSendRset();
	void SMTPSendMail();
	void SMTPSendRcpt(const cdstring& addr);
	void SMTPSendToRcpt();
	void SMTPSendCCRcpt();
	void SMTPSendBCCRcpt();
	void SMTPSendDataCmd();
	void SMTPSendData();
	void SMTPSendBdat();
	void SMTPSendBurl(const cdstring& url, bool last);
	void SMTPSendBurlMessage(const cdstrvect& urls);
	void SMTPSetBinaryEncodings(CAttachment* attach);
	void SMTPRestoreEncodings();
	bool SMTPHasBase64Parts(const CAttachment* attach) const;
	void SMTPSendQuit();

	// U T I L I T I E S
	char* SMTPFilterInLFs(char* txt);

	void SMTPMapErrorStr(const char*& syserr_id, const char*& protobad_id);
};

#endif
