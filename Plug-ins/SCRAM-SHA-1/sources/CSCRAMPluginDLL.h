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

// CSCRAMPluginDLL.h
//
// SCRAM (RFC 5802) base class for SCRAM-SHA-1 and SCRAM-SHA-256 plugins.

#ifndef __SCRAM_PLUGIN_MULBERRY__
#define __SCRAM_PLUGIN_MULBERRY__

#include "CAuthPluginDLL.h"

#include <openssl/evp.h>

class CSCRAMPluginDLL : public CAuthPluginDLL
{
public:

	CSCRAMPluginDLL(const EVP_MD* digest, unsigned int digestLen);
	virtual ~CSCRAMPluginDLL();

	// Entry codes
	virtual bool	CanRun(void);
	virtual long	ProcessData(SAuthPluginData* info);

protected:
	enum ESCRAMPluginState
	{
		eError = 0,
		eClientFirst,
		eServerFirst,
		eServerFinal,
		eTagLine,
		eDone
	};

	ESCRAMPluginState mState;
	const EVP_MD* mDigest;
	unsigned int mDigestLen;

	char mClientNonce[48];
	char mGS2Header[80];
	char mClientFirstBare[1024];
	char mServerFirstMsg[1024];
	unsigned char mServerSignature[EVP_MAX_MD_SIZE];
	unsigned int mServerSigLen;

	long ProcessClientFirst(SAuthPluginData* info);
	long ProcessServerFirst(SAuthPluginData* info);
	long ProcessServerFinal(SAuthPluginData* info);
	long ProcessTag(SAuthPluginData* info);

	bool GenerateNonce();
	void EscapeUsername(const char* in, char* out, size_t outlen);
};

#endif
