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

// CSCRAMPluginDLL.cp
//
// SCRAM (RFC 5802) base implementation for SCRAM-SHA-1 and SCRAM-SHA-256.

#include "CSCRAMPluginDLL.h"

#include "CStringUtils.h"
#include "kbase64.h"

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define AUTHERROR(xx_msg) do { \
	char err_buf[256]; \
	mState = eError; \
	::snprintf(err_buf, sizeof(err_buf), "SCRAM Plugin Error: %s", xx_msg); \
	LogEntry(err_buf); \
	return eAuthServerError; \
} while (0)

#pragma mark ____________________________CSCRAMPluginDLL

CSCRAMPluginDLL::CSCRAMPluginDLL(const EVP_MD* digest, unsigned int digestLen)
{
	mState = eClientFirst;
	mDigest = digest;
	mDigestLen = digestLen;
	mClientNonce[0] = 0;
	mGS2Header[0] = 0;
	mClientFirstBare[0] = 0;
	mServerFirstMsg[0] = 0;
	mServerSigLen = 0;
}

CSCRAMPluginDLL::~CSCRAMPluginDLL()
{
	OPENSSL_cleanse(mClientNonce, sizeof(mClientNonce));
	OPENSSL_cleanse(mClientFirstBare, sizeof(mClientFirstBare));
	OPENSSL_cleanse(mServerFirstMsg, sizeof(mServerFirstMsg));
	OPENSSL_cleanse(mServerSignature, sizeof(mServerSignature));
}

bool CSCRAMPluginDLL::CanRun(void)
{
	return true;
}

long CSCRAMPluginDLL::ProcessData(SAuthPluginData* info)
{
	switch(mState)
	{
	case eClientFirst:
		return ProcessClientFirst(info);
	case eServerFirst:
		return ProcessServerFirst(info);
	case eServerFinal:
		return ProcessServerFinal(info);
	case eTagLine:
		return ProcessTag(info);
	default:
		return eAuthError;
	}
}

void CSCRAMPluginDLL::GenerateNonce()
{
	unsigned char raw[24];
	RAND_bytes(raw, sizeof(raw));
	kbase64_to64((unsigned char*) mClientNonce, raw, sizeof(raw));
}

void CSCRAMPluginDLL::EscapeUsername(const char* in, char* out, size_t outlen)
{
	char* q = out;
	char* end = out + outlen - 1;
	while (*in && q < end)
	{
		if (*in == '=')
		{
			if (q + 3 > end) break;
			*q++ = '=';
			*q++ = '3';
			*q++ = 'D';
		}
		else if (*in == ',')
		{
			if (q + 3 > end) break;
			*q++ = '=';
			*q++ = '2';
			*q++ = 'C';
		}
		else
		{
			*q++ = *in;
		}
		in++;
	}
	*q = 0;
}

long CSCRAMPluginDLL::ProcessClientFirst(SAuthPluginData* info)
{
	char* p = info->data;

	switch(mServerType)
	{
	case eServerIMAP:
	case eServerPOP3:
	case eServerIMSP:
	case eServerACAP:
		if (*p != '+')
			AUTHERROR("expected '+' continuation");
		break;
	case eServerSMTP:
		if (::strncmp(p, "334", 3) != 0)
			AUTHERROR("expected '334' continuation");
		break;
	case eServerManageSIEVE:
		break;
	default:
		AUTHERROR("unknown server type");
	}

	GenerateNonce();

	char escaped_user[768];
	EscapeUsername(mUserID, escaped_user, sizeof(escaped_user));

	switch(mChannelBind.mMode)
	{
	case 'p':
		::snprintf(mGS2Header, sizeof(mGS2Header), "p=%s,,", mChannelBind.mType);
		break;
	case 'y':
		::strcpy(mGS2Header, "y,,");
		break;
	default:
		::strcpy(mGS2Header, "n,,");
		break;
	}

	::snprintf(mClientFirstBare, sizeof(mClientFirstBare),
		"n=%s,r=%s", escaped_user, mClientNonce);

	char client_first[1024];
	::snprintf(client_first, sizeof(client_first),
		"%s%s", mGS2Header, mClientFirstBare);

	p = info->data;
	*p = 0;

	switch(mServerType)
	{
	case eServerIMAP:
	case eServerPOP3:
	case eServerIMSP:
	case eServerSMTP:
	{
		char* q = p + ::strlen(client_first) + 1;
		kbase64_to64((unsigned char*) q, (unsigned char*) client_first, ::strlen(client_first));
		::memmove(p, q, ::strlen(q) + 1);
		break;
	}
	case eServerACAP:
		::strcpy(p, "\"");
		::strcat(p, client_first);
		::strcat(p, "\"");
		break;
	case eServerManageSIEVE:
	{
		char* q = p + ::strlen(client_first) + 3;
		kbase64_to64((unsigned char*) q, (unsigned char*) client_first, ::strlen(client_first));
		p[0] = '\"';
		::memmove(p + 1, q, ::strlen(q) + 1);
		::strcat(p, "\"");
		break;
	}
	default:;
	}

	mState = eServerFirst;
	return eAuthSendDataToServer;
}

long CSCRAMPluginDLL::ProcessServerFirst(SAuthPluginData* info)
{
	char* p = info->data;

	switch(mServerType)
	{
	case eServerIMAP:
	case eServerPOP3:
	case eServerIMSP:
	case eServerACAP:
		if ((*p != '+') || (p[1] != ' '))
			AUTHERROR("expected '+ ' continuation");
		p += 2;
		break;
	case eServerSMTP:
		if (::strncmp(p, "334 ", 4) != 0)
			AUTHERROR("expected '334 ' continuation");
		p += 4;
		break;
	case eServerManageSIEVE:
		break;
	default:
		AUTHERROR("unknown server type");
	}

	switch(mServerType)
	{
	case eServerIMAP:
	case eServerPOP3:
	case eServerIMSP:
	case eServerSMTP:
	{
		int len = kbase64_from64(info->data, p);
		info->data[len] = 0;
		break;
	}
	case eServerACAP:
	case eServerManageSIEVE:
		if (*p == '\"')
		{
			char* q = ::strgetquotestr(&p);
			::strcpy(info->data, q);
		}
		else if (*p == '{')
		{
			mState = eServerFirst;
			return eAuthMoreData;
		}
		else
			AUTHERROR("illegal server data: not a string");
		break;
	default:
		AUTHERROR("unknown server type");
	}

	if (mServerType == eServerManageSIEVE)
	{
		p = info->data;
		int len = kbase64_from64(info->data, p);
		info->data[len] = 0;
	}

	::strncpy(mServerFirstMsg, info->data, sizeof(mServerFirstMsg) - 1);
	mServerFirstMsg[sizeof(mServerFirstMsg) - 1] = 0;

	p = info->data;

	// Parse server-first-message: [m=,]r=<nonce>,s=<salt>,i=<iter>[,...]
	char* combined_nonce = NULL;
	char* salt_b64 = NULL;
	int iter_count = 0;

	while (*p)
	{
		if (*p == 'm' && *(p + 1) == '=')
			AUTHERROR("mandatory extension not supported");

		if (*p == 'r' && *(p + 1) == '=')
		{
			p += 2;
			combined_nonce = p;
			while (*p && *p != ',') p++;
			if (*p == ',') *p++ = 0;
		}
		else if (*p == 's' && *(p + 1) == '=')
		{
			p += 2;
			salt_b64 = p;
			while (*p && *p != ',') p++;
			if (*p == ',') *p++ = 0;
		}
		else if (*p == 'i' && *(p + 1) == '=')
		{
			p += 2;
			iter_count = ::strtol(p, &p, 10);
			if (*p == ',') p++;
		}
		else
		{
			while (*p && *p != ',') p++;
			if (*p == ',') p++;
		}
	}

	if (!combined_nonce || !salt_b64 || iter_count <= 0)
		AUTHERROR("missing required attribute in server-first-message");

	size_t cnonce_len = ::strlen(mClientNonce);
	if (::strncmp(combined_nonce, mClientNonce, cnonce_len) != 0)
		AUTHERROR("server nonce does not start with client nonce");

	if (::strlen(combined_nonce) <= cnonce_len)
		AUTHERROR("server did not add to nonce");

	if (iter_count > 1000000)
		AUTHERROR("iteration count too high");

	unsigned char salt[256];
	int salt_len = kbase64_from64((char*) salt, salt_b64);
	if (salt_len <= 0)
		AUTHERROR("invalid salt encoding");

	// SaltedPassword = Hi(password, salt, i) = PBKDF2
	unsigned char salted_password[EVP_MAX_MD_SIZE];
	PKCS5_PBKDF2_HMAC(mPassword, ::strlen(mPassword),
		salt, salt_len, iter_count,
		mDigest, mDigestLen, salted_password);

	// ClientKey = HMAC(SaltedPassword, "Client Key")
	unsigned char client_key[EVP_MAX_MD_SIZE];
	unsigned int client_key_len = 0;
	HMAC(mDigest, salted_password, mDigestLen,
		(const unsigned char*) "Client Key", 10,
		client_key, &client_key_len);

	// StoredKey = H(ClientKey)
	unsigned char stored_key[EVP_MAX_MD_SIZE];
	unsigned int stored_key_len = 0;
	EVP_Digest(client_key, client_key_len, stored_key, &stored_key_len, mDigest, NULL);

	// Build cbind-input and c= attribute
	char cbind_input[512];
	size_t cbind_len = ::strlen(mGS2Header);
	::memcpy(cbind_input, mGS2Header, cbind_len);
	if (mChannelBind.mMode == 'p' && mChannelBind.mLength > 0)
	{
		::memcpy(cbind_input + cbind_len, mChannelBind.mData, mChannelBind.mLength);
		cbind_len += mChannelBind.mLength;
	}

	char cbind_b64[700];
	kbase64_to64((unsigned char*) cbind_b64, (unsigned char*) cbind_input, cbind_len);

	// client-final-message-without-proof
	char cfm_without_proof[1024];
	::snprintf(cfm_without_proof, sizeof(cfm_without_proof),
		"c=%s,r=%s", cbind_b64, combined_nonce);

	// AuthMessage = client-first-message-bare + "," + server-first-message + "," + client-final-message-without-proof
	char auth_message[3072];
	::snprintf(auth_message, sizeof(auth_message),
		"%s,%s,%s", mClientFirstBare, mServerFirstMsg, cfm_without_proof);

	// ClientSignature = HMAC(StoredKey, AuthMessage)
	unsigned char client_sig[EVP_MAX_MD_SIZE];
	unsigned int client_sig_len = 0;
	HMAC(mDigest, stored_key, stored_key_len,
		(const unsigned char*) auth_message, ::strlen(auth_message),
		client_sig, &client_sig_len);

	// ClientProof = ClientKey XOR ClientSignature
	unsigned char client_proof[EVP_MAX_MD_SIZE];
	for (unsigned int j = 0; j < client_key_len; j++)
		client_proof[j] = client_key[j] ^ client_sig[j];

	// ServerKey = HMAC(SaltedPassword, "Server Key")
	unsigned char server_key[EVP_MAX_MD_SIZE];
	unsigned int server_key_len = 0;
	HMAC(mDigest, salted_password, mDigestLen,
		(const unsigned char*) "Server Key", 10,
		server_key, &server_key_len);

	// ServerSignature = HMAC(ServerKey, AuthMessage)
	HMAC(mDigest, server_key, server_key_len,
		(const unsigned char*) auth_message, ::strlen(auth_message),
		mServerSignature, &mServerSigLen);

	// Wipe sensitive key material
	OPENSSL_cleanse(salted_password, sizeof(salted_password));
	OPENSSL_cleanse(client_key, sizeof(client_key));
	OPENSSL_cleanse(server_key, sizeof(server_key));
	OPENSSL_cleanse(stored_key, sizeof(stored_key));
	OPENSSL_cleanse(client_sig, sizeof(client_sig));

	// Base64-encode ClientProof
	char proof_b64[256];
	kbase64_to64((unsigned char*) proof_b64, client_proof, client_key_len);
	OPENSSL_cleanse(client_proof, sizeof(client_proof));

	// Build client-final-message
	char client_final[2048];
	::snprintf(client_final, sizeof(client_final),
		"%s,p=%s", cfm_without_proof, proof_b64);

	// Encode for wire
	p = info->data;
	*p = 0;

	switch(mServerType)
	{
	case eServerIMAP:
	case eServerPOP3:
	case eServerIMSP:
	case eServerSMTP:
	{
		char* q = p + ::strlen(client_final) + 1;
		kbase64_to64((unsigned char*) q, (unsigned char*) client_final, ::strlen(client_final));
		::memmove(p, q, ::strlen(q) + 1);
		break;
	}
	case eServerACAP:
		::strcpy(p, "\"");
		::strcat(p, client_final);
		::strcat(p, "\"");
		break;
	case eServerManageSIEVE:
	{
		char* q = p + ::strlen(client_final) + 3;
		kbase64_to64((unsigned char*) q, (unsigned char*) client_final, ::strlen(client_final));
		p[0] = '\"';
		::memmove(p + 1, q, ::strlen(q) + 1);
		::strcat(p, "\"");
		break;
	}
	default:;
	}

	mState = eServerFinal;
	return eAuthSendDataToServer;
}

long CSCRAMPluginDLL::ProcessServerFinal(SAuthPluginData* info)
{
	char* p = info->data;
	bool is_tagged = false;

	switch(mServerType)
	{
	case eServerIMAP:
	case eServerIMSP:
	case eServerACAP:
		if (*p == '+' && p[1] == ' ')
		{
			p += 2;
		}
		else if (*p != '*' && *p != '+')
		{
			// Tagged response — server-final may be embedded
			is_tagged = true;
			// Punt over tag
			while (*p && *p != ' ') p++;
			while (*p == ' ') p++;
			if (::strncmpnocase(p, "OK", 2) == 0)
			{
				p += 2;
				while (*p == ' ') p++;
				if (*p == 0)
					AUTHERROR("server omitted verification signature");
			}
			else
			{
				mState = eError;
				return eAuthServerError;
			}
		}
		else
		{
			AUTHERROR("unexpected response in server-final");
		}
		break;
	case eServerPOP3:
		if (*p == '+' && p[1] == ' ')
		{
			p += 2;
		}
		else if (::strncmpnocase(p, "+OK", 3) == 0)
		{
			is_tagged = true;
			p += 3;
			while (*p == ' ') p++;
			if (*p == 0)
				AUTHERROR("server omitted verification signature");
		}
		else
		{
			mState = eError;
			return eAuthServerError;
		}
		break;
	case eServerSMTP:
		if (::strncmp(p, "334 ", 4) == 0)
		{
			p += 4;
		}
		else if (::strncmp(p, "235", 3) == 0)
		{
			is_tagged = true;
			p += 3;
			while (*p == ' ') p++;
			if (*p == 0)
				AUTHERROR("server omitted verification signature");
		}
		else
		{
			mState = eError;
			return eAuthServerError;
		}
		break;
	case eServerManageSIEVE:
		if (::strncmpnocase(p, "OK", 2) == 0)
		{
			mState = eDone;
			return eAuthDone;
		}
		break;
	default:
		AUTHERROR("unknown server type");
	}

	// Decode the server-final-message
	char decoded[1024];
	switch(mServerType)
	{
	case eServerIMAP:
	case eServerPOP3:
	case eServerIMSP:
	case eServerSMTP:
	{
		int len = kbase64_from64(decoded, p);
		decoded[len] = 0;
		break;
	}
	default:
		::strncpy(decoded, p, sizeof(decoded) - 1);
		decoded[sizeof(decoded) - 1] = 0;
		break;
	}

	p = decoded;

	// Check for error
	if (*p == 'e' && *(p + 1) == '=')
	{
		char errmsg[256];
		::snprintf(errmsg, sizeof(errmsg), "server error: %s", p + 2);
		mState = eError;
		LogEntry(errmsg);
		return eAuthServerError;
	}

	// Parse v=<base64 server signature>
	if (*p != 'v' || *(p + 1) != '=')
		AUTHERROR("missing server signature in server-final-message");
	p += 2;

	unsigned char recv_sig[EVP_MAX_MD_SIZE];
	int recv_sig_len = kbase64_from64((char*) recv_sig, p);
	if (recv_sig_len <= 0)
		AUTHERROR("invalid server signature encoding");

	if ((unsigned int) recv_sig_len != mServerSigLen ||
		CRYPTO_memcmp(recv_sig, mServerSignature, mServerSigLen) != 0)
		AUTHERROR("server signature verification failed");

	OPENSSL_cleanse(mServerSignature, sizeof(mServerSignature));
	mServerSigLen = 0;

	if (is_tagged)
	{
		mState = eDone;
		return eAuthDone;
	}

	// Send empty response to get tagged OK
	p = info->data;
	*p = 0;
	mState = eTagLine;
	return eAuthSendDataToServer;
}

long CSCRAMPluginDLL::ProcessTag(SAuthPluginData* info)
{
	const char* p = info->data;

	switch(mServerType)
	{
	case eServerIMAP:
	case eServerIMSP:
	case eServerACAP:
		if ((*p == '*') || (*p == '+'))
		{
			mState = eError;
			return eAuthError;
		}
		while(*p && (*p != ' ')) p++;
		while(*p == ' ') p++;
		if (::strncmpnocase(p, "OK", 2) == 0)
		{
			mState = eDone;
			return eAuthDone;
		}
		else
		{
			mState = eError;
			return eAuthServerError;
		}
	case eServerPOP3:
		if (::strncmpnocase(p, "+OK", 3) == 0)
		{
			mState = eDone;
			return eAuthDone;
		}
		else
		{
			mState = eError;
			return eAuthServerError;
		}
	case eServerSMTP:
		if (::strncmp(p, "235", 3) == 0)
		{
			mState = eDone;
			return eAuthDone;
		}
		else
		{
			mState = eError;
			return eAuthServerError;
		}
	case eServerManageSIEVE:
		if (::strncmpnocase(p, "OK", 2) == 0)
		{
			mState = eDone;
			return eAuthDone;
		}
		else
		{
			mState = eError;
			return eAuthServerError;
		}
	default:;
	}

	mState = eError;
	return eAuthServerError;
}
