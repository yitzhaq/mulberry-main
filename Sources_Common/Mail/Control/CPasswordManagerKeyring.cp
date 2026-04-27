/*
    Copyright (c) 2009 Cyrus Daboo. All rights reserved.

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

// CPasswordManagerKeyring.cp

#include "CPasswordManagerKeyring.h"

#include "CConnectionManager.h"
#include "CINETAccount.h"
#include "CLocalCommon.h"
#include "base64.h"

#include <fstream>
#include <memory>
#include <sstream>
#include <cstring>
#include <sodium.h>

#if __dest_os == __win32_os
#include <winsock.h>
#else
#include <arpa/inet.h>
#include <sys/stat.h>
#endif

// V1 legacy support (MD5+RC4) — kept for migration only
#include <openssl/rc4.h>
#include <openssl/md5.h>

#if __dest_os == __win32_os
const char* cKeyRing = "keyring";
#else
const char* cKeyRing = ".keyring";
#endif

static const char* cKeyRingV2Header = "MULBERRY-KEYRING-V2\n";
static const size_t cKeyRingV2HeaderLen = 20;

CPasswordManagerKeyring::CPasswordManagerKeyring()
{
	mKeyringPath = CConnectionManager::sConnectionManager.GetUserCWD();
	::addtopath(mKeyringPath, cKeyRing);
	mActive = false;
}

CPasswordManagerKeyring::~CPasswordManagerKeyring()
{
}

void CPasswordManagerKeyring::MakePasswordManagerKeyring()
{
	if (sPasswordManager == NULL)
		sPasswordManager = new CPasswordManagerKeyring();
}

bool CPasswordManagerKeyring::KeyringExists() const
{
	return ::fileexists(mKeyringPath);
}

cdstring CPasswordManagerKeyring::GetAccountURL(const CINETAccount* acct) const
{
	cdstring server = acct->GetServerIP();

	cdstring user = acct->GetName();
	if (acct->GetAuthenticator().RequiresUserPswd())
		user = acct->GetAuthenticatorUserPswd()->GetUID();

	cdstring scheme;
	switch(acct->GetServerType())
	{
	case CINETAccount::eIMAP:
		if ((acct->GetTLSType() == CINETAccount::eSSL) ||
			(acct->GetTLSType() == CINETAccount::eSSLv3))
			scheme = "imaps:";
		else
			scheme = "imap:";
		break;
	case CINETAccount::ePOP3:
		if ((acct->GetTLSType() == CINETAccount::eSSL) ||
			(acct->GetTLSType() == CINETAccount::eSSLv3))
			scheme = "pop3s:";
		else
			scheme = "pop3:";
		break;
	case CINETAccount::eSMTP:
		if ((acct->GetTLSType() == CINETAccount::eSSL) ||
			(acct->GetTLSType() == CINETAccount::eSSLv3))
			scheme = "smtps:";
		else
			scheme = "smtp:";
		break;
	case CINETAccount::eIMSP:
		if ((acct->GetTLSType() == CINETAccount::eSSL) ||
			(acct->GetTLSType() == CINETAccount::eSSLv3))
			scheme = "imsps:";
		else
			scheme = "imsp:";
		break;
	case CINETAccount::eACAP:
		if ((acct->GetTLSType() == CINETAccount::eSSL) ||
			(acct->GetTLSType() == CINETAccount::eSSLv3))
			scheme = "acaps:";
		else
			scheme = "acap:";
		break;
	case CINETAccount::eLDAP:
		if ((acct->GetTLSType() == CINETAccount::eSSL) ||
			(acct->GetTLSType() == CINETAccount::eSSLv3))
			scheme = "ldaps:";
		else
			scheme = "ldap:";
		break;
	case CINETAccount::eManageSIEVE:
		if ((acct->GetTLSType() == CINETAccount::eSSL) ||
			(acct->GetTLSType() == CINETAccount::eSSLv3))
			scheme = "managesieves:";
		else
			scheme = "managesieve:";
		break;
	case CINETAccount::eWebDAVPrefs:
	case CINETAccount::eHTTPCalendar:
	case CINETAccount::eWebDAVCalendar:
	case CINETAccount::eCalDAVCalendar:
	case CINETAccount::eCardDAVAdbk:
		if ((acct->GetTLSType() == CINETAccount::eSSL) ||
			(acct->GetTLSType() == CINETAccount::eSSLv3))
			scheme = "https://";
		else
			scheme = "http://";
		break;
	default:
		scheme = "unknown:";
	}

	return scheme + user + "@" + server;
}

// Parse plaintext key-value pairs into map
static void ParseMapFromPlaintext(const char* plaintext, cdstrmap& results)
{
	std::istringstream sin(plaintext);
	cdstrpair kv;
	bool key_or_value = true;
	while(sin)
	{
		getline(sin, key_or_value ? kv.first : kv.second);
		key_or_value = !key_or_value;
		if (key_or_value)
			if (!kv.first.empty() && !kv.second.empty())
				results[kv.first] = kv.second;
	}
}

// V1 legacy decrypt (MD5+RC4) — for migration only
static bool DecryptV1(const cdstring& data, const cdstring& passphrase, cdstrmap& results)
{
	if (data.length() == 0)
		return false;

	size_t encrypted_len = 0;
	std::unique_ptr<unsigned char> encrypted(::base64_decode(data.c_str(), encrypted_len));
	if (!encrypted || encrypted_len == 0)
		return false;

	unsigned char digest[MD5_DIGEST_LENGTH];
	RC4_KEY rc4key;
	std::unique_ptr<unsigned char[]> decrypted(new unsigned char[encrypted_len + 1]);

	MD5(reinterpret_cast<const unsigned char*>(passphrase.c_str()), passphrase.length(), digest);
	RC4_set_key(&rc4key, MD5_DIGEST_LENGTH, digest);
	RC4(&rc4key, encrypted_len, encrypted.get(), decrypted.get());
	decrypted.get()[encrypted_len] = 0;

	sodium_memzero(digest, sizeof(digest));

	ParseMapFromPlaintext(reinterpret_cast<const char*>(decrypted.get()), results);
	sodium_memzero(decrypted.get(), encrypted_len + 1);

	return true;
}

cdstrmap CPasswordManagerKeyring::ReadEncryptedMap() const
{
	cdstrmap results;

	// Read entire file
	std::ifstream fin(mKeyringPath.c_str());
	if (!fin.is_open())
		return results;

	std::string file_content((std::istreambuf_iterator<char>(fin)),
	                          std::istreambuf_iterator<char>());
	fin.close();

	if (file_content.empty())
		return results;

	// Check for V2 header
	if (file_content.length() > cKeyRingV2HeaderLen &&
		file_content.substr(0, cKeyRingV2HeaderLen) == cKeyRingV2Header)
	{
		// V2 format: Argon2id + XChaCha20-Poly1305
		std::string b64data = file_content.substr(cKeyRingV2HeaderLen);

		size_t blob_len = 0;
		std::unique_ptr<unsigned char> blob(::base64_decode(b64data.c_str(), blob_len));
		if (!blob)
			return results;

		// Minimum blob size: salt + opslimit + memlimit + nonce + MAC
		const size_t min_blob = crypto_pwhash_SALTBYTES + 4 + 4 +
		                        crypto_secretbox_NONCEBYTES +
		                        crypto_secretbox_MACBYTES;
		if (blob_len < min_blob)
			return results;

		const unsigned char* p = blob.get();

		// Extract salt
		unsigned char salt[crypto_pwhash_SALTBYTES];
		::memcpy(salt, p, crypto_pwhash_SALTBYTES);
		p += crypto_pwhash_SALTBYTES;

		// Extract KDF parameters (network byte order)
		uint32_t opslimit_n, memlimit_n;
		::memcpy(&opslimit_n, p, 4); p += 4;
		::memcpy(&memlimit_n, p, 4); p += 4;
		unsigned long long opslimit = ntohl(opslimit_n);
		size_t memlimit = (size_t)ntohl(memlimit_n) * 1024;

		// Extract nonce
		unsigned char nonce[crypto_secretbox_NONCEBYTES];
		::memcpy(nonce, p, crypto_secretbox_NONCEBYTES);
		p += crypto_secretbox_NONCEBYTES;

		// Remaining is ciphertext + MAC
		size_t ciphertext_len = blob_len - (p - blob.get());
		if (ciphertext_len < crypto_secretbox_MACBYTES)
			return results;

		// Derive key from passphrase
		unsigned char key[crypto_secretbox_KEYBYTES];
		if (crypto_pwhash(key, sizeof key,
		                  mPassphrase.c_str(), mPassphrase.length(),
		                  salt, opslimit, memlimit,
		                  crypto_pwhash_ALG_ARGON2ID13) != 0)
		{
			sodium_memzero(key, sizeof key);
			return results;
		}

		// Decrypt
		size_t plaintext_len = ciphertext_len - crypto_secretbox_MACBYTES;
		std::unique_ptr<unsigned char[]> plaintext(new unsigned char[plaintext_len + 1]);

		if (crypto_secretbox_open_easy(plaintext.get(), p, ciphertext_len,
		                               nonce, key) != 0)
		{
			// MAC verification failed — wrong passphrase
			sodium_memzero(key, sizeof key);
			return results;
		}
		plaintext.get()[plaintext_len] = 0;

		sodium_memzero(key, sizeof key);

		ParseMapFromPlaintext(reinterpret_cast<const char*>(plaintext.get()), results);
		sodium_memzero(plaintext.get(), plaintext_len + 1);
	}
	else
	{
		// V1 format: MD5+RC4 — migrate to V2
		cdstring data(file_content.c_str());
		if (DecryptV1(data, mPassphrase, results))
		{
			// Backup old file before overwriting with V2
			cdstring backup = mKeyringPath + ".v1.bak";
			if (::rename_utf8(mKeyringPath, backup) != 0)
				return results;

			// Re-encrypt with V2
			WriteEncryptedMap(results);
		}
	}

	return results;
}

void CPasswordManagerKeyring::WriteEncryptedMap(const cdstrmap& pswds) const
{
	// Serialize map to plaintext
	std::ostringstream ostr;
	for(cdstrmap::const_iterator iter = pswds.begin(); iter != pswds.end(); iter++)
	{
		ostr << (*iter).first << std::endl << (*iter).second << std::endl;
	}
	std::string data = ostr.str();

	// Generate random salt
	unsigned char salt[crypto_pwhash_SALTBYTES];
	randombytes_buf(salt, sizeof salt);

	// Derive key from passphrase using Argon2id
	unsigned char key[crypto_secretbox_KEYBYTES];
	unsigned long long opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
	size_t memlimit = crypto_pwhash_MEMLIMIT_MODERATE;

	if (crypto_pwhash(key, sizeof key,
	                  mPassphrase.c_str(), mPassphrase.length(),
	                  salt, opslimit, memlimit,
	                  crypto_pwhash_ALG_ARGON2ID13) != 0)
	{
		sodium_memzero(key, sizeof key);
		return;
	}

	// Generate random nonce
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, sizeof nonce);

	// Encrypt
	size_t ciphertext_len = data.length() + crypto_secretbox_MACBYTES;
	std::unique_ptr<unsigned char[]> ciphertext(new unsigned char[ciphertext_len]);

	crypto_secretbox_easy(ciphertext.get(),
	                      reinterpret_cast<const unsigned char*>(data.c_str()),
	                      data.length(), nonce, key);

	sodium_memzero(key, sizeof key);

	// Build blob: salt + opslimit(net) + memlimit_kb(net) + nonce + ciphertext
	uint32_t opslimit_n = htonl((uint32_t)opslimit);
	uint32_t memlimit_n = htonl((uint32_t)(memlimit / 1024));

	size_t blob_len = sizeof(salt) + 4 + 4 + sizeof(nonce) + ciphertext_len;
	std::unique_ptr<unsigned char[]> blob(new unsigned char[blob_len]);
	unsigned char* p = blob.get();

	::memcpy(p, salt, sizeof salt); p += sizeof salt;
	::memcpy(p, &opslimit_n, 4); p += 4;
	::memcpy(p, &memlimit_n, 4); p += 4;
	::memcpy(p, nonce, sizeof nonce); p += sizeof nonce;
	::memcpy(p, ciphertext.get(), ciphertext_len);

	// Base64 encode
	std::unique_ptr<char> b64(::base64_encode(blob.get(), blob_len));

	// Write V2 file with restrictive permissions
#if __dest_os != __win32_os
	mode_t old_umask = ::umask(077);
#endif
	std::ofstream fout(mKeyringPath.c_str());
	fout << cKeyRingV2Header << b64.get();
	fout.close();
#if __dest_os != __win32_os
	::umask(old_umask);
#endif
}

bool CPasswordManagerKeyring::GetPassword(const CINETAccount* acct, cdstring& pswd)
{
	if (!mActive)
		return false;

	cdstring accturl = GetAccountURL(acct);

	cdstrmap pswdmap = ReadEncryptedMap();
	if (pswdmap.count(accturl))
	{
		pswd = pswdmap[accturl];
		return true;
	}
	else
		return false;
}

void CPasswordManagerKeyring::AddPassword(const CINETAccount* acct, const cdstring& pswd)
{
	if (!mActive)
		return;

	cdstring accturl = GetAccountURL(acct);

	cdstrmap pswdmap = ReadEncryptedMap();
	pswdmap[accturl] = pswd;
	WriteEncryptedMap(pswdmap);
}
