/*
    Copyright (c) 2007-2009 Cyrus Daboo. All rights reserved.
    
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

// CGPGPluginDLL.cpp
//
// Copyright 2006, Cyrus Daboo.  All Rights Reserved.
//
// Created: 04-May-1998
// Author: Cyrus Daboo
// Platforms: Mac OS, Win32
//
// Description:
// This class implements a PGP security DLL based plug-in for use in Mulberry.
//
// History:
// 04-May-1998: Created initial header and implementation.
//

#include <stdio.h>
#include <stdlib.h>

#include "CGPGPluginDLL.h"
#include "CPluginInfo.h"
#include "CStringUtils.h"
#if __dest_os == __win32_os
#include "CUnicodeStdLib.h"
#endif

#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <memory>

#if __dest_os == __win32_os
#include <fcntl.h>
#include <sys/stat.h>
typedef size_t ssize_t;
#endif
#if __dest_os == __linux_os || __dest_os == __mac_os_x
#include <fcntl.h>
#define O_BINARY 0
#include <sys/stat.h>
#define bzero(a,b) memset(a,0,b)
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#endif

//#define DEBUG_OUTPUT

#pragma mark ____________________________consts

const char* cPluginName = "GPG Plugin";
const CPluginDLL::EPluginType cPluginType = CPluginDLL::ePluginSecurity;
const char* cPluginDescription = "GNUpg Security plugin for Mulberry." COPYRIGHT;
const char* cProcessedBy = "processed by Mulberry GPG Plugin";
const char* cProcessVersion = "Mulberry GPG Plugin v2.0";

const char* cGPG = "gpg";
const char* cGNUPGStatus = "[GNUPG:] ";

// Passphrase status
const char* cGOOD_PASSPHRASE = "GOOD_PASSPHRASE";
const char* cBAD_PASSPHRASE = "BAD_PASSPHRASE ";

// Signature verification status
const char* cNEWSIG = "NEWSIG";
const char* cGOODSIG = "GOODSIG ";
const char* cBADSIG = "BADSIG ";
const char* cERRSIG = "ERRSIG ";
const char* cEXPSIG = "EXPSIG ";
const char* cEXPKEYSIG = "EXPKEYSIG ";
const char* cREVKEYSIG = "REVKEYSIG ";
const char* cVALIDSIG = "VALIDSIG ";
const char* cNOPUBKEY = "NO_PUBKEY ";

// Trust status
const char* cTRUST_UNDEFINED = "TRUST_UNDEFINED";
const char* cTRUST_NEVER = "TRUST_NEVER";
const char* cTRUST_MARGINAL = "TRUST_MARGINAL";
const char* cTRUST_FULLY = "TRUST_FULLY";
const char* cTRUST_ULTIMATE = "TRUST_ULTIMATE";

// Decryption status
const char* cDECRYPTION_OKAY = "DECRYPTION_OKAY";
const char* cDECRYPTION_FAILED = "DECRYPTION_FAILED";
const char* cDECRYPTION_INFO = "DECRYPTION_INFO ";

// Signing status
const char* cSIG_CREATED = "SIG_CREATED ";
const char* cBEGIN_SIGNING = "BEGIN_SIGNING";

// Key status
const char* cNO_SECKEY = "NO_SECKEY ";
const char* cKEYEXPIRED = "KEYEXPIRED ";
const char* cKEYREVOKED = "KEYREVOKED";

// Recipient errors
const char* cINV_RECP = "INV_RECP ";
const char* cNO_RECP = "NO_RECP";

// General errors
const char* cERROR = "ERROR ";
const char* cFAILURE = "FAILURE ";
const char* cNODATA = "NODATA ";

#pragma mark ____________________________CGPGPluginDLL

class StRemoveFile
{
public:
	StRemoveFile()
		{ }
	StRemoveFile(const char* filename)
		{ mFileName = filename; }
	~StRemoveFile()
		{ if (!mFileName.empty()) ::remove(mFileName); }
	
	void set(const char* filename)
		{ mFileName = filename; }
private:
	cdstring mFileName;
};

#if __dest_os == __mac_os || __dest_os == __mac_os_x
class StRemoveFileSpec
{
public:
	StRemoveFileSpec()
		{ *mFileSpec.name = 0; }
	StRemoveFileSpec(FSSpec* filespec)
		{ mFileSpec = *filespec; }
	~StRemoveFileSpec()
		{ if (*mFileSpec.name) ::FSpDelete(&mFileSpec); }

	void set(FSSpec* filespec)
		{ mFileSpec = *filespec; }
private:
	FSSpec mFileSpec;
};
#else
class StRemoveFileSpec
{
public:
	StRemoveFileSpec()
		{ }
	StRemoveFileSpec(const char* filename)
		{ mFileName = filename; }
	~StRemoveFileSpec()
		{ if (!mFileName.empty()) ::remove(mFileName); }
	
	void set(const char* filename)
		{ mFileName = filename; }
private:
	cdstring mFileName;
};
#endif

class StClearPassphrase
{
public:
	StClearPassphrase(char* buf, size_t len)
		: mBuf(buf), mLen(len) {}
	~StClearPassphrase()
	{
		if (mBuf)
		{
#if __dest_os == __win32_os
			SecureZeroMemory(mBuf, mLen);
#else
			explicit_bzero(mBuf, mLen);
#endif
		}
	}
private:
	char* mBuf;
	size_t mLen;
};

#if __dest_os == __win32_os
static const char *gpg2ExeName = "\\gpg2.exe";
#endif

// Constructor
CGPGPluginDLL::CGPGPluginDLL()
{
	mData = new SData;
	mData->mSignedByList = NULL;
	mData->mEncryptedToList = NULL;
	mData->mErrno = eSecurity_NoErr;
	mData->mDidSig = false;

	mData->mHashAlgorithm = 0;
	mData->mCipherAlgorithm = 0;
	mData->mSignatureExpiry = 0;
	mData->mTrustLevel = 0;
	mData->mExpiredSignature = false;
	mData->mExpiredKey = false;
	mData->mRevokedKey = false;
	mData->mDecryptionOK = false;
	mData->mWeakHashDetected = false;
	mData->mSigCreatedHashAlgo = 0;

#if __dest_os == __win32_os
	// Try to get exe path from registry
	mExePath = cdstring::null_str;

	// Open the key for the full path
	HKEY key;
	if (::RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\GNU\\GnuPG", 0, KEY_READ, &key) == ERROR_SUCCESS
		|| ::RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\GNU\\GnuPG", 0, KEY_READ, &key) == ERROR_SUCCESS
#if defined(_WIN64)
		|| ::RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Wow6432Node\\GNU\\GnuPG", 0, KEY_READ, &key) == ERROR_SUCCESS // GPG is only in 32 bit version available
		|| ::RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\GNU\\GnuPG", 0, KEY_READ, &key) == ERROR_SUCCESS
#endif
		)
	{
		// Determine the space required
		DWORD bufsize = 0;
		if (::RegQueryValueExA(key, "gpgProgram", 0, NULL, NULL, &bufsize) == ERROR_SUCCESS)
		{
			// Reserve the space
			mExePath.reserve(bufsize);

			// Get the key's named value
			::RegQueryValueExA(key, "gpgProgram", 0, NULL, reinterpret_cast<unsigned char*>(mExePath.c_str_mod()), &bufsize);
		}
		else if (::RegQueryValueExA(key, "Install Directory", 0, NULL, NULL, &bufsize) == ERROR_SUCCESS)
		{
			// Reserve the space
			mExePath.reserve(bufsize+strlen(gpg2ExeName)+1);
		
			// Get the key's named value
			::RegQueryValueExA(key, "Install Directory", 0, NULL, reinterpret_cast<unsigned char*>(mExePath.c_str_mod()), &bufsize);
			mExePath += gpg2ExeName;
		}
		// Close the key
		::RegCloseKey(key);
	}
	
	// If no registry entry, default to C drive location
	if (mExePath.empty())
		mExePath = "C:\\gnupg\\gpg.exe";
#endif
}

// Destructor
CGPGPluginDLL::~CGPGPluginDLL()
{
	if (mData->mSignedByList)
		cdstring::FreeArray(mData->mSignedByList);
	if (mData->mEncryptedToList)
		cdstring::FreeArray(mData->mEncryptedToList);

	delete mData;
}

// Initialise plug-in
void CGPGPluginDLL::Initialise(void)
{
	// Do default
	CSecurityPluginDLL::Initialise();
}

// Does plug-in need to be registered
bool CGPGPluginDLL::UseRegistration(unsigned long* key)
{
	if (key)
		*key = ('Mlby' | 'PGP5');
	return false;
}

// Can plug-in run as demo
bool CGPGPluginDLL::CanDemo(void)
{
	// Must be registered
	return false;
}

#define DATE_PROTECTION		0

#define	COPYP_MAX_YEAR	2000
#define COPYP_MAX_MONTH	3

// Test for run ability
bool CGPGPluginDLL::CanRun(void)
{
#if DATE_PROTECTION
	time_t systime = ::time(nil);
	struct tm* currtime = ::localtime(&systime);

	if ((currtime->tm_year + 1900 > COPYP_MAX_YEAR) ||
		((currtime->tm_year + 1900 == COPYP_MAX_YEAR) && (currtime->tm_mon + 1 > COPYP_MAX_MONTH)))
		return false;
#endif

	// Check for gpg as an executable
#if __dest_os == __win32_os
	// Check for executable
	if (::access_utf8(mExePath.c_str(), X_OK) == 0)
		return true;
	else
		return false;
#else
	const char* path = ::getenv("PATH");
	if (!path)
		return false;

	// Tokenise PATH
	cdstring cpath(path);
#if __dest_os == __mac_os_x
	cpath += ":/usr/local/bin";
#endif	
	const char* p = ::strtok(cpath.c_str_mod(), ":");
	while(p)
	{
		// Make full path
		cdstring npath(p);
		if (npath.empty() || npath.c_str()[npath.length() - 1] != '/')
			npath += "/";
		npath += cGPG;

		// Check for executable
		if (::access(npath.c_str(), X_OK) == 0)
			return true;

		// Next token
		p = ::strtok(NULL, ":");
	}

	return false;
#endif
}

// Returns the name of the plug-in
const char* CGPGPluginDLL::GetName(void) const
{
	return cPluginName;
}

// Returns the version number of the plug-in
long CGPGPluginDLL::GetVersion(void) const
{
	return cPluginVersion;
}

// Returns the type of the plug-in
CPluginDLL::EPluginType CGPGPluginDLL::GetType(void) const
{
	return cPluginType;
}

// Returns manufacturer of plug-in
const char* CGPGPluginDLL::GetManufacturer(void) const
{
	return cPluginManufacturer;
}

// Returns description of plug-in
const char* CGPGPluginDLL::GetDescription(void) const
{
	return cPluginDescription;
}

#pragma mark ____________________________Memory Based

// Sign data with address
long CGPGPluginDLL::SignData(const char* in, const char* key, char** out, unsigned long* out_len, bool useMime, bool binary)
{
	long result = 0;

	// Write data to temp file
#if __dest_os == __mac_os || __dest_os == __mac_os_x
	FSSpec in_spec;
	in_spec.name[0] = 0;
	FSSpec* in_tmp = &in_spec;
	FSSpec out_spec;
	out_spec.name[0] = 0;
	FSSpec* out_tmp = &out_spec;
#else
	char in_tmp[1024];
	*in_tmp = 0;

	char out_tmp[1024];
	*out_tmp = 0;
#endif

	try
	{
		// Create temp files
		TempCreate(in_tmp, out_tmp, in);

		// Make sure temp files are deleted once we are done
		StRemoveFileSpec _in_remove(in_tmp);
		StRemoveFileSpec _out_remove(out_tmp);

		// Do file based sign (flag for use of temp files)
		result = SignFileX(in_tmp, key, out_tmp, useMime, binary, true);

		// Copy output data to memory
		if (result)
			// Read in temp data
			TempRead(out_tmp, out, out_len);
	}
	catch(...)
	{
		// Catch all and fall through to clean-up
	}

	return result;
}

// Encrypt to addresses
long CGPGPluginDLL::EncryptData(const char* in, const char** to, char** out, unsigned long* out_len, bool useMime, bool binary)
{
	long result = 0;

	// Write data to temp file
#if __dest_os == __mac_os || __dest_os == __mac_os_x
	FSSpec in_spec;
	in_spec.name[0] = 0;
	FSSpec* in_tmp = &in_spec;
	FSSpec out_spec;
	out_spec.name[0] = 0;
	FSSpec* out_tmp = &out_spec;
#else
	char in_tmp[1024];
	*in_tmp = 0;

	char out_tmp[1024];
	*out_tmp = 0;
#endif

	try
	{
		// Create temp files
		TempCreate(in_tmp, out_tmp, in);

		// Make sure temp files are deleted once we are done
		StRemoveFileSpec _in_remove(in_tmp);
		StRemoveFileSpec _out_remove(out_tmp);

		// Do file based sign (flag for use of temp files)
		result = EncryptFileX(in_tmp, to, out_tmp, useMime, binary, true);

		// Copy output data to memory
		if (result)
			// Read in temp data
			TempRead(out_tmp, out, out_len);
	}
	catch(...)
	{
		// Catch all and fall through to clean-up
	}

	return result;
}

// Encrypt to addresses and sign with address
long CGPGPluginDLL::EncryptSignData(const char* in, const char** to, const char* key, char** out, unsigned long* out_len, bool useMime, bool binary)
{
	long result = 0;

	// Write data to temp file
#if __dest_os == __mac_os || __dest_os == __mac_os_x
	FSSpec in_spec;
	in_spec.name[0] = 0;
	FSSpec* in_tmp = &in_spec;
	FSSpec out_spec;
	out_spec.name[0] = 0;
	FSSpec* out_tmp = &out_spec;
#else
	char in_tmp[1024];
	*in_tmp = 0;

	char out_tmp[1024];
	*out_tmp = 0;
#endif

	try
	{
		// Create temp files
		TempCreate(in_tmp, out_tmp, in);

		// Make sure temp files are deleted once we are done
		StRemoveFileSpec _in_remove(in_tmp);
		StRemoveFileSpec _out_remove(out_tmp);

		// Do file based sign (flag for use of temp files)
		result = EncryptSignFileX(in_tmp, to, key, out_tmp, useMime, binary, true);

		// Copy output data to memory
		if (result)
			// Read in temp data
			TempRead(out_tmp, out, out_len);
	}
	catch(...)
	{
		// Catch all and fall through to clean-up
	}

	return result;
}

// Decrypt or verify data
long CGPGPluginDLL::DecryptVerifyData(const char* in, const char* sig, const char* in_from,
										char** out, unsigned long* out_len, char** out_signedby, char** out_encryptedto,
										bool* success, bool* did_sig, bool* sig_ok, bool binary)
{
	long result = 0;

	// Write data to temp file
#if __dest_os == __mac_os || __dest_os == __mac_os_x
	FSSpec in_spec;
	in_spec.name[0] = 0;
	FSSpec* in_tmp = &in_spec;
	FSSpec out_spec;
	out_spec.name[0] = 0;
	FSSpec* out_tmp = &out_spec;
#else
	char in_tmp[1024];
	*in_tmp = 0;

	char out_tmp[1024];
	*out_tmp = 0;
#endif

	try
	{
		// Create temp files
		TempCreate(in_tmp, out_tmp, in);

		// Make sure temp files are deleted once we are done
		StRemoveFileSpec _in_remove(in_tmp);
		StRemoveFileSpec _out_remove(out_tmp);

		// Do file based sign (flag for use of temp files)
		result = DecryptVerifyFileX(in_tmp, sig, in_from, out_tmp, out_signedby, out_encryptedto, success, did_sig, sig_ok, binary, true);

		// Copy output data to memory
		if (result && out && out_len)
			// Read in temp data
			TempRead(out_tmp, out, out_len);
	}
	catch(...)
	{
		// Catch all and fall through to clean-up
	}

	return result;
}

long CGPGPluginDLL::DisposeData(const char* data)
{
	::free((void*) data);
	return 1;
}

#pragma mark ____________________________File based

// Sign file
long CGPGPluginDLL::SignFile(fspec in, const char* key, fspec out, bool useMime, bool binary)
{
	// Just do local op but flag as NOT using temp files
	return SignFileX(in, key, out, useMime, binary, false);
}

// Encrypt file
long CGPGPluginDLL::EncryptFile(fspec in, const char** to, fspec out, bool useMime, bool binary)
{
	// Just do local op but flag as NOT using temp files
	return EncryptFileX(in, to, out, useMime, binary, false);
}

// Encrypt & sign file
long CGPGPluginDLL::EncryptSignFile(fspec in, const char** to, const char* key, fspec out, bool useMime, bool binary)
{
	// Just do local op but flag as NOT using temp files
	return EncryptSignFileX(in, to, key, out, useMime, binary, false);
}

// Decrypt/verify file
long CGPGPluginDLL::DecryptVerifyFile(fspec in, const char* sig, const char* in_from,
										fspec out, char** out_signedby, char** out_encryptedto,
										bool* success, bool* did_sig, bool* sig_ok, bool binary)
{
	// Just do local op but flag as NOT using temp files
	return DecryptVerifyFileX(in, sig, in_from, out, out_signedby, out_encryptedto, success, did_sig, sig_ok, binary, false);
}

#pragma mark ____________________________Local File based operations

// Sign file
long CGPGPluginDLL::SignFileX(fspec in, const char* key, fspec out, bool useMime, bool binary, bool using_temp_files)
{
	// Signing requires passphrase
	char passphrase[256];
	StClearPassphrase _clear_pass(passphrase, sizeof(passphrase));
	if (!GetSignKeyPassphrase(key, passphrase))
	{
		REPORTERROR(eSecurity_UserAbort, "User cancelled passphrase");
		return 0;
	}

	std::unique_ptr<char> in_path(ToPath(in));
	std::unique_ptr<char> out_path(ToPath(out));

#if __dest_os == __mac_os_x || __dest_os == __win32_os
	// Make sure temp file is deleted when we return
	StRemoveFile _in_remove;

	// Do this conversion only if not binary
	if (!binary)
	{
		// Do lendl -> LF conversion using temporary file
		cdstring in_tmp;
		if (lendl_convertLF(in_path.get(), using_temp_files ? NULL : &in_tmp, false) != 1)
			return 0;
		
		// If original file was not overwritten, replace original path with temp path
		if (!using_temp_files)
		{
			// Switch to use temp file as input path
			in_path.reset(in_tmp.grab_c_str());
			
			// Make sure temp file is deleted when we return
			_in_remove.set(in_path.get());
		}
	}
#endif

	cdstrvect args;
	args.push_back("-u");
	args.push_back(key);
	args.push_back("-o");
	args.push_back(out_path.get());
	args.push_back("-a");
	if (useMime)
		args.push_back("--detach-sign");
	else
		args.push_back("--clearsign");
	args.push_back(in_path.get());

	long result = CallGPG(args, passphrase, binary);

#if __dest_os == __mac_os_x || __dest_os == __win32_os
	// Do LF -> lendl conversion
	if (result == 1)
		result = lendl_convertLF(out_path.get(), NULL, true);
#endif

	return result;
}

// Encrypt file
long CGPGPluginDLL::EncryptFileX(fspec in, const char** to, fspec out, bool useMime, bool binary, bool using_temp_files)
{
	std::unique_ptr<char> in_path(ToPath(in));
	std::unique_ptr<char> out_path(ToPath(out));

#if __dest_os == __mac_os_x || __dest_os == __win32_os
	// Make sure temp file is deleted when we return
	StRemoveFile _in_remove;

	// Do this conversion only if not binary
	if (!binary)
	{
		// Do lendl -> LF conversion using temporary file
		cdstring in_tmp;
		if (lendl_convertLF(in_path.get(), using_temp_files ? NULL : &in_tmp, false) != 1)
			return 0;
		
		// If original file was not overwritten, replace original path with temp path
		if (!using_temp_files)
		{
			// Switch to use temp file as input path
			in_path.reset(in_tmp.grab_c_str());
			
			// Make sure temp file is deleted when we return
			_in_remove.set(in_path.get());
		}
	}
#endif

	cdstrvect args;
	const char** p = to;
	while(*p)
	{
		args.push_back("-r");
		args.push_back(*p++);
	}
	args.push_back("-o");
	args.push_back(out_path.get());
	args.push_back("-a");
	args.push_back("-e");
	args.push_back(in_path.get());

	long result = CallGPG(args, NULL, binary);

#if __dest_os == __mac_os_x || __dest_os == __win32_os
	// Do LF -> lendl conversion
	if (result == 1)
		result = lendl_convertLF(out_path.get(), NULL, true);
#endif

	return result;
}

// Encrypt & sign file
long CGPGPluginDLL::EncryptSignFileX(fspec in, const char** to, const char* key, fspec out, bool useMime, bool binary, bool using_temp_files)
{
	std::unique_ptr<char> in_path(ToPath(in));
	std::unique_ptr<char> out_path(ToPath(out));

	// Signing requires passphrase
	char passphrase[256];
	StClearPassphrase _clear_pass(passphrase, sizeof(passphrase));
	if (!GetSignKeyPassphrase(key, passphrase))
	{
		REPORTERROR(eSecurity_UserAbort, "User cancelled passphrase");
		return 0;
	}

#if __dest_os == __mac_os_x || __dest_os == __win32_os
	// Make sure temp file is deleted when we return
	StRemoveFile _in_remove;

	// Do this conversion only if not binary
	if (!binary)
	{
		// Do lendl -> LF conversion using temporary file
		cdstring in_tmp;
		if (lendl_convertLF(in_path.get(), using_temp_files ? NULL : &in_tmp, false) != 1)
			return 0;
		
		// If original file was not overwritten, replace original path with temp path
		if (!using_temp_files)
		{
			// Switch to use temp file as input path
			in_path.reset(in_tmp.grab_c_str());
			
			// Make sure temp file is deleted when we return
			_in_remove.set(in_path.get());
		}
	}
#endif

	cdstrvect args;
	const char** p = to;
	while(*p)
	{
		args.push_back("-r");
		args.push_back(*p++);
	}
	args.push_back("-u");
	args.push_back(key);
	args.push_back("-o");
	args.push_back(out_path.get());
	args.push_back("-a");
	args.push_back("-es");
	args.push_back(in_path.get());

	long result = CallGPG(args, passphrase, binary);

#if __dest_os == __mac_os_x || __dest_os == __win32_os
	// Do LF -> lendl conversion
	if (result == 1)
		result = lendl_convertLF(out_path.get(), NULL, true);
#endif

	return result;
}

// Decrypt/verify file
long CGPGPluginDLL::DecryptVerifyFileX(fspec in, const char* sig, const char* in_from,
											fspec out, char** out_signedby, char** out_encryptedto,
											bool* success, bool* did_sig, bool* sig_ok, bool binary, bool using_temp_files)
{
	long result = 0;
	mData->mDidSig = false;
	cdstrvect signedBy;
	cdstrvect encryptedTo;

	std::unique_ptr<char> in_path(ToPath(in));
	std::unique_ptr<char> out_path(ToPath(out));

#if __dest_os == __mac_os_x || __dest_os == __win32_os
	// Make sure temp file is deleted when we return
	StRemoveFile _in_remove;

	// Do this conversion only if not binary
	if (!binary)
	{
		// Do lendl -> LF conversion using temporary file
		cdstring in_tmp;
		if (lendl_convertLF(in_path.get(), using_temp_files ? NULL : &in_tmp, false) != 1)
			return 0;
		
		// If original file was not overwritten, replace original path with temp path
		if (!using_temp_files)
		{
			// Switch to use temp file as input path
			in_path.reset(in_tmp.grab_c_str());
			
			// Make sure temp file is deleted when we return
			_in_remove.set(in_path.get());
		}
	}
#endif

	// Signing requires passphrase
	char passphrase[256];
	StClearPassphrase _clear_pass(passphrase, sizeof(passphrase));

#if __dest_os == __mac_os || __dest_os == __mac_os_x
	FSSpec sig_spec;
	sig_spec.name[0] = 0;
	FSSpec* sig_tmp = &sig_spec;
#else
	char sig_tmp[1024];
	*sig_tmp = 0;
#endif
	// Make sure temp file is deleted when we return
	StRemoveFile _sig_remove;

	cdstrvect args;
	if (out_path.get() && *out_path.get())
	{
		args.push_back("-o");
		args.push_back(out_path.get());
	}
	if (!sig)
	{
		// Need to get passphrase for file
		if (GetPassphraseForFile(in_path.get(), passphrase, signedBy, encryptedTo) != 1)
		{
			return 0;
		}

		args.push_back("--decrypt");
	}
	else
	{
		// Create temp sig file
		try
		{
			TempCreate(sig_tmp, NULL, sig);
		}
		catch(...)
		{
			*success = false;
		}
#if __dest_os == __mac_os || __dest_os == __mac_os_x
		if (!*sig_spec.name)
#else
		if (!*sig_tmp)
#endif
			return 0;

		std::unique_ptr<char> sig_path(ToPath(sig_tmp));
		_sig_remove.set(sig_path.get());

#if __dest_os == __mac_os_x || __dest_os == __win32_os
		// Do lendl -> LF conversion
		if (lendl_convertLF(sig_path.get(), NULL, false) != 1)
			return 0;
#endif

		// Need to get passphrase for file
		if (GetPassphraseForFile(sig_path.get(), passphrase, signedBy, encryptedTo) != 1)
		{
			return 0;
		}

		args.push_back("--verify");
		args.push_back(sig_path.get());
	}
	args.push_back(in_path.get());

	// Clear out signed by cache in case we need it
	mData->mSignatureKeys.clear();

	result = CallGPG(args, encryptedTo.size() ? passphrase : NULL, binary);
	*success = (result == 1);
	*did_sig = mData->mDidSig;
	*sig_ok = (result == 1);

	// Recover signed by info if not already found
	if (mData->mDidSig && (signedBy.size() == 0) && mData->mSignatureKeys.size())
	{
		LookupKeys(false, mData->mSignatureKeys, signedBy, true, true);
	}

	mData->mSignedByList = cdstring::ToArray(signedBy);
	*out_signedby = (char*) mData->mSignedByList;
	
	if (encryptedTo.size())
	{
		mData->mEncryptedToList = cdstring::ToArray(encryptedTo);
		*out_encryptedto = (char*) mData->mEncryptedToList;
	}

#if __dest_os == __mac_os_x || __dest_os == __win32_os
	// Do LF -> lendl conversion only for valid output file
	// When verifying there may not be an output
	if ((result == 1) && out_path.get() && *out_path.get())
		result = lendl_convertLF(out_path.get(), NULL, true);
#endif

	return result;
}

#pragma mark ____________________________Others

// MIME parameters

// top-level multipart
const char* cMIMEMultipartType = "multipart";
const char* cMIMEMultipartSigned = "signed";
const char* cMIMEMultipartEncrypted = "encrypted";

// micalg value will be dynamically overridden by SIG_CREATED parsing
const char* cMIMEMultipartSignedParams[] =
	{ "micalg", "pgp-sha256", "protocol", "application/pgp-signature", NULL };
const char* cMIMEMultipartEncryptedParams[] = 
	{ "protocol", "application/pgp-encrypted", NULL };

const char* cMIMEApplicationType = "application";
const char* cMIMEPGPSigned = "pgp-signature";
const char* cMIMEPGPEncrypted = "pgp-encrypted";
const char* cMIMEOctetStream = "octet-stream";

// Get MIME parameters for signing
long CGPGPluginDLL::GetMIMESign(SMIMEMultiInfo* params)
{
	// Use dynamic micalg from SIG_CREATED if available
	const char** sign_params;
	if (!mData->mSigCreatedMicalg.empty())
	{
		mData->mDynamicSignedParams[0] = "micalg";
		mData->mDynamicSignedParams[1] = mData->mSigCreatedMicalg.c_str();
		mData->mDynamicSignedParams[2] = "protocol";
		mData->mDynamicSignedParams[3] = "application/pgp-signature";
		mData->mDynamicSignedParams[4] = NULL;
		sign_params = mData->mDynamicSignedParams;
	}
	else
		sign_params = cMIMEMultipartSignedParams;

	SetMIMEDetails(&params->multipart,
					cMIMEMultipartType,
					cMIMEMultipartSigned,
					sign_params);

	SetMIMEDetails(&params->first,
					NULL,
					NULL,
					NULL);

	SetMIMEDetails(&params->second,
					cMIMEApplicationType,
					cMIMEPGPSigned,
					NULL);

	return 1;
}

// Get MIME parameters for encryption
long CGPGPluginDLL::GetMIMEEncrypt(SMIMEMultiInfo* params)
{
	SetMIMEDetails(&params->multipart,
					cMIMEMultipartType,
					cMIMEMultipartEncrypted,
					cMIMEMultipartEncryptedParams);
	
	SetMIMEDetails(&params->first,
					cMIMEApplicationType,
					cMIMEPGPEncrypted,
					NULL);
	
	SetMIMEDetails(&params->second,
					cMIMEApplicationType,
					cMIMEOctetStream,
					NULL);
	
	return 1;
}

// Get MIME parameters for encryption
long CGPGPluginDLL::GetMIMEEncryptSign(SMIMEMultiInfo* params)
{
	SetMIMEDetails(&params->multipart,
					cMIMEMultipartType,
					cMIMEMultipartEncrypted,
					cMIMEMultipartEncryptedParams);
	
	SetMIMEDetails(&params->first,
					cMIMEApplicationType,
					cMIMEPGPEncrypted,
					NULL);
	
	SetMIMEDetails(&params->second,
					cMIMEApplicationType,
					cMIMEOctetStream,
					NULL);
	
	return 1;
}

// Check that MIME type is verifiable by this plugin
long CGPGPluginDLL::CanVerifyThis(const char* type)
{
	// Return 0 if it can verify, 1 if not
	// This ensures that old PGP plugins that don't support this call
	// pretend to support the crypto type
	return !::strcmpnocase(type, "application/pgp-signature") ? 0 : 1;
}

// Check that MIME type is decryptable by this plugin
long CGPGPluginDLL::CanDecryptThis(const char* type)
{
	// Return 0 if it can decrypt, 1 if not
	// This ensures that old PGP plugins that don't support this call
	// pretend to support the crypto type
	return ::strcmpnocase(type, "application/pgp-encrypted");
}

// Get last textual error
long CGPGPluginDLL::GetLastError(long* err_no, char** error)
{
	*err_no = mData->mErrno;
	*error = mData->mErrstr.c_str_mod();

	return 0;
}

#pragma mark ____________________________Utilities
// Prepare PGP context
void CGPGPluginDLL::PreparePGP()
{
	// Create a new PGP context
	//ThrowIfPGPErr(PGPNewContext(kPGPsdkAPIVersion, &mContextRef))
}

// Finish with PGP context
void CGPGPluginDLL::FinishPGP()
{
	//if(PGPContextRefIsValid(mContextRef)) 	PGPFreeContext(mContextRef);

	// Initialize allocatable storage to  kInvalidPGP..
	//mContextRef = kInvalidPGPContextRef;
}

// Set MIME details
void CGPGPluginDLL::SetMIMEDetails(SMIMEInfo* mime, const char* type, const char* subtype, const char** params)
{
	mime->type = type;
	mime->subtype = subtype;
	mime->params = params;
}

long CGPGPluginDLL::CallGPG(cdstrvect& args, const char* passphrase, bool binary, bool file_status, bool key_list)
{
	mData->mErrno = 0;
	mData->mSigCreatedHashAlgo = 0;
	mData->mSigCreatedMicalg = cdstring::null_str;
	long result = 1;

	cdstrvect out;
#ifdef USE_WIN32FORK
	out.push_back(mExePath.c_str());
#else
#if __dest_os == __mac_os_x
	out.push_back("/usr/local/bin/gpg");
#else
	out.push_back(cGPG);
#endif
#endif
	out.push_back("--batch");
	//out.push_back("--no-options");
	out.push_back("--yes");
	out.push_back("--no-emit-version");

	// Do canonical text mode if not binary
	if (!binary)
		out.push_back("-t");

#if defined(USE_UNIXFORK)

	int outputfd[2] = {-1, -1};
	int errorfd[2] = {-1, -1};
	int statusfd[2] = {-1, -1};
	int passfd[2] = {-1, -1};

	try
	{
		// Create stdout pipe if required
		if (file_status)
		{
			if (pipe(outputfd) == -1)
			{
				REPORTERROR(eSecurity_UnknownError, "Could not create output pipe");
				throw -1L;
			}
		}

		// Always create stderr pipe
		if (pipe(errorfd) == -1)
		{
			REPORTERROR(eSecurity_UnknownError, "Could not create error pipe");
			throw -1L;
		}

		// Always create a status pipe
		if (pipe(statusfd) == -1)
		{
			REPORTERROR(eSecurity_UnknownError, "Could not create status pipe");
			throw -1L;
		}
		else
		{
			// Make sure gpg knows what the pipe's fd is
			out.push_back("--status-fd");
			out.push_back(cdstring((unsigned long) statusfd[1]));
		}

		// Create a passphrase pipe if required
		if (passphrase)
		{
			if (pipe(passfd) == -1)
			{
				REPORTERROR(eSecurity_UnknownError, "Could not create passphrase pipe");
				throw -1L;
			}
			else
			{
				// Write passphrase into the pipe ready for gpg to read it
				::write (passfd[1], passphrase, ::strlen(passphrase));
				::write (passfd[1], "\n", 1);

				// Make sure gpg knows what the pipe's fd is
				out.push_back("--passphrase-fd");
				out.push_back(cdstring((unsigned long) passfd[0]));
			}
		}
	}
	catch(...)
	{
		unix_closepipes(outputfd);
		unix_closepipes(errorfd);
		unix_closepipes(statusfd);
		unix_closepipes(passfd);

		return 0;
	}

	// Do log of command line here before the fork:
	// OS X does not like the LogEntry in the forked process
	if (mLogging)
	{
		cdstring logged = "Command line: ";
 		for(unsigned int i = 0; i < out.size(); i++)
 		{
			logged += " ";
			logged += out[i];
		}
 		for(unsigned int i = 0; i < args.size(); i++)
 		{
			logged += " ";
			logged += args[i];
		}
 		LogEntry(logged);
	}

	// Create gpg process
	pid_t pid = fork();
	if (pid == -1)
	{
		REPORTERROR(eSecurity_UnknownError, "Failed to fork");
		unix_closepipes(outputfd);
		unix_closepipes(errorfd);
		unix_closepipes(statusfd);
		unix_closepipes(passfd);
	}
	else if (pid == 0)
	{
		// Child process
 
		// Close other ends of pipes
		if (outputfd[0] != -1)
		{
			::close(outputfd[0]);
			outputfd[0] = -1;
		}
		::close(errorfd[0]);
		errorfd[0] = -1;
		::close(statusfd[0]);
		statusfd[0] = -1;

		// Direct stdin, stdout, stderr to /dev/null
		int devnull = ::open("/dev/null", O_RDWR);
		if (devnull == -1)
		{
			REPORTERROR(eSecurity_UnknownError, "Failed to open /dev/null in child process");
			exit(1);
		}

		// Setup stdin, stdout & stderr
		::dup2(devnull, 0);
		::dup2(outputfd[1], 1);
		::close(outputfd[1]);
		outputfd[1] = -1;
		::dup2(errorfd[1], 2);
		::close(errorfd[1]);
		errorfd[1] = -1;

		// Close fds that we do not want the child to inherit
		long open_max = ::sysconf(_SC_OPEN_MAX);
		if (open_max > 0)
		{
			for (int i = 3; i < open_max; i++)
			{
				// Must keep status (out) /pswd (in) pipes open
				if ((i != statusfd[1]) && (i != passfd[0]))
					::close(i);
			}
		}

		// create args
		int argc = out.size() + args.size();
		char** argv = (char**) malloc((argc + 1) * sizeof(char*));
		if (!argv)
			exit(1);
		char** p = argv;
		cdstring logged;
 		for(unsigned int i = 0; i < out.size(); i++)
 			*p++ = out[i].c_str_mod();
 		for(unsigned int i = 0; i < args.size(); i++)
 			*p++ = args[i].c_str_mod();
 		*p = NULL;
 
		// Execute it
		::execvp(argv[0], argv);

		// Only get here if failed
		REPORTERROR(eSecurity_UnknownError, "Failed to exec process");
		exit(1);
	}
	else
	{
		// Parent process must wait
		int status = 0;
		pid_t retpid = ::waitpid(pid, &status, WNOHANG);

		fd_set readfds;
		FD_ZERO (&readfds);
		if (file_status)
			FD_SET (outputfd[0], &readfds);
		FD_SET (errorfd[0], &readfds);
		FD_SET (statusfd[0], &readfds);
		struct timeval timeout = { 0, 0 };
		int select_fd = std::max(outputfd[0], std::max(errorfd[0], statusfd[0])) + 1;
		int dataavail = ::select(select_fd, &readfds, NULL, NULL, &timeout);

		cdstring output_line;
		mData->mStdError = cdstring::null_str;
		cdstring status_line;
		while((retpid == 0) || (dataavail != 0))
		{
			// Handle output
			if (file_status && FD_ISSET(outputfd[0], &readfds))
			{
				const int bufsize = 1024;
				cdstring buf;
				buf.reserve(bufsize);
				int readsize = ::read(outputfd[0], buf, bufsize);
				if (readsize == -1)
					break;
				buf[(unsigned long) std::min(bufsize - 1, readsize)] = 0;
				buf.ConvertEndl();
				output_line += buf;

#ifdef DEBUG_OUTPUT
				printf("%s", buf);
#endif
				LogEntry(buf);

				if (key_list)
					ProcessKeyListOutput(output_line);
				else
					ProcessFileStatusOutput(output_line);
			}

			// Handle error
			if (FD_ISSET(errorfd[0], &readfds))
			{
				const int bufsize = 1024;
				cdstring buf;
				buf.reserve(bufsize);
				int readsize = ::read(errorfd[0], buf, bufsize);
				if (readsize == -1)
					break;
				buf[(unsigned long) std::min(bufsize - 1, readsize)] = 0;
				buf.ConvertEndl();

#ifdef DEBUG_OUTPUT
				printf("%s", buf);
#endif
				LogEntry(buf);
				mData->mStdError += buf;
			}

			// Handle status
			if (FD_ISSET(statusfd[0], &readfds))
			{
				const int bufsize = 1024;
				cdstring buf;
				buf.reserve(bufsize);
				int readsize = ::read(statusfd[0], buf, bufsize);
				if (readsize == -1)
					break;
				buf[(unsigned long) std::min(bufsize - 1, readsize)] = 0;
				buf.ConvertEndl();
				status_line += buf;

#ifdef DEBUG_OUTPUT
				printf("%s", buf);
#endif
				LogEntry(buf);

				ProcessStatus(status_line);
			}

			if (retpid == 0)
			{
				retpid = ::waitpid(pid, &status, WNOHANG);
				if (retpid == -1)
					break;
			}
			FD_ZERO (&readfds);
			if (file_status)
				FD_SET (outputfd[0], &readfds);
			FD_SET (errorfd[0], &readfds);
			FD_SET (statusfd[0], &readfds);
			dataavail = ::select(select_fd, &readfds, NULL, NULL, &timeout);
			if (dataavail == -1)
				break;
		}

		// Ensure the child is reaped so status is valid — the loop may have
		// exited via a read-error break before the in-loop waitpid ran
		if (retpid == 0)
			retpid = ::waitpid(pid, &status, 0);

		// Check process return value via shared helper
		result = ProcessExitResult(
			WIFEXITED(status) ? WEXITSTATUS(status) : 0,
			WIFEXITED(status),
			WIFSIGNALED(status),
			WIFSIGNALED(status) ? WTERMSIG(status) : 0);

		unix_closepipes(outputfd);
		unix_closepipes(errorfd);
		unix_closepipes(statusfd);
		unix_closepipes(passfd);
	}
#elif defined(USE_WIN32FORK)
	HANDLE outputfd[2] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
	HANDLE errorfd[2] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
	HANDLE statusfd[2] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
	HANDLE passfd[2] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};

	try
	{
		// Create stdout pipe if required
		if (file_status)
		{
			if (!win32_createpipes(outputfd, true))
			{
				REPORTERROR(eSecurity_UnknownError, "Could not create output pipe");
				throw -1L;
			}
		}

		// Always create stderr pipe
		if (!win32_createpipes(errorfd, true))
		{
			REPORTERROR(eSecurity_UnknownError, "Could not create error pipe");
			throw -1L;
		}

		// Always create a status pipe
		if (!win32_createpipes(statusfd, true))
		{
			REPORTERROR(eSecurity_UnknownError, "Could not create status pipe");
			throw -1L;
		}
		else
		{
			// Make sure gpg knows what the pipe's fd is
			out.push_back("--status-fd");
			out.push_back(cdstring((unsigned long) statusfd[1]));
		}

		// Create a passphrase pipe if required
		if (passphrase)
		{
			if (!win32_createpipes(passfd, false))
			{
				REPORTERROR(eSecurity_UnknownError, "Could not create passphrase pipe");
				throw -1L;
			}
			else
			{
				// Write passphrase into the pipe ready for gpg to read it
				DWORD written;
				::WriteFile(passfd[1], passphrase, ::strlen(passphrase), &written, NULL);
				::WriteFile(passfd[1], "\n", 1, &written, NULL);

				// Make sure gpg knows what the pipe's fd is
				out.push_back("--passphrase-fd");
				out.push_back(cdstring((unsigned long) passfd[0]));
			}
		}
	}
	catch(...)
	{
		win32_closepipes(outputfd);
		win32_closepipes(errorfd);
		win32_closepipes(statusfd);
		win32_closepipes(passfd);

		return 0;
	}

	// Add args
	for(cdstrvect::iterator iter = args.begin(); iter != args.end(); iter++)
		out.push_back(*iter);

	// Create process
	HANDLE proc = win32_spawn(out, outputfd[1], errorfd[1], statusfd[1]);
    if (proc == INVALID_HANDLE_VALUE)
	{
		REPORTERROR(eSecurity_UnknownError, "Failed to fork");
		win32_closepipes(outputfd);
		win32_closepipes(errorfd);
		win32_closepipes(statusfd);
		win32_closepipes(passfd);
		
		result = 0;
	}
	else
	{
		// Parent process must wait
		DWORD status;
		int retpid = win32_waitpid(proc, status);

		bool outputfd_bytes = false;
		bool errorfd_bytes = false;
		bool statusfd_bytes = false;
		int dataavail = win32_select(outputfd[0], outputfd_bytes, errorfd[0], errorfd_bytes, statusfd[0], statusfd_bytes);

		cdstring output_line;
		mData->mStdError = cdstring::null_str;
		cdstring status_line;
		while((retpid == 0) || (dataavail != 0))
		{
			// Handle output
			if (outputfd_bytes)
			{
				const DWORD bufsize = 1024;
				cdstring buf;
				buf.reserve(bufsize);
				DWORD bufread;
				if (::ReadFile(outputfd[0], buf.c_str_mod(), bufsize, &bufread, NULL) && bufread)
				{
					buf[(cdstring::size_type)std::min(bufsize - 1, bufread)] = 0;
					buf.ConvertEndl();
					output_line += buf;

#ifdef DEBUG_OUTPUT
					printf("%s", buf);
#endif
					LogEntry(buf);

					if (key_list)
						ProcessKeyListOutput(output_line);
					else
						ProcessFileStatusOutput(output_line);
				}
			}

			// Handle error
			if (errorfd_bytes)
			{
				const DWORD bufsize = 1024;
				cdstring buf;
				buf.reserve(bufsize);
				DWORD bufread;
				if (::ReadFile(errorfd[0], buf.c_str_mod(), bufsize, &bufread, NULL) && bufread)
				{
					buf[(cdstring::size_type)std::min(bufsize - 1, bufread)] = 0;
					buf.ConvertEndl();
#ifdef DEBUG_OUTPUT
					printf("%s", buf);
#endif
					LogEntry(buf);
					mData->mStdError += buf;
				}
			}

			// Handle status
			if (statusfd_bytes)
			{
				const DWORD bufsize = 1024;
				cdstring buf;
				buf.reserve(bufsize);
				DWORD bufread;
				if (::ReadFile(statusfd[0], buf.c_str_mod(), bufsize, &bufread, NULL) && bufread)
				{
					buf[(cdstring::size_type)std::min(bufsize - 1, bufread)] = 0;
					buf.ConvertEndl();
					status_line += buf;

#ifdef DEBUG_OUTPUT
					printf("%s", buf);
#endif
					LogEntry(buf);

					ProcessStatus(status_line);
				}
			}

			if (retpid == 0)
				retpid = win32_waitpid(proc, status);

			dataavail = win32_select(outputfd[0], outputfd_bytes, errorfd[0], errorfd_bytes, statusfd[0], statusfd_bytes);
		}

		// Check process return value via shared helper
		result = ProcessExitResult(status, true, false, 0);

		win32_closepipes(outputfd);
		win32_closepipes(errorfd);
		win32_closepipes(statusfd);
		win32_closepipes(passfd);
	}
#endif

	return result;
}

long CGPGPluginDLL::ProcessExitResult(int exit_code, bool exited_normally, bool was_signaled, int signal_num)
{
	if (mData->mErrno && mData->mErrno != eSecurity_DubiousKey)
		return 0;

	if (exited_normally && exit_code != 0)
	{
		if (mData->mStdError.length())
			REPORTERROR(eSecurity_UnknownError, mData->mStdError.c_str());
		else
			REPORTERROR(eSecurity_UnknownError, "Exit status non-zero");

		cdstring buf;
		buf.reserve(1024);
		::snprintf(buf.c_str_mod(), 1024, "Exit status non-zero: %d\n", exit_code);
		buf.ConvertEndl();
#ifdef DEBUG_OUTPUT
		printf("%s", buf);
#endif
		LogEntry(buf);
		return 0;
	}

	if (was_signaled && signal_num != 0)
	{
		cdstring errtxt("Process killed by signal: ");
#if __dest_os == __linux_os || __dest_os == __mac_os_x
		errtxt += ::strsignal(signal_num);
#else
		errtxt += cdstring((long) signal_num);
#endif
		REPORTERROR(eSecurity_UnknownError, errtxt);
		LogEntry(errtxt);
		return 0;
	}

	return 1;
}

#ifdef USE_UNIXFORK
int CGPGPluginDLL::unix_closepipes(int* fds)
{
	for(int i = 0; i < 2; i++)
	{
		if (fds[i] != -1)
		{
			::close(fds[i]);
			fds[i] = -1;
		}
	}
	
	return 1;
}
#endif

#ifdef USE_WIN32FORK
int CGPGPluginDLL::win32_createpipes(HANDLE* hdls, bool read_this_end)
{
	// Create the pipe handles
	if (!::CreatePipe(&hdls[0], &hdls[1], NULL, 1024))
	{
		REPORTERROR(eSecurity_UnknownError, "Could not create pipe");
		::CloseHandle(hdls[0]);
		::CloseHandle(hdls[1]);
		return 0;
	}
	
	// Duplicate the handle for the other end and make it inheritable
	HANDLE h;
	if (!::DuplicateHandle(GetCurrentProcess(), hdls[read_this_end ? 1 : 0], GetCurrentProcess(), &h, 0, TRUE, DUPLICATE_SAME_ACCESS))
	{
		REPORTERROR(eSecurity_UnknownError, "Could not duplicate pipe");
		::CloseHandle(hdls[0]);
		::CloseHandle(hdls[1]);
		return 0;
	}
	::CloseHandle(hdls[read_this_end ? 1 : 0]);
	hdls[read_this_end ? 1 : 0] = h;
	
	return 1;
}

int CGPGPluginDLL::win32_closepipes(HANDLE* hdls)
{
	for(int i = 0; i < 2; i++)
	{
		if (hdls[i] != INVALID_HANDLE_VALUE)
		{
			::CloseHandle(hdls[i]);
			hdls[i] = INVALID_HANDLE_VALUE;
		}
	}
	
	return 1;
}

HANDLE CGPGPluginDLL::win32_spawn(const cdstrvect& args, HANDLE& outputfd, HANDLE& errorfd, HANDLE& statusfd)
{
	// Create process
	cdstring cmd_line;
	for(cdstrvect::const_iterator iter = args.begin(); iter != args.end(); iter++)
	{
		if (iter != args.begin())
			cmd_line += " ";
		
		// May need to quote
		if (::strchr((*iter).c_str(), ' '))
		{
			cmd_line += "\"";
			cmd_line += *iter;
			cmd_line += "\"";
		}
		else
			cmd_line += *iter;
	}
	LogEntry(cmd_line);

    SECURITY_ATTRIBUTES sec_attr;
    ::memset(&sec_attr, 0, sizeof sec_attr);
    sec_attr.nLength = sizeof sec_attr;
    sec_attr.bInheritHandle = FALSE;

    int cr_flags = CREATE_SUSPENDED | CREATE_DEFAULT_ERROR_MODE | GetPriorityClass(GetCurrentProcess());
    char *envblock = NULL;

	int debug_me = 0;
    STARTUPINFOA si;
   	::memset(&si, 0, sizeof si);
    si.cb = sizeof (si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = debug_me? SW_SHOW : SW_HIDE;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	// si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdOutput = (outputfd != INVALID_HANDLE_VALUE ? outputfd : GetStdHandle(STD_OUTPUT_HANDLE));
    si.hStdError = (errorfd != INVALID_HANDLE_VALUE ? errorfd : GetStdHandle(STD_OUTPUT_HANDLE));

    PROCESS_INFORMATION pi = {
        NULL,      /* returns process handle */
        0,         /* returns primary thread handle */
        0,         /* returns pid */
        0         /* returns tid */
    };

    if (::CreateProcessA(NULL, cmd_line, &sec_attr, &sec_attr, TRUE, cr_flags, envblock, NULL, &si, &pi))
	{
		// Child process
 
		// Close other ends of pipes
		if (outputfd != INVALID_HANDLE_VALUE)
		{
			::CloseHandle(outputfd);
			outputfd = INVALID_HANDLE_VALUE;
		}
		if (errorfd != INVALID_HANDLE_VALUE)
		{
			::CloseHandle(errorfd);
			errorfd = INVALID_HANDLE_VALUE;
		}
		::CloseHandle(statusfd);
		statusfd = INVALID_HANDLE_VALUE;

		// Execute it
		if (::ResumeThread(pi.hThread) < 0)
		{
			// Only get here if failed
			REPORTERROR(eSecurity_UnknownError, "Failed to ResumeThread");
	    	return INVALID_HANDLE_VALUE;
		}
	    if (!::CloseHandle(pi.hThread))
	    { 
			REPORTERROR(eSecurity_UnknownError, "Failed to CloseHandle");
	    	return INVALID_HANDLE_VALUE;
	    }

    	return pi.hProcess;
	}
    else
    {
    	DWORD err = ::GetLastError();
    	return INVALID_HANDLE_VALUE;
    }
}

int CGPGPluginDLL::win32_waitpid(HANDLE proc, DWORD& status)
{
	int result = 0;

	DWORD signal = ::WaitForSingleObject(proc, 0);
	switch (signal)
	{
	case WAIT_FAILED:
		REPORTERROR(eSecurity_UnknownError, "WaitForSingleObjectre returned WAIT_FAILED");
		break;

	case WAIT_OBJECT_0:
		if (!::GetExitCodeProcess(proc, &status))
			REPORTERROR(eSecurity_UnknownError, "GetExitCodeProcess returned false");
		result = 1;
		break;

	case WAIT_TIMEOUT:
		break;

	default:
		break;
	}

	return result;
}

int CGPGPluginDLL::win32_select(HANDLE outfd, bool& outfd_bytes, HANDLE errorfd, bool& errorfd_bytes, HANDLE statusfd, bool& statusfd_bytes)
{
	outfd_bytes = win32_hasbytes(outfd);
	errorfd_bytes = win32_hasbytes(errorfd);
	statusfd_bytes = win32_hasbytes(statusfd);

	return (outfd_bytes || errorfd_bytes || statusfd_bytes) ? 1 : 0;
}

bool CGPGPluginDLL::win32_hasbytes(HANDLE hdl)
{
	DWORD bytes_available = 0;
	if (hdl != INVALID_HANDLE_VALUE)
		::PeekNamedPipe(hdl, NULL, 0, NULL, &bytes_available, NULL);
	
	return (bytes_available > 0);
}

#endif

long CGPGPluginDLL::GetSignKeyPassphrase(const char* key, char* passphrase)
{
	if (key && *key && passphrase)
		return GetSignPassphrase(key, passphrase);
	else
		return 0;
}

long CGPGPluginDLL::GetPassphraseForFile(const char* in_path, char* passphrase, cdstrvect& signedBy, cdstrvect& encryptedTo)
{
	// Init required data structures
	mData->mListKeys.clear();
	mData->mSignatureKeys.clear();
	mData->mEncryptionKeys.clear();

	// Get packet data from file
	cdstrvect args;
	args.push_back("--list-packets");
	args.push_back("--list-only");
	args.push_back(in_path);

	// Ignore errors
	CallGPG(args, NULL, true, true);

	// Map signing keyids to names
	if (mData->mSignatureKeys.size())
		LookupKeys(false, mData->mSignatureKeys, signedBy, true, true);

	// Map encryption keyids to names
	if (mData->mEncryptionKeys.size())
	{
		// Map encryption keyids to names (public keys)
		LookupKeys(false, mData->mEncryptionKeys, encryptedTo, true, false);

		// Map encryption keyids to names (private keys)
		cdstrvect secret_keys;
		LookupKeys(true, mData->mEncryptionKeys, secret_keys, false, false);

		// Get a passphrase for a secret key
		if (secret_keys.size())
		{
			// Create array of keys
			std::unique_ptr<const char*> users(cdstring::ToArray(secret_keys, false));

			// Get passphrase
			unsigned long chosen;
			return GetPassphrase(users.get(), passphrase, chosen);
		}
		else
		{
			REPORTERROR(eSecurity_KeyUnavailable, "No secret keys found");
			return 0;
		}
	}
	
	return 1;
}

void CGPGPluginDLL::LookupKeys(bool secret, const cdstrvect& keyids, cdstrvect& keynames, bool add_missing, bool multiple_uids)
{
	mData->mKeyIDMap.clear();

	// List keys with matching keyids — use --with-colons for stable machine-parseable output
	cdstrvect args;
	args.push_back(secret ? "--list-secret-keys" : "--list-keys");
	args.push_back("--with-colons");
	for(cdstrvect::const_iterator iter = keyids.begin(); iter != keyids.end(); iter++)
		args.push_back(*iter);

	// Ignore errors
	CallGPG(args, NULL, true, true, true);

	// Map each keyid found in the PGP data to a name to pass back
	for(cdstrvect::const_iterator iter1 = keyids.begin(); iter1 != keyids.end(); iter1++)
	{
		// If a name mapping exists use the names others use keyid
		if (mData->mKeyIDMap.count(*iter1) == 1)
		{
			for(cdstrvect::const_iterator iter2 =  mData->mKeyIDMap[*iter1].begin(); iter2 != mData->mKeyIDMap[*iter1].end(); iter2++)
			{
				// Append key ids if secret keys
				if (secret)
				{
					cdstring name(*iter2);
					name += " (";
					name += *iter1;
					name += ")";
					keynames.push_back(name);
				}
				else
					keynames.push_back(*iter2);
				
				// Only do one if requested
				if (!multiple_uids)
					break;
			}
		}
		
		// Only add keys that are found if requested
		else if (add_missing)
		{
			// Put key id in parens
			cdstring id;
			id += "(";
			id += *iter1;
			id += ")";
			keynames.push_back(id);
		}
	}
}

long CGPGPluginDLL::ProcessStatus(cdstring& status)
{
	// Look for complete line
	const char* p = ::strchr(status.c_str(), os_endl[0]);
	while(p)
	{
		// Grab line and reset remainder
		cdstring line(status.c_str(), p - status.c_str());
		cdstring temp(p + os_endl_len);
		status = temp;

		// Look for GPG tag and step over
		if (::strncmp(line, cGNUPGStatus, ::strlen(cGNUPGStatus)))
			return 1;
		const char* q = line.c_str() + ::strlen(cGNUPGStatus);

		// Passphrase status
		if (!::strncmp(q, cGOOD_PASSPHRASE, ::strlen(cGOOD_PASSPHRASE)))
		{
			// Always reset the error here. When decrypting a message with multiple sigs
			// BAD_PASSPHRASE will occur before GOOD_PASSPHRASE for keys the user does not
			// enter a passphrase for. As soon as GOOD_PASSPHRASE is sent, passphrase processing
			// stops, so we clear any earlier errors.
			REPORTERROR(eSecurity_NoErr, "Good Passphrase");
		}
		else if (!::strncmp(q, cBAD_PASSPHRASE, ::strlen(cBAD_PASSPHRASE)))
		{
			REPORTERROR(eSecurity_BadPassphrase, "Bad Passphrase");
		}

		// Signature verification: good signature
		else if (!::strncmp(q, cGOODSIG, ::strlen(cGOODSIG)))
		{
			mData->mDidSig = true;
			cdstring tok(q + ::strlen(cGOODSIG));
			char* keyid = ::strtok(tok.c_str_mod(), " ");
			if (keyid)
				mData->mSignatureKeys.push_back(keyid);
		}
		// Expired signature (sig is good but the signature itself expired)
		else if (!::strncmp(q, cEXPSIG, ::strlen(cEXPSIG)))
		{
			mData->mDidSig = true;
			mData->mExpiredSignature = true;
			cdstring tok(q + ::strlen(cEXPSIG));
			char* keyid = ::strtok(tok.c_str_mod(), " ");
			if (keyid)
				mData->mSignatureKeys.push_back(keyid);
		}
		// Expired key (sig is good but key has expired)
		else if (!::strncmp(q, cEXPKEYSIG, ::strlen(cEXPKEYSIG)))
		{
			mData->mDidSig = true;
			mData->mExpiredKey = true;
			cdstring tok(q + ::strlen(cEXPKEYSIG));
			char* keyid = ::strtok(tok.c_str_mod(), " ");
			if (keyid)
				mData->mSignatureKeys.push_back(keyid);
		}
		// Revoked key (sig is good but key has been revoked)
		else if (!::strncmp(q, cREVKEYSIG, ::strlen(cREVKEYSIG)))
		{
			mData->mDidSig = true;
			mData->mRevokedKey = true;
			cdstring tok(q + ::strlen(cREVKEYSIG));
			char* keyid = ::strtok(tok.c_str_mod(), " ");
			if (keyid)
				mData->mSignatureKeys.push_back(keyid);
		}
		// Bad signature
		else if (!::strncmp(q, cBADSIG, ::strlen(cBADSIG)))
		{
			REPORTERROR(eSecurity_InvalidSignature, "Bad Signature");
		}
		// Error in signature verification
		else if (!::strncmp(q, cERRSIG, ::strlen(cERRSIG)))
		{
			REPORTERROR(eSecurity_InvalidSignature, "Error in Signature");
		}
		// No public key
		else if (!::strncmp(q, cNOPUBKEY, ::strlen(cNOPUBKEY)))
		{
			cdstring keyid(q + ::strlen(cNOPUBKEY));
			keyid.trimspace();
			cdstring errtxt("No Public Key (0x");
			errtxt += keyid;
			errtxt += ") for Signature";
			REPORTERROR(eSecurity_InvalidSignature, errtxt);
		}
		// VALIDSIG: full fingerprint, hash algo, timestamps
		// Format: VALIDSIG <fpr> <date> <timestamp> <expire> <ver> <reserved> <pkalgo> <hashalgo> <sigclass> [<primary-fpr>]
		else if (!::strncmp(q, cVALIDSIG, ::strlen(cVALIDSIG)))
		{
			cdstring tok(q + ::strlen(cVALIDSIG));
			char* fields[12] = {};
			char* f = ::strtok(tok.c_str_mod(), " ");
			for (int i = 0; i < 12 && f; i++)
			{
				fields[i] = f;
				f = ::strtok(NULL, " ");
			}
			// Field 0: fingerprint
			if (fields[0])
				mData->mSignerFingerprint = fields[0];
			// Field 3: expire-timestamp (0 = no expiry)
			if (fields[3])
				mData->mSignatureExpiry = ::atol(fields[3]);
			// Field 7: hash algorithm ID
			if (fields[7])
			{
				mData->mHashAlgorithm = ::atol(fields[7]);
				// RFC 9580 §9.5: MUST NOT validate recent sigs with MD5(1), SHA-1(2), RIPEMD-160(3)
				if (mData->mHashAlgorithm == 1 || mData->mHashAlgorithm == 2 || mData->mHashAlgorithm == 3)
				{
					mData->mWeakHashDetected = true;
					REPORTERROR(eSecurity_DubiousKey, "WARNING: Signature uses weak hash algorithm");
				}
			}
		}

		// Trust levels
		else if (!::strncmp(q, cTRUST_ULTIMATE, ::strlen(cTRUST_ULTIMATE)))
		{
			mData->mTrustLevel = 5;
		}
		else if (!::strncmp(q, cTRUST_FULLY, ::strlen(cTRUST_FULLY)))
		{
			mData->mTrustLevel = 4;
		}
		else if (!::strncmp(q, cTRUST_MARGINAL, ::strlen(cTRUST_MARGINAL)))
		{
			mData->mTrustLevel = 3;
		}
		else if (!::strncmp(q, cTRUST_UNDEFINED, ::strlen(cTRUST_UNDEFINED)))
		{
			mData->mTrustLevel = 2;
			REPORTERROR(eSecurity_DubiousKey, " WARNING: Key has no trusted signature!");
		}
		else if (!::strncmp(q, cTRUST_NEVER, ::strlen(cTRUST_NEVER)))
		{
			mData->mTrustLevel = 1;
			REPORTERROR(eSecurity_DubiousKey, " WARNING: Key is explicitly marked as untrusted!");
		}

		// Decryption status
		else if (!::strncmp(q, cDECRYPTION_OKAY, ::strlen(cDECRYPTION_OKAY)))
		{
			mData->mDecryptionOK = true;
		}
		else if (!::strncmp(q, cDECRYPTION_FAILED, ::strlen(cDECRYPTION_FAILED)))
		{
			mData->mDecryptionOK = false;
		}
		// DECRYPTION_INFO: cipher algorithm extraction
		// Format: DECRYPTION_INFO <mdc_method> <sym_algo> [<aead_algo>]
		else if (!::strncmp(q, cDECRYPTION_INFO, ::strlen(cDECRYPTION_INFO)))
		{
			cdstring tok(q + ::strlen(cDECRYPTION_INFO));
			char* mdc = ::strtok(tok.c_str_mod(), " ");
			char* sym = ::strtok(NULL, " ");
			if (sym)
				mData->mCipherAlgorithm = ::atol(sym);
		}

		// SIG_CREATED: for dynamic micalg derivation
		// Format: SIG_CREATED <type> <pk_algo> <hash_algo> <class> <timestamp> <keyfpr>
		else if (!::strncmp(q, cSIG_CREATED, ::strlen(cSIG_CREATED)))
		{
			cdstring tok(q + ::strlen(cSIG_CREATED));
			char* type = ::strtok(tok.c_str_mod(), " ");
			char* pkalgo = ::strtok(NULL, " ");
			char* hashalgo = ::strtok(NULL, " ");
			if (hashalgo)
			{
				mData->mSigCreatedHashAlgo = ::atol(hashalgo);
				// Map hash algorithm ID to micalg text name (RFC 9580 §9.5 / IANA registry)
				switch(mData->mSigCreatedHashAlgo)
				{
				case 1:  mData->mSigCreatedMicalg = "pgp-md5"; break;
				case 2:  mData->mSigCreatedMicalg = "pgp-sha1"; break;
				case 3:  mData->mSigCreatedMicalg = "pgp-ripemd160"; break;
				case 8:  mData->mSigCreatedMicalg = "pgp-sha256"; break;
				case 9:  mData->mSigCreatedMicalg = "pgp-sha384"; break;
				case 10: mData->mSigCreatedMicalg = "pgp-sha512"; break;
				case 11: mData->mSigCreatedMicalg = "pgp-sha224"; break;
				case 12: mData->mSigCreatedMicalg = "pgp-sha3-256"; break;
				case 14: mData->mSigCreatedMicalg = "pgp-sha3-512"; break;
				default: mData->mSigCreatedMicalg = cdstring::null_str; break;
				}
			}
		}

		// Key status
		else if (!::strncmp(q, cNO_SECKEY, ::strlen(cNO_SECKEY)))
		{
			REPORTERROR(eSecurity_KeyUnavailable, "No secret key available");
		}

		// Recipient errors
		else if (!::strncmp(q, cINV_RECP, ::strlen(cINV_RECP)))
		{
			cdstring tok(q + ::strlen(cINV_RECP));
			char* reason = ::strtok(tok.c_str_mod(), " ");
			char* addr = ::strtok(NULL, "");
			cdstring errtxt("Invalid recipient");
			if (addr)
			{
				errtxt += ": ";
				errtxt += addr;
			}
			LogEntry(errtxt);
		}
		else if (!::strncmp(q, cNO_RECP, ::strlen(cNO_RECP)))
		{
			REPORTERROR(eSecurity_KeyUnavailable, "No usable recipients for encryption");
		}

		// Key status
		else if (!::strncmp(q, cKEYEXPIRED, ::strlen(cKEYEXPIRED)))
		{
			mData->mExpiredKey = true;
		}
		else if (!::strncmp(q, cKEYREVOKED, ::strlen(cKEYREVOKED)))
		{
			mData->mRevokedKey = true;
		}

		// General errors
		else if (!::strncmp(q, cFAILURE, ::strlen(cFAILURE)))
		{
			LogEntry(cdstring(q));
		}
		else if (!::strncmp(q, cERROR, ::strlen(cERROR)))
		{
			LogEntry(cdstring(q));
		}
		else if (!::strncmp(q, cNODATA, ::strlen(cNODATA)))
		{
			LogEntry(cdstring(q));
		}

		// Look for next complete line
		p = ::strchr(status.c_str(), os_endl[0]);
	}

	return 1;
}

long CGPGPluginDLL::ProcessFileStatusOutput(cdstring& output)
{
	// Look for complete line
	const char* p = ::strchr(output.c_str(), os_endl[0]);
	while(p)
	{
		// Grab line and reset remainder
		cdstring line(output.c_str(), p - output.c_str());
		cdstring temp(p + os_endl_len);
		output = temp;

		// Look for specific text
		if (line.compare_start(":literal data packet:"))
			;
		else if (line.compare_start(":pubkey enc packet:"))
		{
			// Look for keyid
			char* q = ::strstr(line.c_str_mod(), "keyid ");
			if (q)
			{
				q += 6;
				char* r = ::strtok(q, " ");
				if (r)
				{
					mData->mEncryptionKeys.push_back(r);
				}
			}
		}
		else if (line.compare_start(":symkey enc packet:"))
			;
		else if (line.compare_start(":compressed packet:"))
			;
		else if (line.compare_start(":onepass_sig packet:"))
			;
		else if (line.compare_start(":signature packet:"))
		{
			// Look for keyid
			char* q = ::strstr(line.c_str_mod(), "keyid ");
			q += 6;
			char* r = ::strtok(q, " ");
			mData->mSignatureKeys.push_back(r);
		}

		p = ::strchr(output.c_str(), os_endl[0]);
	}

	return 1;
}

long CGPGPluginDLL::ProcessKeyListOutput(cdstring& output)
{
	// Parse --with-colons output format (stable across gpg versions)
	// Fields are colon-separated. Key record types:
	//   sec/pub: field 4 = key ID, field 1 = validity
	//   ssb/sub: field 4 = subkey ID
	//   uid:     field 9 = user ID string, field 1 = validity
	//   fpr:     field 9 = fingerprint

	const char* p = ::strchr(output.c_str(), os_endl[0]);
	while(p)
	{
		cdstring line(output.c_str(), p - output.c_str());
		cdstring temp(p + os_endl_len);
		output = temp;

		// Split line into colon-delimited fields
		cdstrvect fields;
		const char* start = line.c_str();
		while (start)
		{
			const char* colon = ::strchr(start, ':');
			if (colon)
			{
				fields.push_back(cdstring(start, colon - start));
				start = colon + 1;
			}
			else
			{
				fields.push_back(cdstring(start));
				break;
			}
		}

		if (fields.empty())
		{
			p = ::strchr(output.c_str(), os_endl[0]);
			continue;
		}

		const cdstring& type = fields[0];

		if ((type == "sec" || type == "pub") && fields.size() > 4)
		{
			mData->mLastID = fields[4];

			cdstrvect empty;
			mData->mKeyIDMap["current"] = empty;
			mData->mKeyIDMap[mData->mLastID] = empty;
		}
		else if ((type == "ssb" || type == "sub") && fields.size() > 4)
		{
			cdstring subid = fields[4];
			mData->mKeyIDMap[subid] = mData->mKeyIDMap["current"];
		}
		else if (type == "uid" && fields.size() > 9)
		{
			// field 1 = validity (r = revoked, skip)
			if (fields[1] == "r")
			{
				p = ::strchr(output.c_str(), os_endl[0]);
				continue;
			}

			cdstring name = fields[9];
			if (!name.empty())
			{
				mData->mKeyIDMap["current"].push_back(name);
				mData->mKeyIDMap[mData->mLastID].push_back(name);
			}
		}

		p = ::strchr(output.c_str(), os_endl[0]);
	}

	return 1;
}

// Check key health: expiry, revocation, UID match
bool CGPGPluginDLL::CheckKeyHealth(const char* key_id, cdstring& warning)
{
	if (!key_id || !*key_id)
		return true;

	cdstrvect args;
	args.push_back("--list-keys");
	args.push_back("--with-colons");
	args.push_back(key_id);

	mData->mStdError = cdstring::null_str;
	mData->mErrno = eSecurity_NoErr;
	long result = CallGPG(args, NULL, true, true);

	if (result != 1)
	{
		warning = "Signing key not found: ";
		warning += key_id;
		return false;
	}

	return true;
}

// Check which recipients have keys available
bool CGPGPluginDLL::CheckRecipientKeys(const char** recipients, cdstrvect& missing)
{
	if (!recipients)
		return true;

	const char** p = recipients;
	while(*p)
	{
		cdstrvect args;
		args.push_back("--list-keys");
		args.push_back("--with-colons");
		args.push_back(*p);

		mData->mStdError = cdstring::null_str;
		mData->mErrno = eSecurity_NoErr;
		long result = CallGPG(args, NULL, true, false);

		if (result != 1)
			missing.push_back(*p);

		p++;
	}

	return missing.empty();
}

// Export public key as ASCII-armored text
bool CGPGPluginDLL::ExportPublicKey(const char* key_id, cdstring& key_data)
{
	if (!key_id || !*key_id)
		return false;

	char out_tmp[1024];
	*out_tmp = 0;

	try
	{
		TempCreate(NULL, out_tmp, NULL);
	}
	catch(...)
	{
		return false;
	}

	if (!*out_tmp)
		return false;

	StRemoveFileSpec _remove_tmp(out_tmp);

	cdstrvect args;
	args.push_back("--export");
	args.push_back("--armor");
	args.push_back("-o");
	args.push_back(out_tmp);
	args.push_back(key_id);

	mData->mStdError = cdstring::null_str;
	mData->mErrno = eSecurity_NoErr;
	long result = CallGPG(args, NULL, true);

	if (result == 1)
	{
		char* data = NULL;
		unsigned long data_len = 0;
		TempRead(out_tmp, &data, &data_len);
		if (data)
		{
			key_data = data;
			::free(data);
			return true;
		}
	}

	return false;
}
