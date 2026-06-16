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

// CSCRAMSHA1PluginDLL.cpp
//
// SCRAM-SHA-1 authentication plugin for Mulberry (RFC 5802).

#include "CSCRAMSHA1PluginDLL.h"
#include "CPluginInfo.h"

#include <openssl/evp.h>
#include <string.h>

#pragma mark ____________________________consts

const char* cPluginName = "SCRAM-SHA-1 Plugin";
const CPluginDLL::EPluginType cPluginType = CPluginDLL::ePluginNetworkAuthentication;
const char* cPluginDescription = "SCRAM-SHA-1 authentication plugin for Mulberry (RFC 5802)." COPYRIGHT;
const char* cPluginAuthenticateID = "SCRAM-SHA-1";
const char* cPluginPrefsDescriptor = "SCRAM-SHA-1";

#pragma mark ____________________________CSCRAMSHA1PluginDLL

CSCRAMSHA1PluginDLL::CSCRAMSHA1PluginDLL()
	: CSCRAMPluginDLL(EVP_sha1(), 20)
{
}

CSCRAMSHA1PluginDLL::~CSCRAMSHA1PluginDLL()
{
}

void CSCRAMSHA1PluginDLL::Initialise(void)
{
	CAuthPluginDLL::Initialise();

	::strncpy(mAuthInfo.mAuthTypeID, cPluginAuthenticateID, 255);
	mAuthInfo.mAuthTypeID[255] = 0;
	::strncpy(mAuthInfo.mPrefsDescriptor, cPluginPrefsDescriptor, 255);
	mAuthInfo.mPrefsDescriptor[255] = 0;
	mAuthInfo.mAuthUIType = eAuthUserPswd;
}

bool CSCRAMSHA1PluginDLL::UseRegistration(unsigned long* key)
{
	if (key)
		*key = ('Mlby' | 'SCR1');
	return false;
}

bool CSCRAMSHA1PluginDLL::CanDemo(void)
{
	return false;
}

const char* CSCRAMSHA1PluginDLL::GetName(void) const
{
	return cPluginName;
}

long CSCRAMSHA1PluginDLL::GetVersion(void) const
{
	return cPluginVersion;
}

CPluginDLL::EPluginType CSCRAMSHA1PluginDLL::GetType(void) const
{
	return cPluginType;
}

const char* CSCRAMSHA1PluginDLL::GetManufacturer(void) const
{
	return cPluginManufacturer;
}

const char* CSCRAMSHA1PluginDLL::GetDescription(void) const
{
	return cPluginDescription;
}
