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

// CSCRAMSHA256PluginDLL.cp
//
// SCRAM-SHA-256 authentication plugin for Mulberry (RFC 7677).

#include "CSCRAMSHA256PluginDLL.h"
#include "CPluginInfo.h"

#include <openssl/evp.h>
#include <string.h>

#pragma mark ____________________________consts

const char* cPluginName = "SCRAM-SHA-256 Plugin";
const CPluginDLL::EPluginType cPluginType = CPluginDLL::ePluginNetworkAuthentication;
const char* cPluginDescription = "SCRAM-SHA-256 authentication plugin for Mulberry (RFC 7677)." COPYRIGHT;
const char* cPluginAuthenticateID = "SCRAM-SHA-256";
const char* cPluginPrefsDescriptor = "SCRAM-SHA-256";

#pragma mark ____________________________CSCRAMSHA256PluginDLL

CSCRAMSHA256PluginDLL::CSCRAMSHA256PluginDLL()
	: CSCRAMPluginDLL(EVP_sha256(), 32)
{
}

CSCRAMSHA256PluginDLL::~CSCRAMSHA256PluginDLL()
{
}

void CSCRAMSHA256PluginDLL::Initialise(void)
{
	CAuthPluginDLL::Initialise();

	::strncpy(mAuthInfo.mAuthTypeID, cPluginAuthenticateID, 255);
	mAuthInfo.mAuthTypeID[255] = 0;
	::strncpy(mAuthInfo.mPrefsDescriptor, cPluginPrefsDescriptor, 255);
	mAuthInfo.mPrefsDescriptor[255] = 0;
	mAuthInfo.mAuthUIType = eAuthUserPswd;
}

bool CSCRAMSHA256PluginDLL::UseRegistration(unsigned long* key)
{
	if (key)
		*key = ('Mlby' | 'SC26');
	return false;
}

bool CSCRAMSHA256PluginDLL::CanDemo(void)
{
	return false;
}

const char* CSCRAMSHA256PluginDLL::GetName(void) const
{
	return cPluginName;
}

long CSCRAMSHA256PluginDLL::GetVersion(void) const
{
	return cPluginVersion;
}

CPluginDLL::EPluginType CSCRAMSHA256PluginDLL::GetType(void) const
{
	return cPluginType;
}

const char* CSCRAMSHA256PluginDLL::GetManufacturer(void) const
{
	return cPluginManufacturer;
}

const char* CSCRAMSHA256PluginDLL::GetDescription(void) const
{
	return cPluginDescription;
}
