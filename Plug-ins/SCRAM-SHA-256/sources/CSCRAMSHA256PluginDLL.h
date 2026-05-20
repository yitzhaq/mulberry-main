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

// CSCRAMSHA256PluginDLL.h
//
// SCRAM-SHA-256 authentication plugin for Mulberry (RFC 7677).

#ifndef __SCRAMSHA256_PLUGIN_MULBERRY__
#define __SCRAMSHA256_PLUGIN_MULBERRY__

#include "CSCRAMPluginDLL.h"

class CSCRAMSHA256PluginDLL : public CSCRAMPluginDLL
{
public:

	CSCRAMSHA256PluginDLL();
	virtual ~CSCRAMSHA256PluginDLL();

	virtual void	Initialise(void);

	virtual bool UseRegistration(unsigned long* key);
	virtual bool CanDemo(void);

protected:
	virtual const char* GetName(void) const;
	virtual long GetVersion(void) const;
	virtual EPluginType GetType(void) const;
	virtual const char* GetManufacturer(void) const;
	virtual const char* GetDescription(void) const;
};

#endif
