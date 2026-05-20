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


// Class to implement a 64-bit flag

#ifndef __SBITFLAGS__MULBERRY__
#define __SBITFLAGS__MULBERRY__

#include <cstdint>

struct SBitFlags
{
	SBitFlags()
		{ mFlags = 0; }
	SBitFlags(const SBitFlags& copy)
		{ mFlags = copy.mFlags; }
	SBitFlags(uint64_t flags)
		{ mFlags = flags; }
	~SBitFlags() {}

	SBitFlags& operator=(const SBitFlags& copy)	// Assignment with same type
		{ if (this != &copy) mFlags = copy.mFlags; return *this; }
	SBitFlags& operator=(uint64_t flags)	// Assignment with flags
		{ mFlags = flags; return *this; }

	bool IsSet(uint64_t flag) const
		{ return (mFlags & flag) == flag; }
	bool IsUnset(uint64_t flag) const
		{ return (mFlags & flag) == 0; }
	void Set(uint64_t flag, bool add = true)
		{ mFlags  = (add ? (mFlags | flag) : (mFlags & ~flag)); }

	uint64_t Get() const
		{ return mFlags; }

private:
	uint64_t mFlags;
};

#endif
