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


// Quota Support

#ifndef __CQUOTAS__MULBERRY__
#define __CQUOTAS__MULBERRY__

#include "cdstring.h"

#include <cstdint>
#include <vector>

// Typedefs
class CQuotaItem;
class CQuotaRoot;
typedef std::vector<CQuotaItem> CQuotaItemList;
typedef std::vector<CQuotaRoot> CQuotaRootList;

// CQuotaItem: contains specific quota item

class CQuotaItem
{
public:
	CQuotaItem()
		{ mCurrent = 0; mMax = 0; }
	explicit CQuotaItem(const char* txt1,
				const char* txt2,
				const char* txt3);				// Construct from text
	CQuotaItem(const CQuotaItem& copy);			// Copy construct
	
	~CQuotaItem() {}

	CQuotaItem& operator=(const CQuotaItem& copy);		// Assignment with same type
	int operator==(const CQuotaItem& test) const		// Compare with same type
		{ return (mItem == test.GetItem()); }			// Just compare names

	void SetItem(const char* txt)
		{ mItem = txt; }
	const cdstring GetItem() const
		{ return mItem; }

	void SetCurrent(int64_t current)
		{ mCurrent = current; }
	int64_t GetCurrent() const
		{ return mCurrent; }

	void SetMax(int64_t max)
		{ mMax = max; }
	int64_t GetMax() const
		{ return mMax; }

private:
	cdstring	mItem;					// Description of item
	int64_t		mCurrent;				// Current usage (RFC 9208: 63-bit)
	int64_t		mMax;					// Maximum allowed usage
};

// CQuotaRoot: contains list of quota items

class CQuotaRoot
{
public:
	CQuotaRoot() {}
	CQuotaRoot(const char* txt)					// Construct with name
		{ mName = txt; }
	CQuotaRoot(const CQuotaRoot& copy);			// Copy construct
	
	~CQuotaRoot() {}

	CQuotaRoot& operator=(const CQuotaRoot& copy);		// Assignment with same type
	int operator==(const CQuotaRoot& test) const		// Compare with same type
		{ return (mName == test.GetName()); }			// Just compare names
	int operator!=(const CQuotaRoot& test) const		// Compare with same type
		{ return !operator==(test); }					// Just compare names

	const cdstring& GetName() const
		{ return mName; }

	const CQuotaItemList& GetItems() const
		{ return mItems; }

	void ParseList(const char* txt);	// Parse list of items from server

private:
	cdstring		mName;				// Name of root
	CQuotaItemList	mItems;				// List of items
};

#endif
