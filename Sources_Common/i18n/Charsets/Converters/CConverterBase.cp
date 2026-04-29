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


// Source for CConverterBase class

#include "CConverterBase.h"

#if __dest_os != __win32_os
#include "CUnicodeFilter.h"
#include "CTypographicSubs.h"
#include "CSmileySubs.h"
#include "CEmojiTable.h"
#include <string.h>

static const char* LookupTypographic(wchar_t wc)
{
	size_t lo = 0, hi = cTypographicSubsSize;
	while (lo < hi)
	{
		size_t mid = lo + (hi - lo) / 2;
		if (cTypographicSubs[mid].codepoint < (uint32_t)wc)
			lo = mid + 1;
		else if (cTypographicSubs[mid].codepoint > (uint32_t)wc)
			hi = mid;
		else
			return cTypographicSubs[mid].text;
	}
	return NULL;
}

using namespace i18n;

static const char* LookupSmiley(wchar_t wc)
{
	size_t lo = 0, hi = cSmileySubsSize;
	while (lo < hi)
	{
		size_t mid = lo + (hi - lo) / 2;
		if (cSmileySubs[mid].codepoint < (uint32_t)wc)
			lo = mid + 1;
		else if (cSmileySubs[mid].codepoint > (uint32_t)wc)
			hi = mid;
		else
			return cSmileySubs[mid].text;
	}
	return NULL;
}

static const char* LookupEmoji(wchar_t wc, const unsigned char*& p,
	const unsigned char* q, CConverterBase* conv)
{
	uint32_t first = (uint32_t)wc;

	// Find range of entries starting with this codepoint
	size_t lo = 0, hi = cEmojiTableSize;
	while (lo < hi)
	{
		size_t mid = lo + (hi - lo) / 2;
		if (cEmojiTable[mid].codepoints[0] < first)
			lo = mid + 1;
		else if (cEmojiTable[mid].codepoints[0] > first)
			hi = mid;
		else
		{
			// Found a match on first codepoint — scan for longest sequence
			size_t start = mid;
			while (start > 0 && cEmojiTable[start - 1].codepoints[0] == first)
				start--;
			size_t end = mid + 1;
			while (end < cEmojiTableSize && cEmojiTable[end].codepoints[0] == first)
				end++;

			// Try longest sequences first
			for (size_t i = start; i < end; i++)
			{
				if (cEmojiTable[i].length == 1)
					return cEmojiTable[i].name;

				// Try multi-codepoint match
				const unsigned char* save_p = p;
				bool match = true;
				for (uint8_t j = 1; j < cEmojiTable[i].length; j++)
				{
					if (save_p >= q)
					{
						match = false;
						break;
					}
					wchar_t next = conv->c_2_w(save_p);
					if ((uint32_t)next != cEmojiTable[i].codepoints[j])
					{
						match = false;
						break;
					}
				}
				if (match && cEmojiTable[i].length > 1)
				{
					p = save_p;
					return cEmojiTable[i].name;
				}
			}

			// Fall back to single-codepoint match
			for (size_t i = start; i < end; i++)
			{
				if (cEmojiTable[i].length == 1)
					return cEmojiTable[i].name;
			}
			return NULL;
		}
	}
	return NULL;
}

static void OutputWChar(std::ostream& wout, char c)
{
#ifdef big_endian
	wout.put('\0');
	wout.put(c);
#else
	wout.put(c);
	wout.put('\0');
#endif
}

static void OutputSubstitution(const char* sub, std::ostream& wout,
	char open, char close)
{
	if (open)
		OutputWChar(wout, open);
	for (const char* s = sub; *s; s++)
		OutputWChar(wout, *s);
	if (close)
		OutputWChar(wout, close);
}
#endif

using namespace i18n;

char CConverterBase::undefined_charmap = '?';		// Undefined mapping character
wchar_t CConverterBase::undefined_wcharmap = L'?';	// Undefined mapping character

void CConverterBase::ToUnicode(const char* str, size_t len, std::ostream& wout)
{
	// Must have valid input
	if (!str)
		return;

	// Convert each character
	const unsigned char* p = reinterpret_cast<const unsigned char*>(str);
	const unsigned char* q = p + len;
	while(p < q)
	{
		wchar_t wc = c_2_w(p);
#ifdef big_endian
		wout.put(wc >> 8);
		wout.put(wc & 0x00FF);
#else
		wout.put(wc & 0x00FF);
		wout.put(wc >> 8);
#endif
	}
}

void CConverterBase::FromUnicode(const wchar_t* wstr, size_t wlen, std::ostream& out)
{
	// Must have valid input
	if (!wstr)
		return;

	// Initialise the converter
	init_w_2_c(out);

	// Convert each character
	const wchar_t* p = wstr;
	const wchar_t* q = p + wlen;
	while(p < q)
	{
		char bout[32];
		int len = w_2_c(*p++, bout);
		for(int i = 0; i < len; i++)
			out.put(bout[i]);
	}

	// Finalise the converter
	finish_w_2_c(out);
}

void CConverterBase::ToUTF16(const char* str, size_t len, std::ostream& wout)
{
	// Must have valid input
	if (!str)
		return;

	// Convert each character
	const unsigned char* p = reinterpret_cast<const unsigned char*>(str);
	const unsigned char* q = p + len;
	while(p < q)
	{
		wchar_t wc = c_2_w(p);
		if (wc < 0x100)
		{
			// Latin-1 — render natively
#ifdef big_endian
			wout.put((wc & 0xFF00) >> 8);
			wout.put(wc & 0x00FF);
#else
			wout.put(wc & 0x00FF);
			wout.put((wc & 0xFF00) >> 8);
#endif
		}
		else if (wc > 0x10FFFF)
		{
			// Invalid codepoint
#ifdef big_endian
			wout.put('\0');
			wout.put('?');
#else
			wout.put('?');
			wout.put('\0');
#endif
		}
#if __dest_os == __win32_os
		else if (wc < 0x10000)
		{
			// BMP non-Latin-1 — Windows can render natively
			wout.put(wc & 0x00FF);
			wout.put((wc & 0xFF00) >> 8);
		}
		else
		{
			// Above BMP — surrogate pair for Windows
			wc -= (wchar_t)0x10000;
			wchar_t wc1 = 0xD800 | ((wc & 0x000FFC00) >> 10);
			wchar_t wc2 = 0xDC00 | (wc & 0x000003FF);
			wout.put(wc1 & 0x00FF);
			wout.put((wc1 & 0xFF00) >> 8);
			wout.put(wc2 & 0x00FF);
			wout.put((wc2 & 0xFF00) >> 8);
		}
#else
		else
		{
			// Non-Latin-1 on Linux/Mac — text substitution

			if (IsZeroWidthSeparator(wc))
			{
				OutputWChar(wout, ' ');
				continue;
			}
			if (IsInvisibleUnicode(wc))
				continue;

			// Mathematical styled letters → plain ASCII
			char mathc = MathLetterToAscii(wc);
			if (mathc)
			{
				OutputWChar(wout, mathc);
				continue;
			}

			// Transparent typographic substitutions (no wrapping)
			const char* sub = LookupTypographic(wc);
			if (sub)
			{
				OutputSubstitution(sub, wout, 0, 0);
			}
			// Smiley emoticons [wrapped in brackets]
			else if ((sub = LookupSmiley(wc)) != NULL)
			{
				OutputSubstitution(sub, wout, '[', ']');
			}
			else
			{
				sub = LookupEmoji(wc, p, q, this);
				if (sub)
				{
					OutputWChar(wout, '[');
					OutputSubstitution(sub, wout, ':', ':');
					OutputWChar(wout, ']');
				}
				else
				{
					char hex[14];
					snprintf(hex, sizeof(hex), "U+%04lX", (unsigned long)wc);
					OutputSubstitution(hex, wout, '[', ']');
				}
			}
		}
#endif
	}
}

void CConverterBase::FromUTF16(const unsigned short* str, size_t ulen, std::ostream& out)
{
	// Must have valid input
	if (!str)
		return;

	// Convert each character
	const unsigned short* p = str;
	unsigned long charlen = 0;
	wchar_t wc = 0;
	while(*p)
	{
		if (charlen == 0)
		{
			// Look for mbcs ranges
			if ((*p < 0xD800) || (*p > 0xDFFF))
			{
				charlen = 1;
				wc = *p;
			}
			else if (*p < 0xDC00)
			{
				// Must be valid
				charlen = 2;
				wc = (*p & 0x03FF) << 10;
			}
			else
			{
				// Sequence error
				charlen = 1;
				wc = '?';
			}
		}
		else
		{
			// Must be valid
			if ((*p >= 0xDC00) && (*p <= 0xDFFF))
			{
				wc |= (*p & 0x03FF);
			}
			else
				wc = '?';
		}
		
		// Bump ptr
		p++;
		
		// Reduce byte remaining count and write it out if done
		if (!--charlen)
		{
			char bout[32];
			int len = w_2_c(wc, bout);
			for(int i = 0; i < len; i++)
				out.put(bout[i]);
		}
	}
}

void CConverterBase::ToUTF8(const char* str, size_t len, std::ostream& out)
{
	// Must have valid input
	if (!str)
		return;

	// Convert each character
	const unsigned char* p = reinterpret_cast<const unsigned char*>(str);
	const unsigned char* q = p + len;
	while(p < q)
	{
		wchar_t wp = c_2_w(p);
		if (wp < 0x80)
		{
			// Write 1 to buffer
			unsigned char c = wp;
			out.put(c);
		}
		else if (wp < 0x800)
		{
			// Write 2 to buffer
			unsigned char c = 0xc0 | (wp >> 6);
			out.put(c);

			c = 0x80 | (wp & 0x3f);
			out.put(c);
		}
		else // if (wp < 0x10000)
		{
			// Write 3 to buffer
			unsigned char c = 0xe0 | (wp >> 12);
			out.put(c);

			c = 0x80 | ((wp >> 6) & 0x3f);
			out.put(c);

			c = 0x80 | (wp & 0x3f);
			out.put(c);
		}
	}
}

void CConverterBase::FromUTF8(const char* str, size_t len, std::ostream& out)
{
	// Must have valid input
	if (!str)
		return;

	// Convert each character
	const char* p = str;
	unsigned long charlen = 0;
	wchar_t wc = 0;
	while(*p)
	{
		unsigned char mask = 0x3f;
		if (charlen == 0)
		{
			// Determine length of utf8 encoded wchar_t
			if ((*p & 0xf0 ) == 0xe0)
			{
				charlen = 3;
				mask = 0x0f;
			}
			else if ((*p & 0xe0 ) == 0xc0)
			{
				charlen = 2;
				mask = 0x1f;
			}
			else
			{
				charlen = 1;
				mask = 0x7f;
			}

			// Reset char
			wc = 0;
		}

		// Convert the byte
		wc <<= 6;
		wc |= (*p & mask);
		
		// Bump ptr
		p++;
		
		// Reduce byte remaining count and write it out if done
		if (!--charlen)
		{
			char bout[32];
			int len = w_2_c(wc, bout);
			for(int i = 0; i < len; i++)
				out.put(bout[i]);
		}
	}
}

void CConverterBase::init_w_2_c(std::ostream& out)
{
}

void CConverterBase::finish_w_2_c(std::ostream& out)
{
}
