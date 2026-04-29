/*
    Copyright (c) 2026 Mulberry contributors. All rights reserved.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0
*/

// CUnicodeFilter.h — shared Unicode character classification
//
// Used by CConverterBase (charset conversion) and CParserHTML
// (HTML entity decoding) to consistently handle non-Latin-1
// characters across all rendering paths.

#ifndef __CUNICODEFILTER__MULBERRY__
#define __CUNICODEFILTER__MULBERRY__

#include <stdint.h>

// Characters that should be replaced with a space (zero-width
// separators that provide visual separation between emoji)
inline bool IsZeroWidthSeparator(wchar_t wc)
{
	return (wc >= 0x200B && wc <= 0x200D) ||    // ZWS, ZWNJ, ZWJ
		   wc == 0x2060;                         // word joiner
}

// Characters that should be silently dropped (invisible formatting)
inline bool IsInvisibleUnicode(wchar_t wc)
{
	return wc == 0x00AD ||                       // soft hyphen
		   (wc >= 0x200E && wc <= 0x200F) ||    // bidi marks
		   (wc >= 0x202A && wc <= 0x202E) ||    // bidi embeddings
		   (wc >= 0x2061 && wc <= 0x2069) ||    // invisible operators, bidi isolates
		   (wc >= 0x0300 && wc <= 0x036F) ||    // combining diacritical marks
		   wc == 0xFE0E || wc == 0xFE0F ||      // variation selectors
		   wc == 0xFEFF;                         // BOM / ZWNBSP
}

// Characters that can be rendered natively by JX (Latin-1)
// Excludes soft hyphen (U+00AD) which is an invisible hint
inline bool IsLatin1(wchar_t wc)
{
	return wc < 0x100 && wc != 0x00AD;
}

// Characters above the maximum valid Unicode codepoint
inline bool IsInvalidUnicode(wchar_t wc)
{
	return wc > 0x10FFFF;
}

// Mathematical styled letter → plain ASCII equivalent
// Covers bold, italic, script, fraktur, double-struck,
// sans-serif, and monospace variants of A-Z and a-z
inline char MathLetterToAscii(wchar_t wc)
{
	struct Range { uint32_t start; char base; };
	static const Range ranges[] = {
		{ 0x1D400, 'A' }, { 0x1D41A, 'a' },  // bold
		{ 0x1D434, 'A' }, { 0x1D44E, 'a' },  // italic
		{ 0x1D468, 'A' }, { 0x1D482, 'a' },  // bold italic
		{ 0x1D49C, 'A' }, { 0x1D4B6, 'a' },  // script
		{ 0x1D4D0, 'A' }, { 0x1D4EA, 'a' },  // bold script
		{ 0x1D504, 'A' }, { 0x1D51E, 'a' },  // fraktur
		{ 0x1D538, 'A' }, { 0x1D552, 'a' },  // double-struck
		{ 0x1D56C, 'A' }, { 0x1D586, 'a' },  // bold fraktur
		{ 0x1D5A0, 'A' }, { 0x1D5BA, 'a' },  // sans-serif
		{ 0x1D5D4, 'A' }, { 0x1D5EE, 'a' },  // sans-serif bold
		{ 0x1D608, 'A' }, { 0x1D622, 'a' },  // sans-serif italic
		{ 0x1D63C, 'A' }, { 0x1D656, 'a' },  // sans-serif bold italic
		{ 0x1D670, 'A' }, { 0x1D68A, 'a' },  // monospace
	};
	for (unsigned i = 0; i < sizeof(ranges)/sizeof(ranges[0]); i++)
	{
		uint32_t offset = (uint32_t)wc - ranges[i].start;
		if (offset < 26)
			return ranges[i].base + offset;
	}
	return 0;
}

#endif
