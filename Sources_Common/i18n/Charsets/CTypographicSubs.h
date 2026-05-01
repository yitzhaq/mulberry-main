/*
    Copyright (c) 2026 Mulberry contributors. All rights reserved.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0
*/

// CTypographicSubs.h — transparent ASCII substitutions for
// Unicode typographic characters
//
// These are rendered without any wrapping — curly quotes become
// straight quotes, en dashes become hyphens, etc. The user sees
// the ASCII equivalent as if it were the original character.
//
// Sorted by codepoint for binary search. Pure ASCII only.

#ifndef __CTYPOGRAPHICSUBS__MULBERRY__
#define __CTYPOGRAPHICSUBS__MULBERRY__

#include <stdint.h>
#include <stddef.h>

struct STypographicSub
{
	uint32_t	codepoint;
	const char*	text;
};

static const STypographicSub cTypographicSubs[] = {
	{ 0x02BC, "'" },             // modifier letter apostrophe
	{ 0x2002, " " },             // en space
	{ 0x2003, " " },             // em space
	{ 0x2004, " " },             // three-per-em space
	{ 0x2005, " " },             // four-per-em space
	{ 0x2006, " " },             // six-per-em space
	{ 0x2007, " " },             // figure space
	{ 0x2008, " " },             // punctuation space
	{ 0x2009, " " },             // thin space
	{ 0x200A, " " },             // hair space
	{ 0x2010, "-" },             // hyphen
	{ 0x2011, "-" },             // non-breaking hyphen
	{ 0x2012, "-" },             // figure dash
	{ 0x2013, "-" },             // en dash
	{ 0x2014, "--" },            // em dash
	{ 0x2015, "--" },            // horizontal bar
	{ 0x2016, "||" },            // double vertical line
	{ 0x2018, "'" },             // left single quotation mark
	{ 0x2019, "'" },             // right single quotation mark
	{ 0x201A, "," },             // single low-9 quotation mark
	{ 0x201B, "'" },             // single high-reversed-9 quotation mark
	{ 0x201C, "\"" },            // left double quotation mark
	{ 0x201D, "\"" },            // right double quotation mark
	{ 0x201E, ",," },            // double low-9 quotation mark
	{ 0x201F, "\"" },            // double high-reversed-9 quotation mark
	{ 0x2022, "*" },             // bullet
	{ 0x2023, ">" },             // triangular bullet
	{ 0x2026, "..." },           // horizontal ellipsis
	{ 0x2027, "-" },             // hyphenation point
	{ 0x202F, " " },             // narrow no-break space
	{ 0x2032, "'" },             // prime
	{ 0x2033, "\"" },            // double prime
	{ 0x2039, "<" },             // single left-pointing angle quotation mark
	{ 0x203A, ">" },             // single right-pointing angle quotation mark
	{ 0x2044, "/" },             // fraction slash
	{ 0x204A, "&" },             // tironian sign et
	{ 0x205F, " " },             // medium mathematical space
	{ 0x2116, "No." },           // numero sign
	{ 0x2120, "SM" },            // service mark
	{ 0x2122, "TM" },            // trade mark sign
	{ 0x2212, "-" },             // minus sign
	{ 0x2217, "*" },             // asterisk operator
	{ 0x221E, "oo" },            // infinity
	{ 0x2248, "~=" },            // almost equal to
	{ 0x2260, "!=" },            // not equal to
	{ 0x2264, "<=" },            // less-than or equal to
	{ 0x2265, ">=" },            // greater-than or equal to
	{ 0x2713, "v" },             // check mark
	{ 0x2714, "v" },             // heavy check mark
	{ 0x2717, "x" },             // ballot x
	{ 0x2718, "x" },             // heavy ballot x
	{ 0x25CF, "*" },             // black circle
	{ 0x2800, " " },             // braille blank pattern
	{ 0x3000, " " },             // ideographic space
};

static const size_t cTypographicSubsSize = sizeof(cTypographicSubs) / sizeof(STypographicSub);

#endif
