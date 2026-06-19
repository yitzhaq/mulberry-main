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


// Source for CPRECIS class
//
// RFC 8265 — PRECIS profiles for usernames and passwords
// RFC 8264 — PRECIS framework (derived property algorithm)
// RFC 5892 — IDNA code points (exceptions, contextual rules)
// RFC 5893 — Bidi Rule for right-to-left scripts

#include "CPRECIS.h"

#include <cstring>
#include <memory>
#include <stdexcept>

#include <uninorm.h>
#include <unicase.h>
#include <unictype.h>
#include <unistr.h>
#include <unitypes.h>

using namespace precis;

#pragma mark ____________________________Derived Property Algorithm

// RFC 8264 §8 — derived property algorithm
// RFC 5892 §2.6 — Exceptions table (F)
CPRECIS::EPRECISProperty CPRECIS::GetException(uint32_t cp)
{
	switch (cp)
	{
	// PVALID — would otherwise have been DISALLOWED
	case 0x00DF:	// LATIN SMALL LETTER SHARP S
	case 0x03C2:	// GREEK SMALL LETTER FINAL SIGMA
	case 0x06FD:	// ARABIC SIGN SINDHI AMPERSAND
	case 0x06FE:	// ARABIC SIGN SINDHI POSTPOSITION MEN
	case 0x0F0B:	// TIBETAN MARK INTERSYLLABIC TSHEG
	case 0x3007:	// IDEOGRAPHIC NUMBER ZERO
		return ePVALID;

	// CONTEXTO — would otherwise have been DISALLOWED
	case 0x00B7:	// MIDDLE DOT
	case 0x0375:	// GREEK LOWER NUMERAL SIGN (KERAIA)
	case 0x05F3:	// HEBREW PUNCTUATION GERESH
	case 0x05F4:	// HEBREW PUNCTUATION GERSHAYIM
	case 0x30FB:	// KATAKANA MIDDLE DOT
		return eCONTEXTO;

	// CONTEXTO — would otherwise have been PVALID
	case 0x0660: case 0x0661: case 0x0662: case 0x0663: case 0x0664:
	case 0x0665: case 0x0666: case 0x0667: case 0x0668: case 0x0669:
		return eCONTEXTO;
	case 0x06F0: case 0x06F1: case 0x06F2: case 0x06F3: case 0x06F4:
	case 0x06F5: case 0x06F6: case 0x06F7: case 0x06F8: case 0x06F9:
		return eCONTEXTO;

	// DISALLOWED — would otherwise have been PVALID
	case 0x0640:	// ARABIC TATWEEL
	case 0x07FA:	// NKO LAJANYALAN
	case 0x302E:	// HANGUL SINGLE DOT TONE MARK
	case 0x302F:	// HANGUL DOUBLE DOT TONE MARK
	case 0x3031:	// VERTICAL KANA REPEAT MARK
	case 0x3032:	// VERTICAL KANA REPEAT WITH VOICED SOUND MARK
	case 0x3033:	// VERTICAL KANA REPEAT MARK UPPER HALF
	case 0x3034:	// VERTICAL KANA REPEAT WITH VOICED SOUND MARK UPPER HALF
	case 0x3035:	// VERTICAL KANA REPEAT MARK LOWER HALF
	case 0x303B:	// VERTICAL IDEOGRAPHIC ITERATION MARK
		return eDISALLOWED;

	default:
		throw std::logic_error("PRECIS: GetException called for non-exception code point");
	}
}

// RFC 5892 §2.9 — OldHangulJamo (I)
// Hangul_Syllable_Type(cp) is in {L, V, T}
bool CPRECIS::IsOldHangulJamo(uint32_t cp)
{
	// Leading Jamo
	if (cp >= 0x1100 && cp <= 0x115F) return true;
	if (cp >= 0xA960 && cp <= 0xA97C) return true;

	// Vowel Jamo
	if (cp >= 0x1160 && cp <= 0x11A7) return true;
	if (cp >= 0xD7B0 && cp <= 0xD7C6) return true;

	// Trailing Jamo
	if (cp >= 0x11A8 && cp <= 0x11FF) return true;
	if (cp >= 0xD7CB && cp <= 0xD7FB) return true;

	return false;
}

// RFC 8264 §9.17 — HasCompat (Q): toNFKC(cp) != cp
bool CPRECIS::HasCompat(uint32_t cp)
{
	uint8_t src[5];
	int srclen = 0;

	// Encode cp as UTF-8
	if (cp < 0x80)
	{
		src[0] = static_cast<uint8_t>(cp);
		srclen = 1;
	}
	else if (cp < 0x800)
	{
		src[0] = static_cast<uint8_t>(0xC0 | (cp >> 6));
		src[1] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
		srclen = 2;
	}
	else if (cp < 0x10000)
	{
		src[0] = static_cast<uint8_t>(0xE0 | (cp >> 12));
		src[1] = static_cast<uint8_t>(0x80 | ((cp >> 6) & 0x3F));
		src[2] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
		srclen = 3;
	}
	else
	{
		src[0] = static_cast<uint8_t>(0xF0 | (cp >> 18));
		src[1] = static_cast<uint8_t>(0x80 | ((cp >> 12) & 0x3F));
		src[2] = static_cast<uint8_t>(0x80 | ((cp >> 6) & 0x3F));
		src[3] = static_cast<uint8_t>(0x80 | (cp & 0x3F));
		srclen = 4;
	}

	size_t result_len = 0;
	uint8_t* nfkc = u8_normalize(UNINORM_NFKC, src, srclen, NULL, &result_len);
	if (!nfkc)
		return false;

	bool compat = (result_len != static_cast<size_t>(srclen) ||
					std::memcmp(src, nfkc, srclen) != 0);
	free(nfkc);
	return compat;
}

// RFC 8264 §8 — main derived property algorithm
CPRECIS::EPRECISProperty CPRECIS::GetDerivedProperty(uint32_t cp)
{
	// Step 1: Exceptions (F) — RFC 5892 §2.6
	{
		bool is_exception = false;
		switch (cp)
		{
		case 0x00DF: case 0x03C2: case 0x06FD: case 0x06FE:
		case 0x0F0B: case 0x3007:
		case 0x00B7: case 0x0375: case 0x05F3: case 0x05F4: case 0x30FB:
		case 0x0660: case 0x0661: case 0x0662: case 0x0663: case 0x0664:
		case 0x0665: case 0x0666: case 0x0667: case 0x0668: case 0x0669:
		case 0x06F0: case 0x06F1: case 0x06F2: case 0x06F3: case 0x06F4:
		case 0x06F5: case 0x06F6: case 0x06F7: case 0x06F8: case 0x06F9:
		case 0x0640: case 0x07FA:
		case 0x302E: case 0x302F:
		case 0x3031: case 0x3032: case 0x3033: case 0x3034: case 0x3035:
		case 0x303B:
			is_exception = true;
			break;
		}
		if (is_exception)
			return GetException(cp);
	}

	// Step 2: BackwardCompatible (G) — currently empty per RFC 8264 §9.7
	// (no entries)

	// Step 3: Unassigned (J) — RFC 5892 §2.10
	if (uc_is_property_unassigned_code_value(cp))
		return eUNASSIGNED;

	// Step 4: ASCII7 (K) — RFC 8264 §9.11: cp in {0x0021..0x007E}
	if (cp >= 0x0021 && cp <= 0x007E)
		return ePVALID;

	// Step 5: JoinControl (H) — RFC 5892 §2.8
	if (cp == 0x200C || cp == 0x200D)
		return eCONTEXTJ;

	// Step 6: OldHangulJamo (I) — RFC 5892 §2.9
	if (IsOldHangulJamo(cp))
		return eDISALLOWED;

	// Step 7: PrecisIgnorableProperties (M) — RFC 8264 §9.13
	if (uc_is_property_default_ignorable_code_point(cp) ||
		uc_is_property_not_a_character(cp))
		return eDISALLOWED;

	// Step 8: Controls (L) — RFC 8264 §9.12: General_Category = Cc
	if (uc_is_general_category_withtable(cp, UC_CATEGORY_MASK_Cc))
		return eDISALLOWED;

	// Step 9: HasCompat (Q) — RFC 8264 §9.17: toNFKC(cp) != cp
	// Returns ID_DIS for IdentifierClass, FREE_PVAL for FreeformClass
	if (HasCompat(cp))
		return eFreePval;

	// Step 10: LetterDigits (A) — RFC 5892 §2.1 / RFC 8264 §9.1
	// General_Category in {Ll, Lu, Lt, Lm, Lo, Mn, Mc, Me, Nd, Nl, No}
	if (uc_is_general_category_withtable(cp,
		UC_CATEGORY_MASK_L | UC_CATEGORY_MASK_M |
		UC_CATEGORY_MASK_Nd | UC_CATEGORY_MASK_Nl | UC_CATEGORY_MASK_No))
		return ePVALID;

	// Step 11: OtherLetterDigits (R) — RFC 8264 §9.18
	// General_Category in {Lt, Nl, No, Me}
	// These overlap with LetterDigits, but the ones that reach here
	// are those not already caught above (none, but per spec order)
	if (uc_is_general_category_withtable(cp,
		UC_CATEGORY_MASK_Lt | UC_CATEGORY_MASK_Nl |
		UC_CATEGORY_MASK_No | UC_CATEGORY_MASK_Me))
		return eFreePval;

	// Step 12: Spaces (N) — RFC 8264 §9.14: General_Category = Zs
	if (uc_is_general_category_withtable(cp, UC_CATEGORY_MASK_Zs))
		return eFreePval;

	// Step 13: Symbols (O) — RFC 8264 §9.15
	// General_Category in {Sm, Sc, Sk, So}
	if (uc_is_general_category_withtable(cp, UC_CATEGORY_MASK_S))
		return eFreePval;

	// Step 14: Punctuation (P) — RFC 8264 §9.16
	// General_Category in {Pc, Pd, Ps, Pe, Pi, Pf, Po}
	if (uc_is_general_category_withtable(cp, UC_CATEGORY_MASK_P))
		return eFreePval;

	// Step 15: Everything else is DISALLOWED
	return eDISALLOWED;
}

#pragma mark ____________________________CONTEXTJ/CONTEXTO Validation

// RFC 5892 Appendix A.1 — ZERO WIDTH NON-JOINER (U+200C)
// RFC 5892 Appendix A.2 — ZERO WIDTH JOINER (U+200D)
bool CPRECIS::ValidateContextJ(const uint32_t* cps, size_t len, size_t pos)
{
	uint32_t cp = cps[pos];

	if (cp == 0x200C)
	{
		// Rule 1: If Canonical_Combining_Class(Before(cp)) == Virama Then True
		if (pos > 0 && uc_combining_class(cps[pos - 1]) == UC_CCC_VR)
			return true;

		// Rule 2: RegExpMatch for joining type context
		// (Joining_Type:{L,D})(Joining_Type:T)*‌(Joining_Type:T)*(Joining_Type:{R,D})
		bool found_left = false;
		for (size_t i = pos; i > 0; i--)
		{
			int jt = uc_joining_type(cps[i - 1]);
			if (jt == UC_JOINING_TYPE_T)
				continue;
			if (jt == UC_JOINING_TYPE_L || jt == UC_JOINING_TYPE_D)
			{
				found_left = true;
				break;
			}
			break;
		}
		if (found_left)
		{
			for (size_t i = pos + 1; i < len; i++)
			{
				int jt = uc_joining_type(cps[i]);
				if (jt == UC_JOINING_TYPE_T)
					continue;
				if (jt == UC_JOINING_TYPE_R || jt == UC_JOINING_TYPE_D)
					return true;
				break;
			}
		}
		return false;
	}

	if (cp == 0x200D)
	{
		// If Canonical_Combining_Class(Before(cp)) == Virama Then True
		if (pos > 0 && uc_combining_class(cps[pos - 1]) == UC_CCC_VR)
			return true;
		return false;
	}

	return false;
}

// RFC 5892 Appendix A.3–A.9 — CONTEXTO rules
bool CPRECIS::ValidateContextO(const uint32_t* cps, size_t len, size_t pos)
{
	uint32_t cp = cps[pos];

	// A.3: MIDDLE DOT (U+00B7)
	if (cp == 0x00B7)
	{
		return pos > 0 && pos < len - 1 &&
				cps[pos - 1] == 0x006C && cps[pos + 1] == 0x006C;
	}

	// A.4: GREEK LOWER NUMERAL SIGN (U+0375)
	if (cp == 0x0375)
	{
		if (pos >= len - 1)
			return false;
		const uc_script_t* greek = uc_script_byname("Greek");
		return greek && uc_is_script(cps[pos + 1], greek);
	}

	// A.5: HEBREW PUNCTUATION GERESH (U+05F3)
	if (cp == 0x05F3)
	{
		if (pos == 0)
			return false;
		const uc_script_t* hebrew = uc_script_byname("Hebrew");
		return hebrew && uc_is_script(cps[pos - 1], hebrew);
	}

	// A.6: HEBREW PUNCTUATION GERSHAYIM (U+05F4)
	if (cp == 0x05F4)
	{
		if (pos == 0)
			return false;
		const uc_script_t* hebrew = uc_script_byname("Hebrew");
		return hebrew && uc_is_script(cps[pos - 1], hebrew);
	}

	// A.7: KATAKANA MIDDLE DOT (U+30FB)
	if (cp == 0x30FB)
	{
		const uc_script_t* hiragana = uc_script_byname("Hiragana");
		const uc_script_t* katakana = uc_script_byname("Katakana");
		const uc_script_t* han = uc_script_byname("Han");
		for (size_t i = 0; i < len; i++)
		{
			if ((hiragana && uc_is_script(cps[i], hiragana)) ||
				(katakana && uc_is_script(cps[i], katakana)) ||
				(han && uc_is_script(cps[i], han)))
				return true;
		}
		return false;
	}

	// A.8: ARABIC-INDIC DIGITS (U+0660..U+0669)
	if (cp >= 0x0660 && cp <= 0x0669)
	{
		for (size_t i = 0; i < len; i++)
			if (cps[i] >= 0x06F0 && cps[i] <= 0x06F9)
				return false;
		return true;
	}

	// A.9: EXTENDED ARABIC-INDIC DIGITS (U+06F0..U+06F9)
	if (cp >= 0x06F0 && cp <= 0x06F9)
	{
		for (size_t i = 0; i < len; i++)
			if (cps[i] >= 0x0660 && cps[i] <= 0x0669)
				return false;
		return true;
	}

	return false;
}

#pragma mark ____________________________Class Validation

// Validate all code points against PRECIS IdentifierClass (RFC 8264 §4.2)
void CPRECIS::ValidateIdentifierClass(const uint32_t* cps, size_t len)
{
	for (size_t i = 0; i < len; i++)
	{
		EPRECISProperty prop = GetDerivedProperty(cps[i]);
		switch (prop)
		{
		case ePVALID:
			break;
		case eCONTEXTJ:
			if (!ValidateContextJ(cps, len, i))
				throw std::invalid_argument("PRECIS: invalid CONTEXTJ code point in username");
			break;
		case eCONTEXTO:
			if (!ValidateContextO(cps, len, i))
				throw std::invalid_argument("PRECIS: invalid CONTEXTO code point in username");
			break;
		case eFreePval:
			// FREE_PVAL = ID_DIS for IdentifierClass — disallowed
			throw std::invalid_argument("PRECIS: code point not allowed in IdentifierClass");
		case eDISALLOWED:
		case eUNASSIGNED:
			throw std::invalid_argument("PRECIS: disallowed code point in username");
		}
	}
}

// Validate all code points against PRECIS FreeformClass (RFC 8264 §4.3)
void CPRECIS::ValidateFreeformClass(const uint32_t* cps, size_t len)
{
	for (size_t i = 0; i < len; i++)
	{
		EPRECISProperty prop = GetDerivedProperty(cps[i]);
		switch (prop)
		{
		case ePVALID:
		case eFreePval:
			break;
		case eCONTEXTJ:
			if (!ValidateContextJ(cps, len, i))
				throw std::invalid_argument("PRECIS: invalid CONTEXTJ code point in password");
			break;
		case eCONTEXTO:
			if (!ValidateContextO(cps, len, i))
				throw std::invalid_argument("PRECIS: invalid CONTEXTO code point in password");
			break;
		case eDISALLOWED:
		case eUNASSIGNED:
			throw std::invalid_argument("PRECIS: disallowed code point in password");
		}
	}
}

#pragma mark ____________________________Bidi Rule

// RFC 5893 — Bidi Rule for strings containing RTL characters
bool CPRECIS::CheckBidiRule(const uint32_t* cps, size_t len)
{
	if (len == 0)
		return true;

	// Determine if string contains any RTL characters (R, AL, AN)
	bool has_rtl = false;
	for (size_t i = 0; i < len; i++)
	{
		int bc = uc_bidi_class(cps[i]);
		if (bc == UC_BIDI_R || bc == UC_BIDI_AL || bc == UC_BIDI_AN)
		{
			has_rtl = true;
			break;
		}
	}

	// RFC 8265 §3.3.1/§3.4.1: Bidi Rule applies only to strings
	// that contain right-to-left code points
	if (!has_rtl)
		return true;

	// RTL label rules:

	// Condition 1: first char must be R, AL, or AN
	int first_bc = uc_bidi_class(cps[0]);
	if (first_bc != UC_BIDI_R && first_bc != UC_BIDI_AL && first_bc != UC_BIDI_AN)
		return false;

	// Condition 2: last char must be R, AL, EN, or AN
	// (skip trailing NSM)
	size_t last = len - 1;
	while (last > 0 && uc_bidi_class(cps[last]) == UC_BIDI_NSM)
		last--;
	int last_bc = uc_bidi_class(cps[last]);
	if (last_bc != UC_BIDI_R && last_bc != UC_BIDI_AL &&
		last_bc != UC_BIDI_EN && last_bc != UC_BIDI_AN)
		return false;

	// Condition 3: all chars must be {R, AL, AN, EN, ES, CS, ET, ON, BN, NSM}
	bool has_en = false;
	bool has_an = false;
	for (size_t i = 0; i < len; i++)
	{
		int bc = uc_bidi_class(cps[i]);
		switch (bc)
		{
		case UC_BIDI_R:
		case UC_BIDI_AL:
		case UC_BIDI_AN:
			if (bc == UC_BIDI_AN) has_an = true;
			break;
		case UC_BIDI_EN:
			has_en = true;
			break;
		case UC_BIDI_ES:
		case UC_BIDI_CS:
		case UC_BIDI_ET:
		case UC_BIDI_ON:
		case UC_BIDI_BN:
		case UC_BIDI_NSM:
			break;
		default:
			return false;
		}
	}

	// Condition 4: EN and AN must not both be present
	if (has_en && has_an)
		return false;

	return true;
}

#pragma mark ____________________________Processing Steps

// Width mapping: map fullwidth/halfwidth to decomposition (RFC 8265 §3.3.1/§3.4.1)
cdstring CPRECIS::WidthMap(const cdstring& input)
{
	uint32_t* cps = NULL;
	size_t len = 0;
	UTF8ToUCS4(input, cps, len);
	std::unique_ptr<uint32_t[]> guard(cps);

	// Build output with width-mapped code points
	std::unique_ptr<uint32_t[]> out(new uint32_t[len * UC_DECOMPOSITION_MAX_LENGTH]);
	size_t out_len = 0;

	for (size_t i = 0; i < len; i++)
	{
		int decomp_tag = -1;
		uint32_t decomp[UC_DECOMPOSITION_MAX_LENGTH];
		int dlen = uc_decomposition(cps[i], &decomp_tag, decomp);

		if (dlen > 0 && (decomp_tag == UC_DECOMP_WIDE || decomp_tag == UC_DECOMP_NARROW))
		{
			for (int j = 0; j < dlen; j++)
				out[out_len++] = decomp[j];
		}
		else
		{
			out[out_len++] = cps[i];
		}
	}

	return UCS4ToUTF8(out.get(), out_len);
}

// Map non-ASCII space to SPACE (RFC 8265 §4.2.2 rule 2)
cdstring CPRECIS::MapNonASCIISpace(const cdstring& input)
{
	uint32_t* cps = NULL;
	size_t len = 0;
	UTF8ToUCS4(input, cps, len);
	std::unique_ptr<uint32_t[]> guard(cps);

	for (size_t i = 0; i < len; i++)
	{
		if (cps[i] != 0x0020 &&
			uc_is_general_category_withtable(cps[i], UC_CATEGORY_MASK_Zs))
		{
			cps[i] = 0x0020;
		}
	}

	return UCS4ToUTF8(cps, len);
}

// NFC normalization (RFC 8265 §3.3.1/§3.4.1/§4.2.2)
cdstring CPRECIS::NormalizeNFC(const cdstring& input)
{
	size_t result_len = 0;
	uint8_t* nfc = u8_normalize(UNINORM_NFC, reinterpret_cast<const uint8_t*>(input.c_str()),
								input.length(), NULL, &result_len);
	if (!nfc)
		throw std::runtime_error("PRECIS: NFC normalization failed");

	cdstring result(reinterpret_cast<const char*>(nfc), result_len);
	free(nfc);
	return result;
}

// Case mapping to lowercase (RFC 8265 §3.3.1 rule 3)
cdstring CPRECIS::CaseMapLower(const cdstring& input)
{
	size_t result_len = 0;
	uint8_t* lower = u8_tolower(reinterpret_cast<const uint8_t*>(input.c_str()),
								input.length(), NULL, UNINORM_NFC, NULL, &result_len);
	if (!lower)
		throw std::runtime_error("PRECIS: case mapping failed");

	cdstring result(reinterpret_cast<const char*>(lower), result_len);
	free(lower);
	return result;
}

#pragma mark ____________________________UTF-8 / UCS-4 Conversion

void CPRECIS::UTF8ToUCS4(const cdstring& input, uint32_t*& cps, size_t& len)
{
	const uint8_t* src = reinterpret_cast<const uint8_t*>(input.c_str());
	size_t src_len = input.length();

	// Allocate worst case (one cp per byte); hold it in a guard so a decode
	// error frees it instead of leaking before the caller takes ownership
	std::unique_ptr<uint32_t[]> buf(new uint32_t[src_len + 1]);
	len = 0;

	size_t i = 0;
	while (i < src_len)
	{
		uint32_t cp;
		int bytes;

		uint8_t c = src[i];
		if (c < 0x80)
		{
			cp = c;
			bytes = 1;
		}
		else if ((c & 0xE0) == 0xC0)
		{
			if (i + 1 >= src_len)
				throw std::invalid_argument("PRECIS: invalid UTF-8");
			cp = (c & 0x1F) << 6;
			cp |= (src[i + 1] & 0x3F);
			bytes = 2;
		}
		else if ((c & 0xF0) == 0xE0)
		{
			if (i + 2 >= src_len)
				throw std::invalid_argument("PRECIS: invalid UTF-8");
			cp = (c & 0x0F) << 12;
			cp |= (src[i + 1] & 0x3F) << 6;
			cp |= (src[i + 2] & 0x3F);
			bytes = 3;
		}
		else if ((c & 0xF8) == 0xF0)
		{
			if (i + 3 >= src_len)
				throw std::invalid_argument("PRECIS: invalid UTF-8");
			cp = (c & 0x07) << 18;
			cp |= (src[i + 1] & 0x3F) << 12;
			cp |= (src[i + 2] & 0x3F) << 6;
			cp |= (src[i + 3] & 0x3F);
			bytes = 4;
		}
		else
		{
			throw std::invalid_argument("PRECIS: invalid UTF-8");
		}

		buf[len++] = cp;
		i += bytes;
	}

	cps = buf.release();
}

cdstring CPRECIS::UCS4ToUTF8(const uint32_t* cps, size_t len)
{
	// Allocate worst case (4 bytes per cp)
	std::unique_ptr<char[]> buf(new char[len * 4 + 1]);
	size_t out = 0;

	for (size_t i = 0; i < len; i++)
	{
		uint32_t cp = cps[i];
		if (cp < 0x80)
		{
			buf[out++] = static_cast<char>(cp);
		}
		else if (cp < 0x800)
		{
			buf[out++] = static_cast<char>(0xC0 | (cp >> 6));
			buf[out++] = static_cast<char>(0x80 | (cp & 0x3F));
		}
		else if (cp < 0x10000)
		{
			buf[out++] = static_cast<char>(0xE0 | (cp >> 12));
			buf[out++] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
			buf[out++] = static_cast<char>(0x80 | (cp & 0x3F));
		}
		else
		{
			buf[out++] = static_cast<char>(0xF0 | (cp >> 18));
			buf[out++] = static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
			buf[out++] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
			buf[out++] = static_cast<char>(0x80 | (cp & 0x3F));
		}
	}
	buf[out] = '\0';

	return cdstring(buf.get(), out);
}

#pragma mark ____________________________Profile Enforcement

// RFC 8265 §3.4 — UsernameCasePreserved profile
cdstring CPRECIS::EnforceUsernameCasePreserved(const cdstring& input)
{
	cdstring result = input;

	// Idempotency loop (RFC 8264 §7 SHOULD)
	for (int attempt = 0; attempt < 4; attempt++)
	{
		// Step 1: Width mapping (§3.4.2)
		cdstring mapped = WidthMap(result);

		// Step 2: Validate IdentifierClass (§3.4.2)
		{
			uint32_t* cps = NULL;
			size_t len = 0;
			UTF8ToUCS4(mapped, cps, len);
			std::unique_ptr<uint32_t[]> guard(cps);
			ValidateIdentifierClass(cps, len);
		}

		// Step 3: NFC normalization (§3.4.3)
		cdstring normalized = NormalizeNFC(mapped);

		// Step 4: Bidi Rule (§3.4.3)
		{
			uint32_t* cps = NULL;
			size_t len = 0;
			UTF8ToUCS4(normalized, cps, len);
			std::unique_ptr<uint32_t[]> guard(cps);
			if (len > 0 && !CheckBidiRule(cps, len))
				throw std::invalid_argument("PRECIS: username violates Bidi Rule");
		}

		// Step 5: Non-empty check (§3.4.3)
		if (normalized.empty())
			throw std::invalid_argument("PRECIS: username is empty after enforcement");

		// Check if stable
		if (normalized == result)
			return result;

		result = normalized;
	}

	throw std::invalid_argument("PRECIS: username did not stabilize after enforcement");
}

// RFC 8265 §3.3 — UsernameCaseMapped profile
cdstring CPRECIS::EnforceUsernameCaseMapped(const cdstring& input)
{
	cdstring result = input;

	for (int attempt = 0; attempt < 4; attempt++)
	{
		// Step 1: Width mapping (§3.3.2)
		cdstring mapped = WidthMap(result);

		// Step 2: Validate IdentifierClass (§3.3.2)
		{
			uint32_t* cps = NULL;
			size_t len = 0;
			UTF8ToUCS4(mapped, cps, len);
			std::unique_ptr<uint32_t[]> guard(cps);
			ValidateIdentifierClass(cps, len);
		}

		// Step 3: Case mapping (§3.3.3)
		cdstring lowered = CaseMapLower(mapped);

		// Step 4: NFC normalization (§3.3.3)
		cdstring normalized = NormalizeNFC(lowered);

		// Step 5: Bidi Rule (§3.3.3)
		{
			uint32_t* cps = NULL;
			size_t len = 0;
			UTF8ToUCS4(normalized, cps, len);
			std::unique_ptr<uint32_t[]> guard(cps);
			if (len > 0 && !CheckBidiRule(cps, len))
				throw std::invalid_argument("PRECIS: username violates Bidi Rule");
		}

		// Step 6: Non-empty check (§3.3.3)
		if (normalized.empty())
			throw std::invalid_argument("PRECIS: username is empty after enforcement");

		if (normalized == result)
			return result;

		result = normalized;
	}

	throw std::invalid_argument("PRECIS: username did not stabilize after enforcement");
}

// RFC 8265 §4.2 — OpaqueString profile
cdstring CPRECIS::EnforceOpaqueString(const cdstring& input)
{
	cdstring result = input;

	for (int attempt = 0; attempt < 4; attempt++)
	{
		// Step 1: Validate FreeformClass (§4.2.1)
		{
			uint32_t* cps = NULL;
			size_t len = 0;
			UTF8ToUCS4(result, cps, len);
			std::unique_ptr<uint32_t[]> guard(cps);
			ValidateFreeformClass(cps, len);
		}

		// Step 2: Width mapping — MUST NOT map (§4.2.2 rule 1)
		// (no operation)

		// Step 3: Map non-ASCII space to U+0020 (§4.2.2 rule 2)
		cdstring mapped = MapNonASCIISpace(result);

		// Step 4: No case mapping (§4.2.2 rule 3)
		// (no operation)

		// Step 5: NFC normalization (§4.2.2 rule 4)
		cdstring normalized = NormalizeNFC(mapped);

		// Step 6: No directionality rule (§4.2.2 rule 5)
		// (no operation)

		// Step 7: Non-empty check (§4.1)
		if (normalized.empty())
			throw std::invalid_argument("PRECIS: password is empty after enforcement");

		if (normalized == result)
			return result;

		result = normalized;
	}

	throw std::invalid_argument("PRECIS: password did not stabilize after enforcement");
}
