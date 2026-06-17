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

// CSecurityPlugin.cpp
//
// Copyright 2006, Cyrus Daboo.  All Rights Reserved.
//
// Created: 04-May-1998
// Author: Cyrus Daboo
// Platforms: Mac OS, Win32
//
// Description:
// This class implements a wrapper for DLL based security plug-ins in Mulberry.
//
// History:
// CD:	 04-May-1998:	Created initial header and implementation.
//

//#define VISIBLE_TEMP_FILES

#include "CSecurityPlugin.h"

#include "CAddressList.h"
#include "CAttachment.h"
#include "CAttachmentList.h"
#include "CCertificateManager.h"
#include "CDataAttachment.h"
#include "CErrorHandler.h"
#include "CFileAttachment.h"
#include "CGeneralException.h"
#include "CGetPassphraseDialog.h"
#include "CLocalAttachment.h"
#include "CLocalCommon.h"
#include "CLocalMessage.h"
#include "CMailControl.h"
#include "CMbox.h"
#include "CMessage.h"
#include "CMessageWindow.h"
#include "CMulberryApp.h"
#include "CMulberryCommon.h"
#include "CNetworkException.h"
#include "CPluginManager.h"
#include "CPreferences.h"
#include "CPreferenceVersions.h"
#include "CRFC822.h"
#include "CRFC822Parser.h"
#include "CSSLPlugin.h"
#include "CStreamAttachment.h"
#include "CStreamFilter.h"
#include "CStreamType.h"
#include "CStreamUtils.h"
#if __dest_os == __mac_os || __dest_os == __mac_os_x
#include "CStringResources.h"
#endif
#include "CStringUtils.h"
#include "CTextListChoice.h"
#include "CUtils.h"

#include "mimefilters.h"
#include "cdfstream.h"

#if __dest_os == __mac_os_x
#include "MyCFString.h"
#include <SysCFURL.h>
#endif

#include <algorithm>
#include <strstream>
#include <typeinfo>

CSecurityPlugin::SSecurityPluginHandlers CSecurityPlugin::sSecurityPlugins;
cdstring CSecurityPlugin::sPreferredPlugin;
cdstrmap CSecurityPlugin::sCanVerify;
cdstrmap CSecurityPlugin::sCanDecrypt;

cdstrmap CSecurityPlugin::sPassphrases;
cdstring CSecurityPlugin::sLastPassphraseUID;

const unsigned long cFileThreshold = 0x10000;

const char* cGPGName = "GPG Plugin";
const char* cPGPName = "PGP Plugin";
const char* cSMIMEName = "SMIME Plugin";

// Register a security plugin
void CSecurityPlugin::RegisterSecurityPlugin(CSecurityPlugin* plugin)
{
	// Add it to the list
	sSecurityPlugins.insert(SSecurityPluginHandlers::value_type(plugin->GetName(), plugin));
}

CSecurityPlugin* CSecurityPlugin::GetRegisteredPlugin(const cdstring& descriptor)
{
	SSecurityPluginHandlers::const_iterator found = sSecurityPlugins.find(descriptor);
	if (found != sSecurityPlugins.end())
		return (*found).second;
	else
		return NULL;
}

// Plugin used for sign/encrypt operations
CSecurityPlugin* CSecurityPlugin::GetDefaultPlugin()
{
	// Prompt user to choose if no preferred item and more than one is loaded
	if ((sSecurityPlugins.size() > 1) && CPreferences::sPrefs->mPreferredPlugin.GetValue().empty())
	{
		// Get list of available plugins
		cdstrvect plugins;
		for(SSecurityPluginHandlers::const_iterator iter = sSecurityPlugins.begin(); iter != sSecurityPlugins.end(); iter++)
			plugins.push_back((*iter).first);
		
		// Allow user to choose the one they want
		ulvector selected;
		if (CTextListChoice::PoseDialog("Alerts::General::ChooseCryptoPluginTitle", NULL, NULL, false, true, false, true, plugins, cdstring::null_str, selected, NULL))
		{
			// Save the choice in the preferences
			CPreferences::sPrefs->mPreferredPlugin.SetValue(plugins.at(selected.front()));
		}
		else
		{
			CLOG_LOGTHROW(CGeneralException, -1);
			throw CGeneralException(-1);
		}
	}

	// Now try to find the appropriate plugin
	CSecurityPlugin* plugin = NULL;
	if (sSecurityPlugins.size() > 1)
	{
		// Look for one that matches the chosen name
		plugin = GetRegisteredPlugin(CPreferences::sPrefs->mPreferredPlugin.GetValue());
		
		if (plugin == NULL)
		{
			// Use alternate PGP/GPG depending on what is present
			if (CPreferences::sPrefs->mPreferredPlugin.GetValue() == cGPGName)
				plugin = GetRegisteredPlugin(cPGPName);
			else if (CPreferences::sPrefs->mPreferredPlugin.GetValue() == cPGPName)
				plugin = GetRegisteredPlugin(cGPGName);
		}
	}

	// Just use the first one in the list
	if (!plugin && sSecurityPlugins.size())
		plugin = sSecurityPlugins.begin()->second;

	return plugin;
}

// Make sure version matches
bool CSecurityPlugin::VerifyVersion() const
{
	// New API >= 3.1b5
	if (VersionTest(GetVersion(), VERS_3_1_0_B_5) >= 0)
		return true;
	else
	{
		CErrorHandler::PutStopAlertRsrcStr("Alerts::General::IllegalPluginCryptoVersion", GetName().c_str());
		return false;
	}
}

// Load information
void CSecurityPlugin::LoadPlugin()
{
	// Do inherited then set callback if all OK
	CPlugin::LoadPlugin();
	SetCallback();
	if (GetName() == cSMIMEName)
		SetContext();
}

#pragma mark ____________________________High Level

bool CSecurityPlugin::ProcessMessage(CMessage* msg, ESecureMessage mode, const char* key)
{
	// Only bother if something actually required
	if (mode == eNone)
		return true;

	// Cannot sign without key
	if (((mode == eSign) || (mode == eEncryptSign)) &&
		(!key || !*key))
		return false;

	// Load plugin
	StLoadPlugin load(this);

	bool result = false;
	while(true)
	{
		long err = 0;

		try
		{
			if (UseMIME())
				ProcessBody(msg, mode, key);
			else
				// Sign each part
				ProcessAttachment(msg, msg->GetBody(), mode, key);

			result = true;
		}
		catch (...)
		{
			CLOG_LOGCATCH(...);

			err = HandleError();
			result = false;
		}
		
		// Try it again if error was bad passphrase
		if (result || (err != eSecurity_BadPassphrase))
			break;
	}

	return result;

}

#if __dest_os == __mac_os || __dest_os == __mac_os_x
void CSecurityPlugin::CreateTempFile(PPx::FSObject* ftemp, ESecureMessage mode, const cdstring& name)
#else
void CSecurityPlugin::CreateTempFile(cdstring& ftemp, ESecureMessage mode, const cdstring& name)
#endif
{
	// Generate a suitable name
	cdstring new_name = name;
	if (new_name.empty())
	{
		static unsigned long sCtr = 0;
		
		new_name.reserve(L_tmpnam);
		::snprintf(new_name.c_str_mod(), L_tmpnam, "Temp_%lx%03ld", ::time(NULL), sCtr++ % 256);
	}
	switch(mode)
	{
	case eSign:
		new_name += ".sig";
		break;
	case eEncrypt:
	case eEncryptSign:
		new_name += ".asc";
		break;
	default:
		new_name += ".tmp";
	}

#if __dest_os == __mac_os || __dest_os == __mac_os_x
	::TempFileSpecSecurity(*ftemp, new_name);
	
	// Must create the file on Mac OS to ensure file path conversion will work
	LFile fileTemp(*ftemp);
	fileTemp.CreateNewFile('Mlby', 'SECR', smCurrentScript);
	ftemp->Update();
#else
	::TempFileSpecSecurity(ftemp, new_name);
#endif
}

void CSecurityPlugin::ApplyMIME(CAttachment* part, SMIMEInfo* info)
{
	// Add content type
	if (info->type)
		part->GetContent().SetContentType(info->type);
	
	// Add content subtype
	if (info->subtype)
		part->GetContent().SetContentSubtype(info->subtype);
	
	// Add parameters
	const char** p = info->params;
	while(p && *p)
	{
		const char* name = *p++;
		const char* value = *p++;
		if (name && *name && value && *value)
			part->GetContent().SetContentParameter(name, value);
	}
}

bool CSecurityPlugin::DoesEncryptSignAllInOne() const
{
	return GetName() != cSMIMEName;
}

bool CSecurityPlugin::UseMIME() const
{
	return (GetName() == cSMIMEName) || CPreferences::sPrefs->mUseMIMESecurity.GetValue();
}

#pragma mark ____________________________Whitespace stripping

// RFC 3156 §5 step 4: strip trailing spaces/tabs from each line before signing
void CSecurityPlugin::StripTrailingWhitespace(cdstring& data)
{
	if (data.empty())
		return;

	const char* src = data.c_str();
	size_t len = data.length();
	cdstring result;
	result.reserve(len);

	const char* line_start = src;
	const char* end = src + len;

	while (src < end)
	{
		if (*src == '\r' && src + 1 < end && *(src + 1) == '\n')
		{
			const char* p = src;
			while (p > line_start && (*(p - 1) == ' ' || *(p - 1) == '\t'))
				p--;
			result += cdstring(line_start, p - line_start);
			result += "\r\n";
			src += 2;
			line_start = src;
		}
		else if (*src == '\n')
		{
			const char* p = src;
			while (p > line_start && (*(p - 1) == ' ' || *(p - 1) == '\t'))
				p--;
			result += cdstring(line_start, p - line_start);
			result += "\n";
			src++;
			line_start = src;
		}
		else
		{
			src++;
		}
	}

	if (src > line_start)
	{
		const char* p = src;
		while (p > line_start && (*(p - 1) == ' ' || *(p - 1) == '\t'))
			p--;
		result += cdstring(line_start, p - line_start);
	}

	data = result;
}

void CSecurityPlugin::StripTrailingWhitespaceFile(const cdstring& path)
{
	cdstring data;
	{
		cdifstream in(path, std::ios_base::in | std::ios_base::binary);
		if (!in.is_open())
			return;
		std::ostrstream buf;
		buf << in.rdbuf();
		buf << std::ends;
		data.steal(buf.str());
	}

	StripTrailingWhitespace(data);

	{
		cdofstream out(path, std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
		out.write(data.c_str(), data.length());
	}
}

#pragma mark ____________________________Header protection (RFC 9788)

// RFC 9788 §3.2.1: hcp_baseline
cdstring CSecurityPlugin::ApplyHCP(const cdstring& name, const cdstring& value)
{
	if (!::strcmpnocase(name, "Subject"))
		return "[...]";
	if (!::strcmpnocase(name, "Comments") || !::strcmpnocase(name, "Keywords"))
		return cdstring::null_str;
	return value;
}

// Collect user-facing headers from message envelope
void CSecurityPlugin::GetUserFacingHeaders(const CMessage* msg, cdstrpairvect& headers)
{
	if (!msg || !msg->GetEnvelope())
		return;

	const CEnvelope* env = msg->GetEnvelope();

	// Date
	cdstring date_text = env->GetTextDate(false);
	if (!date_text.empty())
		headers.push_back(cdstrpair("Date", date_text));

	// From
	if (env->GetFrom() && env->GetFrom()->size())
	{
		std::ostrstream buf;
		env->GetFrom()->WriteToStream(buf);
		buf << std::ends;
		cdstring from;
		from.steal(buf.str());
		headers.push_back(cdstrpair("From", from));
	}

	// To
	if (env->GetTo() && env->GetTo()->size())
	{
		std::ostrstream buf;
		env->GetTo()->WriteToStream(buf);
		buf << std::ends;
		cdstring to;
		to.steal(buf.str());
		headers.push_back(cdstrpair("To", to));
	}

	// Cc
	if (env->GetCC() && env->GetCC()->size())
	{
		std::ostrstream buf;
		env->GetCC()->WriteToStream(buf);
		buf << std::ends;
		cdstring cc;
		cc.steal(buf.str());
		headers.push_back(cdstrpair("Cc", cc));
	}

	// Reply-To
	if (env->GetReplyTo() && env->GetReplyTo()->size())
	{
		std::ostrstream buf;
		env->GetReplyTo()->WriteToStream(buf);
		buf << std::ends;
		cdstring reply_to;
		reply_to.steal(buf.str());
		headers.push_back(cdstrpair("Reply-To", reply_to));
	}

	// Subject
	if (!env->GetSubject().empty())
		headers.push_back(cdstrpair("Subject", env->GetSubject()));

	// Message-ID
	if (!env->GetMessageID().empty())
		headers.push_back(cdstrpair("Message-ID", env->GetMessageID()));
}

// Insert protected headers into MIME data before the header/body separator
void CSecurityPlugin::InsertProtectedHeaders(cdstring& data, const cdstrpairvect& headers,
												const cdstrpairvect* hp_outer)
{
	if (headers.empty() && (!hp_outer || hp_outer->empty()))
		return;

	// Find the first CRLFCRLF (header/body separator)
	const char* sep = ::strstr(data.c_str(), "\r\n\r\n");
	if (!sep)
		return;

	size_t insert_pos = sep - data.c_str() + 2;

	cdstring insert_text;

	// Add user-facing headers
	for (cdstrpairvect::const_iterator iter = headers.begin(); iter != headers.end(); iter++)
	{
		insert_text += iter->first;
		insert_text += ": ";
		insert_text += iter->second;
		insert_text += "\r\n";
	}

	// Add HP-Outer headers
	if (hp_outer)
	{
		for (cdstrpairvect::const_iterator iter = hp_outer->begin(); iter != hp_outer->end(); iter++)
		{
			insert_text += cHDR_HP_OUTER;
			insert_text += iter->first;
			insert_text += ": ";
			insert_text += iter->second;
			insert_text += "\r\n";
		}
	}

	cdstring result(data.c_str(), insert_pos);
	result += insert_text;
	result += cdstring(data.c_str() + insert_pos);
	data = result;
}

void CSecurityPlugin::InsertProtectedHeadersFile(const cdstring& path, const cdstrpairvect& headers,
													const cdstrpairvect* hp_outer)
{
	cdstring data;
	{
		cdifstream in(path, std::ios_base::in | std::ios_base::binary);
		if (!in.is_open())
			return;
		std::ostrstream buf;
		buf << in.rdbuf();
		buf << std::ends;
		data.steal(buf.str());
	}

	InsertProtectedHeaders(data, headers, hp_outer);

	{
		cdofstream out(path, std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
		out.write(data.c_str(), data.length());
	}
}

// Extract a header value from raw MIME text (before the blank line)
static cdstring ExtractHeaderFromRaw(const char* data, const char* header_name)
{
	if (!data || !header_name)
		return cdstring::null_str;

	size_t name_len = ::strlen(header_name);
	const char* p = data;

	while (*p)
	{
		// Check for blank line (end of headers)
		if (*p == '\r' && *(p + 1) == '\n' && *(p + 2) == '\r' && *(p + 3) == '\n')
			break;
		if (*p == '\n' && *(p + 1) == '\n')
			break;

		// Check for matching header name (case-insensitive)
		if (::strncasecmp(p, header_name, name_len) == 0 && *(p + name_len) == ':')
		{
			const char* val = p + name_len + 1;
			while (*val == ' ' || *val == '\t')
				val++;

			// Find end of value (handle continuation lines)
			const char* end = val;
			while (*end)
			{
				if (*end == '\r' && *(end + 1) == '\n')
				{
					if (*(end + 2) == ' ' || *(end + 2) == '\t')
						end += 2;
					else
						break;
				}
				else if (*end == '\n')
				{
					if (*(end + 1) == ' ' || *(end + 1) == '\t')
						end++;
					else
						break;
				}
				else
					end++;
			}

			return cdstring(val, end - val);
		}

		// Skip to next line
		while (*p && *p != '\n')
			p++;
		if (*p == '\n')
			p++;
	}

	return cdstring::null_str;
}

// Extract protected headers from Cryptographic Payload on receive side
void CSecurityPlugin::ExtractProtectedHeaders(const CAttachment* payload, const CMessage* msg,
												CMessageCryptoInfo& info,
												const char* raw_data)
{
	if (!payload || !msg || !msg->GetEnvelope())
		return;

	// Check for hp parameter on Cryptographic Payload
	const cdstring& hp = payload->GetContent().GetContentParameter(cMIMEParameter[eHP]);
	if (hp.empty())
		return;

	bool is_encrypted = !::strcmpnocase(hp, "cipher");

	info.SetHeadersProtected(true);
	info.SetHeadersEncrypted(is_encrypted);

	// Extract and compare protected header values if raw data is available
	if (raw_data)
	{
		const CEnvelope* env = msg->GetEnvelope();

		cdstring inner_subject = ExtractHeaderFromRaw(raw_data, "Subject");
		cdstring inner_from = ExtractHeaderFromRaw(raw_data, "From");
		cdstring inner_to = ExtractHeaderFromRaw(raw_data, "To");
		cdstring inner_cc = ExtractHeaderFromRaw(raw_data, "Cc");
		cdstring inner_date = ExtractHeaderFromRaw(raw_data, "Date");
		cdstring inner_replyto = ExtractHeaderFromRaw(raw_data, "Reply-To");

		// Compare each with outer headers
		if (!inner_subject.empty() && env->GetSubject() != inner_subject)
			info.GetHeaderMismatches().insert(cdstrmap::value_type("Subject", inner_subject));

		if (!inner_from.empty())
		{
			CAddress inner_addr(inner_from);
			CAddress outer_addr(env->GetFrom()->size() ? env->GetFrom()->front()->GetMailAddress() : cdstring::null_str);
			if (::strcmpnocase(inner_addr.GetMailAddress(), outer_addr.GetMailAddress()) != 0)
			{
				info.SetFromMismatch(true);
				info.GetHeaderMismatches().insert(cdstrmap::value_type("From", inner_from));
			}
		}

		if (!inner_to.empty())
		{
			cdstring outer_to;
			if (env->GetTo() && env->GetTo()->size())
				outer_to = env->GetTo()->front()->GetMailAddress();
			if (::strcmpnocase(inner_to, outer_to) != 0)
				info.GetHeaderMismatches().insert(cdstrmap::value_type("To", inner_to));
		}

		if (!inner_cc.empty())
		{
			cdstring outer_cc;
			if (env->GetCC() && env->GetCC()->size())
				outer_cc = env->GetCC()->front()->GetMailAddress();
			if (::strcmpnocase(inner_cc, outer_cc) != 0)
				info.GetHeaderMismatches().insert(cdstrmap::value_type("Cc", inner_cc));
		}

		if (!inner_date.empty())
		{
			cdstring outer_date = env->GetTextDate(true, false);
			if (::strcmpnocase(inner_date, outer_date) != 0)
				info.GetHeaderMismatches().insert(cdstrmap::value_type("Date", inner_date));
		}

		if (!inner_replyto.empty())
		{
			cdstring outer_replyto;
			if (env->GetReplyTo() && env->GetReplyTo()->size())
				outer_replyto = env->GetReplyTo()->front()->GetMailAddress();
			if (::strcmpnocase(inner_replyto, outer_replyto) != 0)
				info.GetHeaderMismatches().insert(cdstrmap::value_type("Reply-To", inner_replyto));
		}
	}
}

#pragma mark ____________________________Operations on entire body

void CSecurityPlugin::ProcessBody(CMessage* msg, ESecureMessage mode, const char* key)
{
	// RFC 9787 §5.3: encrypt-only is not permitted — always sign when encrypting
	if (mode == eEncrypt)
		mode = eEncryptSign;

	// Special processing for Encrypt&Sign separate
	if ((mode == eEncryptSign) && !DoesEncryptSignAllInOne())
	{
		// Do signature first
		ProcessBody(msg, eSign, key);

		// Change mode to encrypt for second operation
		mode = eEncrypt;
	}

	// Sign entire message
	CAttachment* part = msg->GetBody();
	if (!part)
		return;
	CAttachment* generated_part = NULL;

	// Special processing for crypto - only needed for broken PGP implementations
	part->ProcessSendCrypto(mode, true);

	// RFC 9788: set hp parameter and collect headers for protection
	cdstrpairvect protected_headers;
	cdstrpairvect hp_outer_headers;
	bool do_header_protection = (mode == eSign || mode == eEncryptSign);
	if (do_header_protection)
	{
		GetUserFacingHeaders(msg, protected_headers);

		if (mode == eSign)
		{
			part->GetContent().SetContentParameter(cMIMEParameter[eHP], "clear");
		}
		else
		{
			part->GetContent().SetContentParameter(cMIMEParameter[eHP], "cipher");

			// Build HP-Outer: protected copy of what the outer headers will be after HCP
			for (cdstrpairvect::const_iterator iter = protected_headers.begin();
				 iter != protected_headers.end(); iter++)
			{
				cdstring hcp_val = ApplyHCP(iter->first, iter->second);
				if (!hcp_val.empty())
					hp_outer_headers.push_back(cdstrpair(iter->first, hcp_val));
			}

			// RFC 9788 §5.2.1 step 2: build Legacy Display list (headers changed by HCP)
			cdstrpairvect ldlist;
			for (cdstrpairvect::const_iterator iter = protected_headers.begin();
				 iter != protected_headers.end(); iter++)
			{
				cdstring hcp_val = ApplyHCP(iter->first, iter->second);
				if (hcp_val != iter->second)
					ldlist.push_back(*iter);
			}

			// Insert Legacy Display Elements into text body parts
			if (!ldlist.empty())
			{
				cdstring ld_text;
				for (cdstrpairvect::const_iterator iter = ldlist.begin();
					 iter != ldlist.end(); iter++)
				{
					ld_text += iter->first;
					ld_text += ": ";
					ld_text += iter->second;
					ld_text += os_endl;
				}
				ld_text += os_endl;

				// Walk leaf parts and prepend to text/plain main body parts
				CAttachment* main_part = part;
				if (main_part->IsMultipart() && main_part->GetParts())
					main_part = main_part->GetParts()->front();

				if (main_part && main_part->IsText() && main_part->GetData())
				{
					EContentSubType sub = main_part->GetContent().GetContentSubtype();
					if (sub == eContentSubPlain)
					{
						cdstring new_data = ld_text;
						new_data += main_part->GetData();
						char* copy = new char[new_data.length() + 1];
						::memcpy(copy, new_data.c_str(), new_data.length() + 1);
						main_part->SetData(copy);
						main_part->GetContent().SetContentParameter(
							cMIMEParameter[eHPLegacyDisplay], "1");
					}
					else if (sub == eContentSubHTML)
					{
						cdstring html_ld = "<div class=\"legacy-display\">\r\n";
						for (cdstrpairvect::const_iterator iter = ldlist.begin();
							 iter != ldlist.end(); iter++)
						{
							html_ld += "<b>";
							html_ld += iter->first;
							html_ld += "</b>: ";
							html_ld += iter->second;
							html_ld += "<br>\r\n";
						}
						html_ld += "<hr>\r\n</div>\r\n";

						cdstring orig(main_part->GetData());
						const char* body_tag = ::strstr(orig.c_str(), "<body");
						if (!body_tag)
							body_tag = ::strstr(orig.c_str(), "<BODY");

						cdstring new_data;
						if (body_tag)
						{
							const char* after = ::strchr(body_tag, '>');
							if (after)
							{
								after++;
								new_data = cdstring(orig.c_str(), after - orig.c_str());
								new_data += html_ld;
								new_data += after;
							}
						}

						if (new_data.empty())
						{
							new_data = html_ld;
							new_data += orig;
						}

						char* copy = new char[new_data.length() + 1];
						::memcpy(copy, new_data.c_str(), new_data.length() + 1);
						main_part->SetData(copy);
						main_part->GetContent().SetContentParameter(
							cMIMEParameter[eHPLegacyDisplay], "1");
					}
				}
			}
		}
	}

	unsigned long size = 0;
	if (FileBody(part, size))
	{
#if __dest_os == __mac_os || __dest_os == __mac_os_x

		// Create temporary input file
		PPx::FSObject fs_fin;
		PPx::FSObject* fin = &fs_fin;
		CreateTempFile(fin, mode, cdstring::null_str);
		StRemoveFileSpec _remove_fin(fin);

		cdstring fin_path(fin->GetPath());

		// Create temporary output file
		PPx::FSObject fs_fout;
		PPx::FSObject* fout = &fs_fout;
		CreateTempFile(fout, mode, cdstring::null_str);
		StRemoveFileSpec _remove_fout(fout);
		PPx::CFURL fout_url = fout->GetURL();
#else 
		cdstring fin;
		CreateTempFile(fin, mode, cdstring::null_str);
		StRemoveFileSpec _remove_fin(fin);
		cdstring fin_path = fin;

		cdstring fout;
		CreateTempFile(fout, mode, cdstring::null_str);
		StRemoveFileSpec _remove_fout(fout);
#endif

		// Write it to a stream — use CRLF for signing (RFC 3156 §5 step 1)
		{
			cdofstream outs(fin_path, std::ios_base::out|std::ios_base::trunc|std::ios_base::binary);
			unsigned long level = 0;
			EEndl sign_endl = (mode == eSign || mode == eEncryptSign) ? eEndl_CRLF : lendl;
			costream stream_out(&outs, sign_endl);
			part->WriteToStream(stream_out, level, false, nil);
		}

		// For encryption: insert protected headers and strip whitespace
		// in the temp file (the temp file IS the encrypted payload)
		// For signing: the temp file must match the transmitted part exactly,
		// so modifications go on the part object (hp=clear already set above),
		// and gpg -t handles whitespace canonicalization
		if (mode != eSign)
		{
			if (do_header_protection && !protected_headers.empty())
				InsertProtectedHeadersFile(fin_path, protected_headers,
					(mode == eEncryptSign) ? &hp_outer_headers : NULL);
			if (mode == eEncryptSign)
				StripTrailingWhitespaceFile(fin_path);
		}

		// Now process file
		Process(msg, mode, NULL, fin, key, NULL, fout, NULL, true, false);

		// Create part containing PGP data - this takes ownership of the temp file
#if __dest_os == __mac_os || __dest_os == __mac_os_x
		*fout = PPx::FSObject(fout_url);
		generated_part = new CFileAttachment(*fout);
#else
		generated_part = new CFileAttachment(fout);
#endif
		static_cast<CFileAttachment*>(generated_part)->SetDeleteFile(true);

		// Always NULL the file name to prevent temp file names leaking into MIME parameters
		generated_part->GetContent().SetMappedName(cdstring::null_str);

		// Make sure output file is not deleted via stack remove
		_remove_fout.release();
	}
	else
	{
		cdstring data;

		// Write it to a stream — use CRLF for signing (RFC 3156 §5 step 1)
		{
			std::ostrstream outs;
			unsigned long level = 0;
			EEndl sign_endl = (mode == eSign || mode == eEncryptSign) ? eEndl_CRLF : lendl;
			costream stream_out(&outs, sign_endl);
			part->WriteToStream(stream_out, level, false, nil);
			outs << std::ends;
			data.steal(outs.str());
		}

		// For encryption: insert protected headers and strip whitespace
		// For signing: data must match the transmitted part exactly
		if (mode != eSign)
		{
			if (do_header_protection && !protected_headers.empty())
				InsertProtectedHeaders(data, protected_headers,
					(mode == eEncryptSign) ? &hp_outer_headers : NULL);
			if (mode == eEncryptSign)
				StripTrailingWhitespace(data);
		}

		char* out = nil;
		unsigned long out_len = 0;
		Process(msg, mode, data, NULL, key, &out, NULL, &out_len, true, false);

		// Make a copy of the data
		char* local = new char[out_len + 1];
		if (out != NULL)
			::memcpy(local, out, out_len);
		local[out_len] = 0;

		DisposeData(out);

		// Create part containg PGP data
		generated_part = new CDataAttachment;
		generated_part->SetData(local);
	}

	// Now pocess into PGP/MIME

	// Get appropriate MIME params
	SMIMEMultiInfo mime;
	switch(mode)
	{
	case eSign:
		GetMIMESign(&mime);
		break;
	case eEncrypt:
		GetMIMEEncrypt(&mime);
		break;
	case eEncryptSign:
		GetMIMEEncryptSign(&mime);
		break;
	default:;
	}
	
	// Determine whether multipart format can be used
	bool use_multi_part = !::strcmpnocase(mime.multipart.type, "multipart");

	// Process PGP data part
	ApplyMIME(generated_part, &mime.second);
	
	// The content in the generated part is already transfer encoded so we must
	// not re-apply the encoding
	generated_part->GetContent().SetDontEncode();

	// Create actual message structure
	if (use_multi_part)
	{
		// Create the top-level multipart
		CAttachment* multi_part = new CAttachment;
		ApplyMIME(multi_part, &mime.multipart);

		// Give it to the message
		msg->SetBody(multi_part, false);

		// Now add subparts to top part
		switch(mode)
		{
		case eSign:
			// multipart/signed
			// 	type/subtype
			//	application/pgp-signature
			multi_part->AddPart(part);
			multi_part->AddPart(generated_part);

			// Interop: help MUAs that lack PGP/MIME-aware rendering
			generated_part->GetContent().SetContentParameter("name", "OpenPGP_signature.asc");
			generated_part->GetContent().SetContentDescription("OpenPGP digital signature");
			generated_part->GetContent().SetContentDisposition(eContentDispositionAttachment);
			generated_part->GetContent().SetMappedName("OpenPGP_signature.asc");
			break;
		case eEncrypt:
		case eEncryptSign:
			{
				// multipart/encrypted
				// 	application/pgp-encrypted
				//	application/octet-stream

				// Delete original part
				delete part;

				// Create new encryption part
				CDataAttachment* version_part = new CDataAttachment;
				ApplyMIME(version_part, &mime.first);

				version_part->GetContent().SetContentDescription("PGP/MIME version identification");

				cdstring temp("Version: 1");
				temp += os_endl;
				version_part->SetData(temp.grab_c_str());

				// Add the parts now
				multi_part->AddPart(version_part);
				multi_part->AddPart(generated_part);

				// Interop: help MUAs that lack PGP/MIME-aware rendering
				generated_part->GetContent().SetContentParameter("name", "encrypted.asc");
				generated_part->GetContent().SetContentDescription("OpenPGP encrypted message");
				generated_part->GetContent().SetContentDisposition(eContentDispositionInline);
				generated_part->GetContent().SetMappedName("encrypted.asc");

				// NB last part must be set to CTE of 7bit
				generated_part->GetContent().SetTransferEncoding(e7bitEncoding);
			}
			break;
		default:;
		}
	}
	else
	{
		// Delete original part
		delete part;

		// Give new generated part to the message
		msg->SetBody(generated_part, false);
	}

	// RFC 9788 §5.2.1 step 5: apply HCP to outer message headers for encrypted messages
	if (do_header_protection && (mode == eEncrypt || mode == eEncryptSign))
	{
		msg->GetEnvelope()->SetSubject(ApplyHCP("Subject", msg->GetEnvelope()->GetSubject()));
	}
}

// Determine whether body needs to be spooled to file
bool CSecurityPlugin::FileBody(const CAttachment* part, unsigned long& size) const
{
	// See if multipart
	if (part->IsMultipart() && !part->IsMessage() && part->GetParts())
	{
		for(CAttachmentList::iterator iter = part->GetParts()->begin(); iter != part->GetParts()->end(); iter++)
		{
			if (FileBody(*iter, size))
				return true;
		}
		
		return false;
	}
	else if (part->IsMessage())
		return FileBody(part->GetMessage()->GetBody(), size);
	else
	{
		// Files always require file processing
		if (FileAttachment(part))
			return true;

		// Total size > 64K require file processing
		size += part->GetSize();

		return (size >= cFileThreshold);
	}
}

#pragma mark ____________________________Operations on single parts

bool CSecurityPlugin::CanSecureAttachment(const CAttachment* part) const
{
	return part->CanChange();
}

bool CSecurityPlugin::FileAttachment(const CAttachment* part) const
{
	return typeid(*part) == typeid(CFileAttachment);
}

void CSecurityPlugin::ProcessAttachment(CMessage* msg, CAttachment* part, ESecureMessage mode, const char* key)
{
	// RFC 9787 §5.3: encrypt-only is not permitted — always sign when encrypting
	if (mode == eEncrypt)
		mode = eEncryptSign;

	if (!part)
		return;

	// See if multipart
	if (part->IsMultipart() && !part->IsMessage() && !part->IsApplefile() && part->GetParts())
	{
		for(CAttachmentList::iterator iter = part->GetParts()->begin(); iter != part->GetParts()->end(); iter++)
			ProcessAttachment(msg, *iter, mode, key);
	}
	else if (part->IsMessage())
		ProcessAttachment(part->GetMessage(), part->GetMessage()->GetBody(), mode, key);
	else
	{
		// Only do those that are modifiable
		if (!CanSecureAttachment(part))
			return;

		// Special processing for crypto - only needed for broken PGP implementations
		part->ProcessSendCrypto(mode, false);

		// Check for memory or file based attachment
		if (FileAttachment(part))
		{
#if __dest_os == __mac_os || __dest_os == __mac_os_x

			// Create temporary output file
			PPx::FSObject fs_fout;
			PPx::FSObject* fout = &fs_fout;
			cdstring old_name = static_cast<CFileAttachment*>(part)->GetFSSpec()->GetName();
			CreateTempFile(fout, mode, old_name);
			StRemoveFileSpec _remove_fout(fout);
			PPx::CFURL fout_url = fout->GetURL();

#else
			// Create temporary output file
			cdstring fout;
			cdstring old_path = static_cast<CFileAttachment*>(part)->GetFilePath();
			cdstring old_name;
			if (::strrchr(old_path.c_str(), os_dir_delim) != NULL)
				old_name = ::strrchr(old_path.c_str(), os_dir_delim) + 1;
			else
				old_name = old_path;
			
			CreateTempFile(fout, mode, old_name);
			StRemoveFileSpec _remove_fout(fout);
#endif

			// For file attachments we always create a detatched signature of the original file data on disk
			// allowing users to save the file part and the signature part to disk and to then verify that using
			// the desktop PGP tool. Thus we need to turn on the PGP/MIME behaviour for signing here to get the 
			// detached signature.
#if __dest_os == __mac_os || __dest_os == __mac_os_x
			Process(msg, mode, NULL, static_cast<CFileAttachment*>(part)->GetFSSpec(), key, NULL, fout, NULL, mode == eSign, !part->IsText());
#else
			Process(msg, mode, NULL, static_cast<CFileAttachment*>(part)->GetFilePath(), key, NULL, fout, NULL, mode == eSign, !part->IsText());
#endif

			// Get appropriate MIME params
			SMIMEMultiInfo mime;
			switch(mode)
			{
			case eSign:
				GetMIMESign(&mime);
				break;
			case eEncrypt:
				GetMIMEEncrypt(&mime);
				break;
			case eEncryptSign:
				GetMIMEEncryptSign(&mime);
				break;
			default:;
			}
	
			// Now have detached file - decide what to do
			switch(mode)
			{
			case eSign:
			{
				// Turn into multipart and add detached signature
				CDataAttachment* mattach = new CDataAttachment;
				mattach->GetContent().SetContent(eContentMultipart, eContentSubMixed);

				// Attachment takes ownership of temp file
#if __dest_os == __mac_os || __dest_os == __mac_os_x
				*fout = PPx::FSObject(fout_url);
				CFileAttachment* fattach = new CFileAttachment(*fout);
#else
				CFileAttachment* fattach = new CFileAttachment(fout);
#endif
				fattach->SetDeleteFile(true);
		
				// Always NULL the file name to prevent temp file names leaking into MIME parameters
				fattach->GetContent().SetMappedName(cdstring::null_str);
				
				// Make sure output file is not deleted via stack remove
				_remove_fout.release();

				ApplyMIME(fattach, &mime.second);

				// See if it has a parent
				if (part->GetParent())
				{
					CAttachment* pattach = part->GetParent();

					// Get index of part within parent
					unsigned long index = pattach->GetParts() ? pattach->GetParts()->FetchIndexOf(part) : 0;
					if (index)
					{
						// Remove existing part
						index--;
						pattach->RemovePart(part, false);

						// Add in multipart at old position
						pattach->AddPart(mattach, index);

						// Now add the sub-parts
						mattach->AddPart(part);
						mattach->AddPart(fattach);
					}
				}
				else
				{
					// Give multipart to message
					msg->SetBody(mattach, false);

					// Now add the sub-parts
					mattach->AddPart(part);
					mattach->AddPart(fattach);
				}
				break;
			}
			case eEncrypt:
			case eEncryptSign:
				// Special for AppleDouble - must do before setting FSSpec
				if (part->IsMultipart() && part->IsApplefile() && part->GetParts())
				{
					part->RemovePart(part->GetParts()->front());
					part->RemovePart(part->GetParts()->front());
				}

				// Replace existing part with new file - takes ownership of temp file
#if __dest_os == __mac_os || __dest_os == __mac_os_x
				*fout = PPx::FSObject(fout_url);
				static_cast<CFileAttachment*>(part)->SetFSSpec(*fout);
#else
				static_cast<CFileAttachment*>(part)->SetFilePath(fout);
#endif
				static_cast<CFileAttachment*>(part)->SetDeleteFile(true);
		
				// Always NULL the file name to prevent temp file names leaking into MIME parameters
				part->GetContent().SetMappedName(cdstring::null_str);
				
				// Make sure output file is not deleted via stack remove
				_remove_fout.release();

				// Convert to stand alone application/pgp-encrypted
				ApplyMIME(part, &mime.first);
				break;
			default:;
			}
		}
		else
		{
			// Process data through plugin
			char* out = nil;
			unsigned long out_len = 0;

			// RFC 9580 §7: strip trailing whitespace for clearsign (defense-in-depth)
			cdstring stripped_data;
			const char* in_data = part->GetData();
			if ((mode == eSign || mode == eEncryptSign) && in_data)
			{
				stripped_data = in_data;
				StripTrailingWhitespace(stripped_data);
				in_data = stripped_data.c_str();
			}

			Process(msg, mode, in_data, NULL, key, &out, NULL, &out_len, false, !part->IsText());

			// Make a copy of the data
			char* local = new char[out_len + 1];
			if (out != NULL)
				::memcpy(local, out, out_len);
			local[out_len] = 0;

			DisposeData(out);

			part->SetData(local);
		}
	}
}

#pragma mark ____________________________Process some data

void CSecurityPlugin::Process(const CMessage* msg,
								ESecureMessage mode,
								const char* in,
								fspec fin,
								const char* key,
								char** out,
								fspec fout,
								unsigned long* out_len,
								bool useMIME,
								bool binary)
{
	bool do_data = (in != NULL);

	switch(mode)
	{
	case eSign:
		if (do_data)
		{
			// Clear sign data
			if (SignData(in, key, out, out_len, useMIME, binary) != 1)
			{
				CLOG_LOGTHROW(CGeneralException, -1);
				throw CGeneralException(-1);
			}
		}
		else
		{
			// Clear sign file
			if (SignFile(fin, key, fout, useMIME, binary) != 1)
			{
				CLOG_LOGTHROW(CGeneralException, -1);
				throw CGeneralException(-1);
			}
		}
		break;

	case eEncrypt:
		{
			// Create array of keys
			// RFC 9787 §9.4.1: Bcc recipients excluded to prevent key ID leakage
			cdstrvect keylist;

			// Add To and CC recipients only — not Bcc
			if (msg->GetEnvelope()->GetTo())
			{
				for(CAddressList::const_iterator iter =  msg->GetEnvelope()->GetTo()->begin(); iter !=  msg->GetEnvelope()->GetTo()->end(); iter++)
					keylist.push_back((*iter)->GetMailAddress().c_str());
			}
			if (msg->GetEnvelope()->GetCC())
			{
				for(CAddressList::const_iterator iter =  msg->GetEnvelope()->GetCC()->begin(); iter !=  msg->GetEnvelope()->GetCC()->end(); iter++)
					keylist.push_back((*iter)->GetMailAddress().c_str());
			}
			if (CPreferences::sPrefs->mEncryptToSelf.GetValue())
				keylist.push_back(key);

			// Eliminate duplicates then create pointer array
			std::sort(keylist.begin(), keylist.end());
			keylist.erase(std::unique(keylist.begin(), keylist.end()), keylist.end());
			const char** key_list = cdstring::ToArray(keylist);

			try
			{
				if (do_data)
				{
					// Clear sign data
					if (EncryptData(in, key_list, out, out_len, useMIME, binary) != 1)
					{
						CLOG_LOGTHROW(CGeneralException, -1);
						throw CGeneralException(-1);
					}
				}
				else
				{
					// Clear sign data
					if (EncryptFile(fin, key_list, fout, useMIME, binary) != 1)
					{
						CLOG_LOGTHROW(CGeneralException, -1);
						throw CGeneralException(-1);
					}
				}
			}
			catch (...)
			{
				CLOG_LOGCATCH(...);

				// Always delete key list
				cdstring::FreeArray(key_list);

				CLOG_LOGRETHROW;
				throw;
			}

			// Delete key list
			cdstring::FreeArray(key_list);
		}
		break;

	case eEncryptSign:
		{
			// Create array of keys
			// RFC 9787 §9.4.1: Bcc recipients excluded to prevent key ID leakage
			cdstrvect keylist;

			// Add To and CC recipients only — not Bcc
			if (msg->GetEnvelope()->GetTo())
			{
				for(CAddressList::const_iterator iter =  msg->GetEnvelope()->GetTo()->begin(); iter !=  msg->GetEnvelope()->GetTo()->end(); iter++)
					keylist.push_back((*iter)->GetMailAddress().c_str());
			}
			if (msg->GetEnvelope()->GetCC())
			{
				for(CAddressList::const_iterator iter =  msg->GetEnvelope()->GetCC()->begin(); iter !=  msg->GetEnvelope()->GetCC()->end(); iter++)
					keylist.push_back((*iter)->GetMailAddress().c_str());
			}
			if (CPreferences::sPrefs->mEncryptToSelf.GetValue())
				keylist.push_back(key);

			// Eliminate duplicates then create pointer array
			std::sort(keylist.begin(), keylist.end());
			keylist.erase(std::unique(keylist.begin(), keylist.end()), keylist.end());
			const char** key_list = cdstring::ToArray(keylist);

			try
			{
				if (do_data)
				{
					// Clear sign data
					if (EncryptSignData(in, key_list, key, out, out_len, useMIME, binary) != 1)
					{
						CLOG_LOGTHROW(CGeneralException, -1);
						throw CGeneralException(-1);
					}
				}
				else
				{
					// Clear sign data
					if (EncryptSignFile(fin, key_list, key, fout, useMIME, binary) != 1)
					{
						CLOG_LOGTHROW(CGeneralException, -1);
						throw CGeneralException(-1);
					}
				}
			}
			catch (...)
			{
				CLOG_LOGCATCH(...);

				// Always delete key list
				cdstring::FreeArray(key_list);

				CLOG_LOGRETHROW;
				throw;
			}

			// Delete key list
			cdstring::FreeArray(key_list);
		}
		break;
	default:;
	}
}

#pragma mark ____________________________Verify/decrypt static apis

// Only called for inline parts
bool CSecurityPlugin::VerifyDecryptPart(CMessage* msg, CAttachment* part, CMessageCryptoInfo& info)
{
	CSecurityPlugin* splugin = NULL;

	try
	{
		// Is message top part multipart/signed
		if (msg->GetBody() && msg->GetBody()->IsSigned() &&
			msg->GetBody()->GetParts() && (msg->GetBody()->GetParts()->size() == 2))
		{
			// Get the protocol parameter
			const cdstring& protocol = msg->GetBody()->GetContent().GetContentParameter(cMIMEParameter[eCryptoProtocol]);

			// RFC 3156 §5: validate signature part Content-Type matches protocol
			if (!protocol.empty() && msg->GetBody()->GetParts()->at(1))
			{
				cdstring sig_type = CMIMESupport::GenerateContentHeader(msg->GetBody()->GetParts()->at(1), false, lendl, false);
				if (!sig_type.empty() && ::strcmpnocase(sig_type, protocol) != 0)
				{
					cdstring errstr;
					errstr.FromResource("Alerts::Message::SignaturePartTypeMismatch");
					info.SetError(errstr);
					if (CPreferences::sPrefs->mUseErrorAlerts.GetValue())
						CErrorHandler::PutStopAlertRsrc("Alerts::Message::SignaturePartTypeMismatch");
					return false;
				}
			}

			// Get suitable plugin for verify
			splugin = GetVerifyPlugin(protocol);

			// Check for valid sigtype
			if (!splugin)
			{
				// Provide sensible indication for missing parameter
				cdstring err_protocol(protocol);
				if (err_protocol.empty())
					err_protocol = "missing protocol parameter";
				
				// Do error to indicate unsupported protocol
				cdstring errstr;
				errstr.FromResource("Alerts::Message::UNKNOWN_CRYPTO_SHORT");
				errstr.Substitute(err_protocol);
				info.SetError(errstr);

				// Only show alert if requested by user
				if (CPreferences::sPrefs->mUseErrorAlerts.GetValue())
					CErrorHandler::PutStopAlertRsrcStr("Alerts::Message::UNKNOWN_CRYPTO", err_protocol);
				return false;
			}
		}

		// Is parent a multipart/encrypted
		else if (msg->GetBody() && msg->GetBody()->IsEncrypted() &&
					msg->GetBody()->GetParts() && (msg->GetBody()->GetParts()->size() == 2))
		{

			// Get the protocol parameter
			const cdstring& protocol = msg->GetBody()->GetContent().GetContentParameter(cMIMEParameter[eCryptoProtocol]);
			
			// Get suitable plugin for verify
			splugin = GetDecryptPlugin(protocol);

			// Check for valid sigtype
			if (!splugin)
			{
				// Provide sensible indication for missing parameter
				cdstring err_protocol(protocol);
				if (err_protocol.empty())
					err_protocol = "missing protocol parameter";
				
				// Do error to indicate unsupported protocol
				cdstring errstr;
				errstr.FromResource("Alerts::Message::UNKNOWN_CRYPTO_SHORT");
				errstr.Substitute(err_protocol);
				info.SetError(errstr);

				// Only show alert if requested by user
				if (CPreferences::sPrefs->mUseErrorAlerts.GetValue())
					CErrorHandler::PutStopAlertRsrcStr("Alerts::Message::UNKNOWN_CRYPTO", err_protocol);
				return false;
			}
		}
		
		// Is parent application/(x-)pkcs7-mime
		else if (msg->GetBody() && msg->GetBody()->IsDecryptable())
		{
			// Get the protocol parameter
			cdstring type = CMIMESupport::GenerateContentHeader(msg->GetBody(), false, lendl, false);
			
			// Get suitable plugin for verify
			splugin = GetDecryptPlugin(type);

			// Check for valid sigtype
			if (!splugin)
			{
				// Provide sensible indication for missing parameter
				cdstring err_protocol(type);
				if (err_protocol.empty())
					err_protocol = "missing content type";
				
				// Do error to indicate unsupported protocol
				cdstring errstr;
				errstr.FromResource("Alerts::Message::UNKNOWN_CRYPTO_SHORT");
				errstr.Substitute(err_protocol);
				info.SetError(errstr);

				// Only show alert if requested by user
				if (CPreferences::sPrefs->mUseErrorAlerts.GetValue())
					CErrorHandler::PutStopAlertRsrcStr("Alerts::Message::UNKNOWN_CRYPTO", err_protocol);
				return false;
			}
		}
		
		else if (part)
		{
			// Must be inline PGP/GPG
			splugin = GetRegisteredPlugin(cGPGName);
			if (!splugin)
				splugin = GetRegisteredPlugin(cPGPName);

			// Check for valid sigtype
			if (!splugin)
			{
				// Provide sensible indication for missing parameter
				cdstring err_protocol("cannot process inline content");
				
				// Do error to indicate unsupported protocol
				cdstring errstr;
				errstr.FromResource("Alerts::Message::UNKNOWN_CRYPTO_SHORT");
				errstr.Substitute(err_protocol);
				info.SetError(errstr);

				// Only show alert if requested by user
				if (CPreferences::sPrefs->mUseErrorAlerts.GetValue())
					CErrorHandler::PutStopAlertRsrcStr("Alerts::Message::UNKNOWN_CRYPTO", err_protocol);
				return false;
			}
		}
	}
	catch(...)
	{
		CLOG_LOGCATCH(...);
	}

	return splugin ? splugin->VerifyDecryptPartInternal(msg, part, info) : false;
}

CSecurityPlugin* CSecurityPlugin::GetVerifyPlugin(const cdstring& type)
{
	// Force reset of cache if preferred plugin has changed
	if (sPreferredPlugin != CPreferences::sPrefs->mPreferredPlugin.GetValue())
	{
		sCanVerify.clear();
		sPreferredPlugin = CPreferences::sPrefs->mPreferredPlugin.GetValue();
	}

	// See whether result is already cached
	cdstrmap::const_iterator found = sCanVerify.find(type);
	if (found != sCanVerify.end())
	{
		if ((*found).second.length())
			return GetRegisteredPlugin((*found).second);
		else
			return NULL;
	}
	
	// First try the default plugin specified in the preferences. This will ensure that if both PGP and GPG
	// are installed, then the one from the prefs will be picked for PGP verifications
	CSecurityPlugin* splugin = GetRegisteredPlugin(CPreferences::sPrefs->mPreferredPlugin.GetValue());
	if ((splugin != NULL) && (splugin->CanVerifyThis(type) == 0))
	{
		// cache it and return
		sCanVerify.insert(cdstrmap::value_type(type, splugin->GetName()));
		return splugin;
	}

	// Must do lookup using each plugin
	for(SSecurityPluginHandlers::iterator iter = sSecurityPlugins.begin(); iter != sSecurityPlugins.end(); iter++)
	{
		// Try each one
		splugin = (*iter).second;
		if (splugin->CanVerifyThis(type) == 0)
		{
			// cache it and return
			sCanVerify.insert(cdstrmap::value_type(type, (*iter).first));
			return splugin;
		}
	}
	
	// No handler found - cache this as NULL to prevent testing again
	sCanVerify.insert(cdstrmap::value_type(type, cdstring::null_str));
	return NULL;
}

CSecurityPlugin* CSecurityPlugin::GetDecryptPlugin(const cdstring& type)
{
	// Force reset of cache if preferred plugin has changed
	if (sPreferredPlugin != CPreferences::sPrefs->mPreferredPlugin.GetValue())
	{
		sCanDecrypt.clear();
		sPreferredPlugin = CPreferences::sPrefs->mPreferredPlugin.GetValue();
	}

	// See whether result is already cached
	cdstrmap::const_iterator found = sCanDecrypt.find(type);
	if (found != sCanDecrypt.end())
	{
		if ((*found).second.length())
			return GetRegisteredPlugin((*found).second);
		else
			return NULL;
	}
	
	// First try the default plugin specified in the preferences. This will ensure that if both PGP and GPG
	// are installed, then the one from the prefs will be picked for PGP decryptions
	CSecurityPlugin* splugin = GetRegisteredPlugin(CPreferences::sPrefs->mPreferredPlugin.GetValue());
	if ((splugin != NULL) && (splugin->CanDecryptThis(type) == 0))
	{
		// cache it and return
		sCanDecrypt.insert(cdstrmap::value_type(type, splugin->GetName()));
		return splugin;
	}

	// Must do lookup using each plugin
	for(SSecurityPluginHandlers::iterator iter = sSecurityPlugins.begin(); iter != sSecurityPlugins.end(); iter++)
	{
		// Try each one
		splugin = (*iter).second;
		if (splugin->CanDecryptThis(type) == 0)
		{
			// cache it and return
			sCanDecrypt.insert(cdstrmap::value_type(type, (*iter).first));
			return splugin;
		}
	}
	
	// No handler found - cache this as NULL to prevent testing again
	sCanDecrypt.insert(cdstrmap::value_type(type, cdstring::null_str));
	return NULL;
}

#pragma mark ____________________________Verify/decrypt local apis

// Only called for inline parts
bool CSecurityPlugin::VerifyDecryptPartInternal(CMessage* msg, CAttachment* part, CMessageCryptoInfo& info)
{
	// Load plugin
	StLoadPlugin load(this);

	bool result = false;
	try
	{
		// Is message top part multipart/signed
		if (msg->GetBody() &&
			(msg->GetBody()->GetContent().GetContentType() == eContentMultipart) &&
			(msg->GetBody()->GetContent().GetContentSubtype() == eContentSubSigned) &&
			msg->GetBody()->GetParts() &&
			(msg->GetBody()->GetParts()->size() == 2))
		{
			// Check message size first
			if (!CMailControl::CheckSizeWarning(msg, true))
				return false;

			// Do verification
			result = VerifyMessage(msg, info);

			// Now see if signature failed
			if (!result)
				HandleError(&info);
		}

		// Is parent a multipart/encrypted
		else if (msg->GetBody() &&
			(msg->GetBody()->GetContent().GetContentType() == eContentMultipart) &&
			(msg->GetBody()->GetContent().GetContentSubtype() == eContentSubEncrypted) &&
			msg->GetBody()->GetParts() &&
			(msg->GetBody()->GetParts()->size() == 2))
		{
			// Check message size first
			if (!CMailControl::CheckSizeWarning(msg, true))
				return false;

			// Do decrypt
			result = DecryptMessage(msg, info, true);

			// Now see if signature failed
			if (!result)
				HandleError(&info);
		}
		
		// Is parent application/(x-)pkcs7-mime
		else if (msg->GetBody() && msg->GetBody()->IsDecryptable())
		{
			// Check message size first
			if (!CMailControl::CheckSizeWarning(msg, true))
				return false;

			// Do decrypt
			result = DecryptMessage(msg, info, false);

			// Now see if signature failed
			if (!result)
				HandleError(&info);
		}
		
		else if (part)
		{
			// RFC 9787 §6.2.3: inline PGP handling
			// §6.2.3.1: MUST NOT validate inline signatures
			// §6.2.3.2: decrypted content MUST be isolated in a separate MIME part

			cdstring from;
			if (msg->GetEnvelope() && msg->GetEnvelope()->GetFrom() && (msg->GetEnvelope()->GetFrom()->size() != 0))
				from = msg->GetEnvelope()->GetFrom()->front()->GetMailAddress();

			const char* in = part->GetData();
			char* out = NULL;
			unsigned long out_len = 0;
			char* signed_by = NULL;
			char* encrypted_to = NULL;
			bool did_signature = false;
			bool signature_ok = false;
			if (DecryptVerifyData(in, NULL, from, &out, &out_len, &signed_by, &encrypted_to, &result, &did_signature, &signature_ok, !part->IsText()) != 1)
			{
				info.SetSuccess(false);
				CLOG_LOGTHROW(CGeneralException, -1);
				throw CGeneralException(-1);
			}

			// RFC 9787 §6.2.3.1: suppress inline signature verification results
			info.SetSuccess(result);
			info.SetDidSignature(false);
			info.SetSignatureOK(false);

			// Only process decryption results
			if (encrypted_to)
			{
				info.SetDidDecrypt(true);
				cdstring::FromArray((const char**) encrypted_to, info.GetEncryptedTo());
			}

			// RFC 9787 §6.2.3.2: isolate decrypted content in a separate part
			if (result && out && encrypted_to)
			{
				size_t copy_len = ::strlen(out) + 1;
				char* out_copy = new char[copy_len];
				::memcpy(out_copy, out, copy_len);

				CDataAttachment* decrypted_part = new CDataAttachment;
				decrypted_part->SetData(out_copy);
				decrypted_part->GetContent().SetContent(eContentText, eContentSubPlain);

				if (part->GetParent())
				{
					CAttachment* parent = part->GetParent();
					unsigned long index = parent->GetParts() ? parent->GetParts()->FetchIndexOf(part) : 0;
					if (index)
					{
						index--;
						parent->RemovePart(part, false);

						CDataAttachment* wrapper = new CDataAttachment;
						wrapper->GetContent().SetContent(eContentMultipart, eContentSubMixed);
						parent->AddPart(wrapper, index);
						wrapper->AddPart(part);
						wrapper->AddPart(decrypted_part);
					}
					else
					{
						delete decrypted_part;
					}
				}
				else
				{
					msg->SetBody(decrypted_part, true);
				}
			}
			else if (!result)
				HandleError(&info);

			DisposeData(out);
		}

	}
	catch(CNetworkException& ex)
	{
		CLOG_LOGCATCH(CNetworkException&);

		// Must throw out if disconnected/reconnected because
		// message object is no longer valid
		if (ex.disconnected() || ex.reconnected())
			throw;
	}
	catch (...)
	{
		CLOG_LOGCATCH(...);

		HandleError(&info);
		result = false;
	}

	// RFC 9788: extract and check protected headers if present
	if (result && msg->GetBody())
	{
		// For multipart/signed, the Cryptographic Payload is the first subpart
		const CAttachment* payload = msg->GetBody();
		if (payload->GetContent().GetContentType() == eContentMultipart &&
			payload->GetContent().GetContentSubtype() == eContentSubSigned &&
			payload->GetParts() && payload->GetParts()->size() >= 1)
		{
			payload = payload->GetParts()->at(0);
		}
		// Get raw data from payload for header extraction
		const char* payload_data = payload->GetData();
		ExtractProtectedHeaders(payload, msg, info, payload_data);
	}

	return result;
}

// Determine whether body needs to be spooled to file
bool CSecurityPlugin::FileVerifyDecrypt(const CMessage* msg) const
{
	// Do based on size of message
	return (msg->GetSize() > cFileThreshold);
}

// Verify multipart/signed
bool CSecurityPlugin::VerifyMessage(CMessage* msg, CMessageCryptoInfo& info)
{
	bool result = false;

	// See whether to use file or not
	if (FileVerifyDecrypt(msg))
	{
#if __dest_os == __mac_os || __dest_os == __mac_os_x
		// Create temporary input file
		PPx::FSObject fs_fin;
		PPx::FSObject* fin = &fs_fin;
		CreateTempFile(fin, eNone, cdstring::null_str);
		StRemoveFileSpec _remove_fin(fin);
		cdstring fin_path(fin->GetPath());

		// Create temporary data file
		PPx::FSObject fs_fin_d;
		PPx::FSObject* fin_d = &fs_fin_d;
		CreateTempFile(fin_d, eNone, cdstring::null_str);
		StRemoveFileSpec _remove_fin_d(fin_d);
		cdstring fin_d_path(fin_d->GetPath());
#else
		// Create temporary input file
		cdstring fin;
		CreateTempFile(fin, eNone, cdstring::null_str);
		StRemoveFileSpec _remove_fin(fin);
		cdstring fin_path = fin;

		// Create temporary data file
		cdstring fin_d;
		CreateTempFile(fin_d, eNone, cdstring::null_str);
		StRemoveFileSpec _remove_fin_d(fin_d);
		cdstring fin_d_path = fin_d;
#endif

		{
			// Create the temporary file
			cdofstream finstream(fin_path, std::ios_base::out|std::ios_base::trunc|std::ios_base::binary);
			costream stream_out(&finstream, eEndl_CRLF);
			msg->WriteToStream(stream_out, false, NULL);
		}

		// Try to parse it out as a local message
		cdstring sig;
		{
			cdifstream buf_in(fin_path, std::ios_base::in|std::ios_base::binary);
			CRFC822Parser parser;
			std::unique_ptr<CLocalMessage> lmsg(parser.MessageFromStream(buf_in));
			buf_in.clear();
			buf_in.close();

			// Must have message
			if (!lmsg.get() ||
				!lmsg->GetBody() ||
				!lmsg->GetBody()->GetParts() ||
				(lmsg->GetBody()->GetParts()->size() != 2))
			{
				CLOG_LOGTHROW(CGeneralException, -1);
				throw CGeneralException(-1);
			}

			// Now get pointers to relevant bits
			CAttachmentList* parts = lmsg->GetBody()->GetParts();
			unsigned long data_start = static_cast<CLocalAttachment*>(parts->at(0))->GetIndexStart();
			unsigned long data_length = static_cast<CLocalAttachment*>(parts->at(0))->GetIndexLength();

			// Write data into another temp file
			{
#if 1
				cdifstream buf_in2(fin_path, std::ios_base::in|std::ios_base::binary);
				cdofstream buf_out(fin_d_path, std::ios_base::out|std::ios_base::trunc|std::ios_base::binary);
				::StreamCopy(buf_in2, buf_out, data_start, data_length);
#else
				FILE *inf = fopen(fin_path.c_str(), "rb");
				FILE *outf = fopen(fin_d_path.c_str(), "cb");
				fseek(inf, data_start, SEEK_SET);
				char buff[4096];
				int read_size = 0;
				for( int left_over = data_length; read_size == 4096; data_length -= read_size)
				{
					int read_size = fread(buff, 4096, 1, inf);
					fwrite(buff, read_size, 1, outf);
				}
#endif
			}
			
			// Grab signature into internal buffer
			// NB Must get the signature data via the message to ensure MIME decoding has taken place for PGP only
			{
				CAttachment* sig_part = msg->GetBody()->GetParts()->at(1);
				msg->ReadAttachment(sig_part, true, GetName() != cSMIMEName);
				sig = sig_part->GetData();
			}
		}

		cdstring from;
		if (msg->GetEnvelope() && msg->GetEnvelope()->GetFrom() && (msg->GetEnvelope()->GetFrom()->size() != 0))
			from = msg->GetEnvelope()->GetFrom()->front()->GetMailAddress();

		char* signed_by = NULL;
		char* encrypted_to = NULL;
		bool did_signature = false;
		bool signature_ok = false;
		if (DecryptVerifyFile(fin_d, sig, from, NULL, &signed_by, &encrypted_to, &result, &did_signature, &signature_ok, true) != 1)
		{
			info.SetSuccess(false);
			CLOG_LOGTHROW(CGeneralException, -1);
			throw CGeneralException(-1);
		}
		info.SetSuccess(result);
		info.SetDidSignature(did_signature);
		info.SetSignatureOK(signature_ok);

		// Get signed by info
		if (info.GetDidSignature() && signed_by)
			cdstring::FromArray((const char**) signed_by, info.GetSignedBy());

		// Get encrypted to info
		cdstrvect encryptedTo;
		if (encrypted_to)
		{
			info.SetDidDecrypt(true);
			cdstring::FromArray((const char**) encrypted_to, info.GetEncryptedTo());
		}
	}
	else
	{
		// Read raw message data into temp buffer
		std::ostrstream buf;
		costream stream_out(&buf, eEndl_CRLF);
		msg->WriteToStream(stream_out, false, NULL);
		buf << std::ends;
		const char* in = buf.str();
		buf.freeze(false);

		// Try to parse it out as a local message
		std::istrstream buf_in(in);
		CRFC822Parser parser;
		std::unique_ptr<CLocalMessage> lmsg(parser.MessageFromStream(buf_in));

		// Must have message
		if (!lmsg.get() ||
			!lmsg->GetBody() ||
			!lmsg->GetBody()->GetParts() ||
			(lmsg->GetBody()->GetParts()->size() != 2))
		{
			CLOG_LOGTHROW(CGeneralException, -1);
			throw CGeneralException(-1);
		}

		// Now get pointers to relevant bits
		CAttachmentList* parts = lmsg->GetBody()->GetParts();
		unsigned long data_start = static_cast<CLocalAttachment*>(parts->at(0))->GetIndexStart();
		unsigned long data_length = static_cast<CLocalAttachment*>(parts->at(0))->GetIndexLength();

		cdstring from;
		if (msg->GetEnvelope() && msg->GetEnvelope()->GetFrom() && (msg->GetEnvelope()->GetFrom()->size() != 0))
			from = msg->GetEnvelope()->GetFrom()->front()->GetMailAddress();

		// Now form strings
		const char* data = in + data_start;
		const_cast<char*>(data)[data_length] = 0;

		// Grab signature into internal buffer
		// NB Must get the signature data via the message to ensure MIME decoding has taken place for PGP only
		cdstring sig;
		{
			CAttachment* sig_part = msg->GetBody()->GetParts()->at(1);
			msg->ReadAttachment(sig_part, true, GetName() != cSMIMEName);
			sig = sig_part->GetData();
		}

		char* signed_by = NULL;
		char* encrypted_to = NULL;
		bool did_signature = false;
		bool signature_ok = false;
		if (DecryptVerifyData(data, sig, from, NULL, NULL, &signed_by, &encrypted_to, &result, &did_signature, &signature_ok, true) != 1)
		{
			info.SetSuccess(false);
			CLOG_LOGTHROW(CGeneralException, -1);
			throw CGeneralException(-1);
		}
		{
			long err = eSecurity_NoErr;
			char* error = NULL;
			GetLastError(&err, &error);
			if (err == eSecurity_DubiousKey)
			{
				info.SetError(error);
			}
		}
		info.SetSuccess(result);
		info.SetDidSignature(did_signature);
		info.SetSignatureOK(signature_ok);

		// Get signed by info
		if (info.GetDidSignature() && signed_by)
			cdstring::FromArray((const char**) signed_by, info.GetSignedBy());

		// Get encrypted to info
		cdstrvect encryptedTo;
		if (encrypted_to)
		{
			info.SetDidDecrypt(true);
			cdstring::FromArray((const char**) encrypted_to, info.GetEncryptedTo());
		}
	}

	return result;
}

// Decrypt multipart/encrypted
bool CSecurityPlugin::DecryptMessage(CMessage* msg, CMessageCryptoInfo& info, bool use_multi_part)
{
	bool result = false;

	// See whether to use file or not
	if (FileVerifyDecrypt(msg))
	{
#if __dest_os == __mac_os || __dest_os == __mac_os_x
		// Create temporary input file
		PPx::FSObject fs_fin;
		PPx::FSObject* fin = &fs_fin;
		CreateTempFile(fin, eNone, cdstring::null_str);
		StRemoveFileSpec _remove_fin(fin);
		cdstring fin_path(fin->GetPath());

		// Create temporary data file
		PPx::FSObject fs_fin_d;
		PPx::FSObject* fin_d = &fs_fin_d;
		CreateTempFile(fin_d, eNone, cdstring::null_str);
		StRemoveFileSpec _remove_fin_d(fin_d);
		cdstring fin_d_path(fin_d->GetPath());
#else
		// Create temporary input file
		cdstring fin;
		CreateTempFile(fin, eNone, cdstring::null_str);
		StRemoveFileSpec _remove_fin(fin);
		cdstring fin_path = fin;

		// Create temporary data file
		cdstring fin_d;
		CreateTempFile(fin_d, eNone, cdstring::null_str);
		StRemoveFileSpec _remove_fin_d(fin_d);
		cdstring fin_d_path = fin_d;
#endif

		{
			// Get attachment to write to disk
			CAttachment* part2 = NULL;
			if (use_multi_part)
				part2 = msg->GetBody()->GetParts()->at(1);
			else
				part2 = msg->GetBody();

			// Create the temporary file
			cdofstream finstream(fin_path, std::ios_base::out|std::ios_base::trunc|std::ios_base::binary);
			
			// Get encoding filter
			std::unique_ptr<CStreamFilter> filter;

			// May need to filter  - SMIME always gets raw base64 data
			if (GetName() != cSMIMEName)
			{
				switch(part2->GetContent().GetTransferEncoding())
				{
				case eNoTransferEncoding:
				case e7bitEncoding:
				case e8bitEncoding:
					// Do nothing
					break;
				case eQuotedPrintableEncoding:
					// Convert from QP
					filter.reset(new CStreamFilter(new mime_qp_filterbuf(false)));
					filter->SetStream(&finstream);
					break;
				case eBase64Encoding:
					// Convert from base64
					filter.reset(new CStreamFilter(new mime_base64_filterbuf(false)));
					filter->SetStream(&finstream);
					break;
				default:;
				}
			}

			costream stream_out(filter.get() ? static_cast<std::ostream*>(filter.get()) : static_cast<std::ostream*>(&finstream), eEndl_CRLF);
			part2->WriteDataToStream(stream_out, false, NULL, msg);
		}

		cdstring from;
		if (msg->GetEnvelope() && msg->GetEnvelope()->GetFrom() && (msg->GetEnvelope()->GetFrom()->size() != 0))
			from = msg->GetEnvelope()->GetFrom()->front()->GetMailAddress();

		char* signed_by = NULL;
		char* encrypted_to = NULL;
		bool did_signature = false;
		bool signature_ok = false;
		if (DecryptVerifyFile(fin, NULL, from, fin_d, &signed_by, &encrypted_to, &result, &did_signature, &signature_ok, false) != 1)
		{
			info.SetSuccess(false);
			CLOG_LOGTHROW(CGeneralException, -1);
			throw CGeneralException(-1);
		}
		info.SetSuccess(result);
		info.SetDidSignature(did_signature);
		info.SetSignatureOK(signature_ok);

		// Get signed by info
		if (info.GetDidSignature() && signed_by)
			cdstring::FromArray((const char**) signed_by, info.GetSignedBy());

		// Get encrypted to info
		cdstrvect encryptedTo;
		if (encrypted_to)
		{
			info.SetDidDecrypt(true);
			cdstring::FromArray((const char**) encrypted_to, info.GetEncryptedTo());
		}

		// Add data to part, remove any old cached data
		if (result)
		{
			// RFC 9788: restore inner Subject before replacing body
			{
				cdifstream raw_in(fin_d_path, std::ios_base::in | std::ios_base::binary);
				std::ostrstream raw_buf;
				raw_buf << raw_in.rdbuf();
				raw_buf << std::ends;
				cdstring raw_data;
				raw_data.steal(raw_buf.str());
				cdstring inner_subject = ExtractHeaderFromRaw(raw_data, "Subject");
				if (!inner_subject.empty())
					const_cast<CMessage*>(msg)->GetEnvelope()->SetSubject(inner_subject);
			}

			// Replace existing part data with output
			// Create fstream data
			std::unique_ptr<cdifstream> stream(new cdifstream(fin_d_path, std::ios_base::in|std::ios_base::binary));

			// Parse RFC822 parts
			CRFC822Parser parser(true, msg);
			CAttachment* new_body = parser.AttachmentFromStream(*stream, NULL);
			static_cast<CStreamAttachment*>(new_body)->SetStream(stream.get(), NULL, fin_d_path);
			msg->ReplaceBody(static_cast<CStreamAttachment*>(new_body));

			// Stream & temp file are now owned by attachment
			_remove_fin_d.release();
			stream.release();
		}
		else
			HandleError(&info);

	}
	else
	{
		// Get the encrypted data part
		CAttachment* part2 = NULL;
		if (use_multi_part)
			part2 = msg->GetBody()->GetParts()->at(1);
		else
			part2 = msg->GetBody();
		if (!part2)
			return false;

		// Make sure its treated as text even though its application/octet-stream
		part2->SetFakeText(true);
		part2->GetContent().SetDontEncode();

		cdstring from;
		if (msg->GetEnvelope() && msg->GetEnvelope()->GetFrom() && (msg->GetEnvelope()->GetFrom()->size() != 0))
			from = msg->GetEnvelope()->GetFrom()->front()->GetMailAddress();

		// Just use current data in this part
		msg->ReadAttachment(part2);
		const char* in = part2->GetData();
		char* out = NULL;
		unsigned long out_len = 0;
		char* signed_by = NULL;
		char* encrypted_to = NULL;
		bool did_signature = false;
		bool signature_ok = false;
		if (DecryptVerifyData(in, NULL, from, &out, &out_len, &signed_by, &encrypted_to, &result, &did_signature, &signature_ok, false) != 1)
		{
			info.SetSuccess(false);
			CLOG_LOGTHROW(CGeneralException, -1);
			throw CGeneralException(-1);
		}
		info.SetSuccess(result);
		info.SetDidSignature(did_signature);
		info.SetSignatureOK(signature_ok);

		// Get signed by info
		if (info.GetDidSignature() && signed_by)
			cdstring::FromArray((const char**) signed_by, info.GetSignedBy());

		// Get encrypted to info
		cdstrvect encryptedTo;
		if (encrypted_to)
		{
			info.SetDidDecrypt(true);
			cdstring::FromArray((const char**) encrypted_to, info.GetEncryptedTo());
		}

		// Add data to part, remove any old cached data
		if (result)
		{
			// Replace existing part data with output
			if (out)
			{
				// RFC 9788: restore inner Subject
				cdstring inner_subject = ExtractHeaderFromRaw(out, "Subject");
				if (!inner_subject.empty())
					const_cast<CMessage*>(msg)->GetEnvelope()->SetSubject(inner_subject);

				// Create strstream data
				cdstring temp(out);
				std::unique_ptr<std::istrstream> stream(new std::istrstream(temp.c_str()));

				// Parse RFC822 parts
				CRFC822Parser parser(true, msg);
				CAttachment* new_body = parser.AttachmentFromStream(*stream, NULL);
				static_cast<CStreamAttachment*>(new_body)->SetStream(stream.get(), temp.grab_c_str(), cdstring::null_str);
				msg->ReplaceBody(static_cast<CStreamAttachment*>(new_body));

				// Stream is now owned by attachment
				stream.release();
			}
		}
		else
			HandleError(&info);

		DisposeData(out);
	}

	// Look for signed content after decrypt (i.e. original was signed then encrypted)
	if (result && msg->GetBody()->IsVerifiable())
	{
		// First make sure the message header is cached as it will be needed when writing to stream
		msg->GetHeader();

		// Need to create a temporarily remove the message from its mailbox so that WriteToStream writes the parts
		// to stream rather than tries to get raw message from mailbox and write that
		CMbox* mboxold = msg->GetMbox();
		msg->SetMbox(NULL);

		try
		{
			// Now verify signature — don't let sig failure override decrypt success
			CMessageCryptoInfo info2;
			VerifyDecryptPart(msg, NULL, info2);
			
			// Merge signature data — preserve decrypt success even if inner sig fails
			// RFC 9787 §6.4: failed inner sig should yield "Encrypted But Unverified"
			info.SetDidSignature(info2.GetDidSignature());
			info.SetSignatureOK(info2.GetSignatureOK());
			info.GetSignedBy() = info2.GetSignedBy();
			if (info.GetError().empty())
				info.SetError(info2.GetError());
		}
		catch(...)
		{
			CLOG_LOGCATCH(...);

			// Reset old mailbox info
			msg->SetMbox(mboxold);
		}

		msg->SetMbox(mboxold);
		
	}

	return result;
}

#pragma mark ____________________________Errors

long CSecurityPlugin::HandleError(CMessageCryptoInfo* info)
{
	// Get error string from plugin
	long err = eSecurity_NoErr;
	char* error = NULL;
	GetLastError(&err, &error);

	// Plugin may not return an error string; treat as empty to avoid NULL deref
	const char* error_str = (error != NULL) ? error : "";

	// Put into verify/decrypt info if present
	if (info)
	{
		// Copy only first line of error
		const char* p1 = ::strchr(error_str, '\r');
		const char* p2 = ::strchr(error_str, '\n');
		if ((p1 != NULL) && (p2 != NULL))
			p1 = (p1 > p2) ? p2 : p1;
		else if (p2 != NULL)
			p1 = p2;
		if (p1 != NULL)
			info->SetError(cdstring(error_str, p1 - error_str));
		else
			info->SetError(error_str);

		if (err == eSecurity_BadPassphrase)
			info->SetBadPassphrase(true);
	}

	// Show error alert in some cases
	if ((err != 0) && (err != eSecurity_UserAbort) && ((info == NULL) || CPreferences::sPrefs->mUseErrorAlerts.GetValue()))
		CErrorHandler::PutStopAlert(error_str, true);

	// Special support for certian errors
	switch(err)
	{
	case eSecurity_BadPassphrase:
		// Remove thre last cached passphrase
		if (CPreferences::sPrefs->mCachePassphrase.GetValue())
			sPassphrases.erase(sLastPassphraseUID);
		break;
	default:;
	}
	
	return err;
}

#pragma mark ____________________________Memory based

// Sign data
long CSecurityPlugin::SignData(const char* in, const char* key,
								char** out, unsigned long* out_len,
								bool useMime, bool binary)
{
	SSignData info;
	info.mInputData = in;
	info.mKey = key;
	info.mOutputData = out;
	info.mOutputDataLength = out_len;
	info.mUseMIME = useMime;
	info.mBinary = binary;

	return CallPlugin(eSecuritySignData, &info);
}

// Encrypt data
long CSecurityPlugin::EncryptData(const char* in, const char** to,
								char** out, unsigned long* out_len,
								bool useMime, bool binary)
{
	SEncryptData info;
	info.mInputData = in;
	info.mKeys = to;
	info.mOutputData = out;
	info.mOutputDataLength = out_len;
	info.mUseMIME = useMime;
	info.mBinary = binary;

	return CallPlugin(eSecurityEncryptData, &info);
}

// Encrypt & sign data
long CSecurityPlugin::EncryptSignData(const char* in, const char** to, const char* key,
										char** out, unsigned long* out_len,
										bool useMime, bool binary)
{
	SEncryptSignData info;
	info.mInputData = in;
	info.mKeys = to;
	info.mSignKey = key;
	info.mOutputData = out;
	info.mOutputDataLength = out_len;
	info.mUseMIME = useMime;
	info.mBinary = binary;

	return CallPlugin(eSecurityEncryptSignData, &info);
}

// Decrypt/verify data
long CSecurityPlugin::DecryptVerifyData(const char* in, const char* sig, const char* in_from,
										char** out, unsigned long* out_len, char** out_signedby, char** out_encryptedto,
										bool* success, bool* did_sig, bool* sig_ok, bool binary)
{
	SDecryptVerifyData info;
	info.mInputData = in;
	info.mInputSignature = sig;
	info.mInputFrom = in_from;
	info.mOutputData = out;
	info.mOutputDataLength = out_len;
	info.mOutputSignedby = out_signedby;
	info.mOutputEncryptedto = out_encryptedto;
	info.mSuccess = success;
	info.mDidSig = did_sig;
	info.mSigOK = sig_ok;
	info.mBinary = binary;

	return CallPlugin(eSecurityDecryptVerifyData, &info);
}

#pragma mark ____________________________File based

// Sign file
long CSecurityPlugin::SignFile(fspec in, const char* key, fspec out, bool useMime, bool binary)
{
	SSignFile info;
#if __dest_os == __mac_os || __dest_os == __mac_os_x
	FSSpec fsin;
	in->GetFSSpec(fsin);
	info.mInputFile = &fsin;
#else
	info.mInputFile = in;
#endif
	info.mKey = key;
#if __dest_os == __mac_os || __dest_os == __mac_os_x
	FSSpec fsout;
	out->GetFSSpec(fsout);
	info.mOutputFile = &fsout;
#else
	info.mOutputFile = out;
#endif
	info.mUseMIME = useMime;
	info.mBinary = binary;

	return CallPlugin(eSecuritySignFile, &info);
}

// Encrypt file
long CSecurityPlugin::EncryptFile(fspec in, const char** to, fspec out, bool useMime, bool binary)
{
	SEncryptFile info;
#if __dest_os == __mac_os || __dest_os == __mac_os_x
	FSSpec fsin;
	in->GetFSSpec(fsin);
	info.mInputFile = &fsin;
#else
	info.mInputFile = in;
#endif
	info.mKeys = to;
#if __dest_os == __mac_os || __dest_os == __mac_os_x
	FSSpec fsout;
	out->GetFSSpec(fsout);
	info.mOutputFile = &fsout;
#else
	info.mOutputFile = out;
#endif
	info.mUseMIME = useMime;
	info.mBinary = binary;

	return CallPlugin(eSecurityEncryptFile, &info);
}

// Encrypt & sign file
long CSecurityPlugin::EncryptSignFile(fspec in, const char** to, const char* key, fspec out, bool useMime, bool binary)
{
	SEncryptSignFile info;
#if __dest_os == __mac_os || __dest_os == __mac_os_x
	FSSpec fsin;
	in->GetFSSpec(fsin);
	info.mInputFile = &fsin;
#else
	info.mInputFile = in;
#endif
	info.mKeys = to;
	info.mSignKey = key;
#if __dest_os == __mac_os || __dest_os == __mac_os_x
	FSSpec fsout;
	out->GetFSSpec(fsout);
	info.mOutputFile = &fsout;
#else
	info.mOutputFile = out;
#endif
	info.mUseMIME = useMime;
	info.mBinary = binary;

	return CallPlugin(eSecurityEncryptSignFile, &info);
}

// Decrypt/verify file
long CSecurityPlugin::DecryptVerifyFile(fspec in, const char* sig, const char* in_from,
										fspec out, char** out_signedby, char** out_encryptedto,
										bool* success, bool* did_sig, bool* sig_ok, bool binary)
{
	SDecryptVerifyFile info;
#if __dest_os == __mac_os || __dest_os == __mac_os_x
	FSSpec fsin;
	in->GetFSSpec(fsin);
	info.mInputFile = &fsin;
#else
	info.mInputFile = in;
#endif
	info.mInputSignature = sig;
	info.mInputFrom = in_from;
#if __dest_os == __mac_os || __dest_os == __mac_os_x
	FSSpec fsout;
	if (out != NULL)
		out->GetFSSpec(fsout);
	info.mOutputFile = (out != NULL) ? &fsout : NULL;
#else
	info.mOutputFile = out;
#endif
	info.mOutputSignedby = out_signedby;
	info.mOutputEncryptedto = out_encryptedto;
	info.mSuccess = success;
	info.mDidSig = did_sig;
	info.mSigOK = sig_ok;
	info.mBinary = binary;

	return CallPlugin(eSecurityDecryptVerifyFile, &info);
}

#pragma mark ____________________________Others

long CSecurityPlugin::DisposeData(const char* data)
{
	if (data)
		return CallPlugin(eSecurityDisposeData, (void*) data);
	else
		return 1;
}

// Get last error from plugin
long CSecurityPlugin::GetLastError(long* errnum, char** error)
{
	SGetLastError info;
	info.errnum = errnum;
	info.error = error;

	return CallPlugin(eSecurityGetLastError, (void*) &info);
}

// Get MIME parameters for signing
long CSecurityPlugin::GetMIMESign(SMIMEMultiInfo* params)
{
	return CallPlugin(eSecurityGetMIMEParamsSign, (void*) params);
}

// Get MIME parameters for encryption
long CSecurityPlugin::GetMIMEEncrypt(SMIMEMultiInfo* params)
{
	return CallPlugin(eSecurityGetMIMEParamsEncrypt, (void*) params);
}

// Get MIME parameters for encryption and signing
long CSecurityPlugin::GetMIMEEncryptSign(SMIMEMultiInfo* params)
{
	return CallPlugin(eSecurityGetMIMEParamsEncryptSign, (void*) params);
}

// Check that MIME type is verifiable by this plugin
long CSecurityPlugin::CanVerifyThis(const char* type)
{
	// This can be called when not loaded
	StLoadPlugin load(this);

	return CallPlugin(eSecurityCanVerifyThis, (void*) type);
}

// Check that MIME type is decryptable by this plugin
long CSecurityPlugin::CanDecryptThis(const char* type)
{
	// This can be called when not loaded
	StLoadPlugin load(this);

	return CallPlugin(eSecurityCanDecryptThis, (void*) type);
}

#pragma mark ____________________________Callbacks

// Set callback into Mulberry
long CSecurityPlugin::SetCallback()
{
	return CallPlugin(eSecuritySetCallback, (void*) Callback);
}

// Set callback into Mulberry
long CSecurityPlugin::SetContext()
{
	SSMIMEContext context;

	if (CPluginManager::sPluginManager.HasSSL())
	{
		CPluginManager::sPluginManager.GetSSL()->InitSSL();
	
		context.mDLL = CPluginManager::sPluginManager.GetSSL()->GetConnection();
		context.mCertMgr = CCertificateManager::sCertificateManager;

		return CallPlugin(eSecuritySetSMIMEContext, (void*) &context);
	}
	else
		return 0;
}

bool CSecurityPlugin::Callback(ESecurityPluginCallback type, void* data)
{
	switch(type)
	{
	case eCallbackPassphrase:
	{
		SCallbackPassphrase* context = reinterpret_cast<SCallbackPassphrase*>(data);
		return GetPassphrase(context->users, context->passphrase, context->chosen);
	}
	default:
		return false;
	}
}

bool CSecurityPlugin::GetPassphrase(const char** users, char* passphrase, unsigned long& chosen)
{
	// Look in passphrase cache for a user
	if (CPreferences::sPrefs->mCachePassphrase.GetValue())
	{
		const char** p = users;
		unsigned long index = 0;
		while(*p)
		{
			cdstrmap::const_iterator found = sPassphrases.find(*p++);
			if (found != sPassphrases.end())
			{
				sLastPassphraseUID = (*found).first;
				if ((*found).second.length() < 256)
				{
					// Get temporary passphrase
					cdstring temp((*found).second);
					temp.Decrypt(cdstring::eEncryptSimplemUTF7);
					::strcpy(passphrase, temp);

					// Clear memory
					::memset(temp.c_str_mod(), 0, temp.length());

					chosen = index;
					return true;
				}
				else
					return false;
			}
			index++;
		}
	}
	else
		sPassphrases.clear();

	// Ask user for passphrase
	cdstring new_phrase;
	cdstring chosen_user;
	unsigned long index = 0;

	if (CGetPassphraseDialog::PoseDialog(new_phrase, users, chosen_user, index))
	{
		if (new_phrase.length() < 256)
		{
			// Cache the new passphrase
			if (CPreferences::sPrefs->mCachePassphrase.GetValue())
			{
				cdstring temp(new_phrase);
				temp.Encrypt(cdstring::eEncryptSimplemUTF7);
				sPassphrases.insert(cdstrmap::value_type(chosen_user, temp));
				sLastPassphraseUID = chosen_user;
			}

			::strcpy(passphrase, new_phrase);
			
			// Clear memory
			::memset(new_phrase.c_str_mod(), 0, new_phrase.length());

			chosen = index;
			return true;
		}
	}

	return false;
}

void CSecurityPlugin::ClearLastPassphrase()
{
	sPassphrases.erase(sLastPassphraseUID);
}
