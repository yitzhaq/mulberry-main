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


// Header for common IMAP definitions

#ifndef __CIMAPCOMMON__MULBERRY__
#define __CIMAPCOMMON__MULBERRY__

typedef unsigned short tcp_port;

extern const tcp_port cIMAPServerPort;
extern const tcp_port cIMAPServerPort_SSL;

// Response Messages
extern const char* cPERMANENTFLAGS;
extern const char* cTRYCREATE;
extern const char* cTOOBIG;
extern const char* cUIDVALIDITY;
extern const char* cUIDNEXT;
extern const char* cUNSEEN;
extern const char* cNOSUCHMAILBOX;
extern const int cNOSUCHMAILBOX_LENGTH;
extern const char* cOPENFAILED;
extern const int cOPENFAILED_LENGTH;

// Capability responses
extern const char* cIMAP4;
extern const char* cIMAP4REV1;
extern const char* cIMAP_ACL;
extern const char* cIMAP_QUOTA;
extern const char* cIMAP_QUOTA_RES;
extern const char* cIMAP_MOVE;
extern const char* cIMAP_SASL_IR;
extern const char* cIMAP_ENABLE;
extern const char* cIMAP_ESEARCH;
extern const char* cENABLE;
extern const char* cESEARCH;
extern const char* cRETURN_ALL;
extern const char* cIMAP_LITERAL_PLUS;
extern const char* cIMAP_NAMESPACE;
extern const char* cIMAP_UIDPLUS;
extern const char* cIMAP_UNSELECT;
extern const char* cIMAP_SORT;
extern const char* cIMAP_THREAD_SUBJECT;
extern const char* cIMAP_THREAD_REFERENCES;
extern const char* cIMAP_ID;
extern const char* cIMAP_APPENDLIMIT;
extern const char* cIMAP_LIST_EXTENDED;
extern const char* cIMAP_LIST_STATUS;
extern const char* cIMAP_STATUS_SIZE;
extern const char* cIMAP_SEARCHRES;
extern const char* cIMAP_IDLE;
extern const char* cIMAP_BINARY;
extern const char* cIMAP_SORT_DISPLAY;
extern const char* cIMAP_ESORT;
extern const char* cIMAP_MULTIAPPEND;
extern const char* cIMAP_SPECIAL_USE;
extern const char* cIMAP_REPLACE;
extern const char* cIMAP_COMPRESS;
extern const char* cIMAP_CONDSTORE;
extern const char* cIMAP_QRESYNC;
extern const char* cRETURN_SAVE_ALL;
extern const char* cIMAP_AUTHLOGIN;
extern const char* cIMAP_AUTHPLAIN;
extern const char* cIMAP_AUTHANON;

// Commands
extern const char* cIDLE;
extern const char* cDONE;
extern const char* cSELECT;
extern const char* cEXAMINE;
extern const char* cBBOARD;
extern const char* cFINDMAILBOXES;
extern const char* cFINDALLMAILBOXES;
extern const char* cFINDBBOARDS;
extern const char* cLIST;
extern const char* cLSUB;
extern const char* cCHECK;
extern const char* cSTATUS;
extern const char* cEXPUNGE;
extern const char* cCLOSE;
extern const char* cCOPY;
extern const char* cMOVE;
extern const char* cFETCH;
extern const char* cSTORE;
extern const char* cPARTIAL;
extern const char* cSEARCH;
extern const char* cCREATE;
extern const char* cIMAP_DELETE;
extern const char* cRENAME;
extern const char* cAPPEND;
extern const char* cSUBSCRIBEMBOX;
extern const char* cUNSUBSCRIBEMBOX;
extern const char* cSUBSCRIBEMBOX4;
extern const char* cUNSUBSCRIBEMBOX4;

extern const char* cUIDCOPY;
extern const char* cUIDMOVE;
extern const char* cUIDFETCH;
extern const char* cUIDSTORE;
extern const char* cUIDSEARCH;
extern const char* cUIDEXPUNGE;
extern const char* cUIDREPLACE;
extern const char* cCOMPRESS;

// Unsolicitied
extern const char* cFLAGS;
extern const char* cMAILBOX;

// Numeric
extern const char* cMSGEXISTS;
extern const char* cMSGRECENT;
extern const char* cMSGEXPUNGE;
extern const char* cMSGSTORE;
extern const char* cMSGFETCH;
extern const char* cMSGCOPY;

// Paramaters
extern const char* cINBOX;
extern const char* cENVELOPE;
extern const char* cBODY;
extern const char* cBODYALL_OUT;
extern const char* cBODYSTRUCTURE;
extern const char* cBODYSECTION_OUT;
extern const char* cBODYSECTIONPEEK_OUT;
extern const char* cBODYSECTION_IN;
extern const char* cBODYSECTIONPEEK_IN;
extern const char* cBINARYSECTION_OUT;
extern const char* cBINARYSECTIONPEEK_OUT;
extern const char* cBINARYSECTION_IN;
extern const char* cBINARYSIZE_IN;
extern const char* cBODYTEXT;
extern const char* cBODYPEEKTEXT;
extern const char* cBODYTEXT_OUT;
extern const char* cINTERNALDATE;
extern const char* cUID;
extern const char* cMODSEQ;
extern const char* cNOMODSEQ;
extern const char* cCHANGEDSINCE;
extern const char* cUNCHANGEDSINCE;
extern const char* cMODIFIED;
extern const char* cRFC822;
extern const char* cRFC822HEADER;
extern const char* cRFC822HEADER_OUT;
extern const char* cRFC822SIZE;
extern const char* cRFC822TEXT;
extern const char* cRFC822TEXTPEEK;
extern const char* cRFC822TEXT_OUT;
extern const char* cBODYHEADER;
extern const char* cBODYHEADERFIELDS;
extern const char* cBODYHEADERFIELDSNOT;
extern const char* cBODYHEADERMIME;
extern const char* cBODYHEADERTEXT;
extern const char* cSUMMARY;
extern const char* cSUMMARY4;
extern const char* cRFC822MSG;
extern const char* cRFC822_OUT;
extern const char* cRFC822PEEK_OUT;

// Flags
extern const char* cFLAGRECENT;
extern const char* cFLAGANSWERED;
extern const char* cFLAGFLAGGED;
extern const char* cFLAGDELETED;
extern const char* cFLAGSEEN;
extern const char* cFLAGDRAFT;
extern const char* cFLAGMDNSENT;
extern const char* cFLAGFORWARDED;
extern const char* cFLAGIMPORTANT;
extern const char* cFLAGLABELS[];
extern const char* cFLAGKEYWORDS;
extern const char* cSET_FLAG;
extern const char* cUNSET_FLAG;
extern const char* cFLAG_END;

extern const char* cMBOXFLAGMARKED;
extern const char* cMBOXFLAGNOINFERIORS;
extern const char* cMBOXFLAGNOSELECT;
extern const char* cMBOXFLAGUNMARKED;
extern const char* cMBOXFLAGUNMARKEDHASCHILDREN;
extern const char* cMBOXFLAGUNMARKEDHASNOCHILDREN;
extern const char* cMBOXFLAGSUBSCRIBED;
extern const char* cMBOXFLAGNONEXISTENT;

// RFC 6154 Special-Use attributes
extern const char* cMBOXFLAGSPECIAL_ALL;
extern const char* cMBOXFLAGSPECIAL_ARCHIVE;
extern const char* cMBOXFLAGSPECIAL_DRAFTS;
extern const char* cMBOXFLAGSPECIAL_FLAGGED;
extern const char* cMBOXFLAGSPECIAL_JUNK;
extern const char* cMBOXFLAGSPECIAL_SENT;
extern const char* cMBOXFLAGSPECIAL_TRASH;
extern const char* cMBOXFLAGSPECIAL_IMPORTANT;

// STATUS bits
extern const char* cSTATUS_MESSAGES;
extern const char* cSTATUS_RECENT;
extern const char* cSTATUS_UIDNEXT;
extern const char* cSTATUS_UIDVALIDITY;
extern const char* cSTATUS_UNSEEN;
extern const char* cSTATUS_HIGHESTMODSEQ;
extern const char* cSTATUS_CHECK;
extern const char* cSTATUS_APPENDLIMIT;
extern const char* cSTATUS_SIZE;

// SEARCH criteria
extern const char* cSEARCH_CHARSET;
extern const char* cSEARCH_ALL;
extern const char* cSEARCH_ANSWERED;
extern const char* cSEARCH_BCC;
extern const char* cSEARCH_BEFORE;
extern const char* cSEARCH_BODY;
extern const char* cSEARCH_CC;
extern const char* cSEARCH_DELETED;
extern const char* cSEARCH_DRAFT;
extern const char* cSEARCH_FLAGGED;
extern const char* cSEARCH_FROM;
extern const char* cSEARCH_HEADER;
extern const char* cSEARCH_KEYWORD;
extern const char* cSEARCH_LARGER;
extern const char* cSEARCH_NEW;
extern const char* cSEARCH_NOT;
extern const char* cSEARCH_OLD;
extern const char* cSEARCH_ON;
extern const char* cSEARCH_OR;
extern const char* cSEARCH_RECENT;
extern const char* cSEARCH_SEEN;
extern const char* cSEARCH_SENTBEFORE;
extern const char* cSEARCH_SENTON;
extern const char* cSEARCH_SENTSINCE;
extern const char* cSEARCH_SINCE;
extern const char* cSEARCH_SMALLER;
extern const char* cSEARCH_SUBJECT;
extern const char* cSEARCH_TEXT;
extern const char* cSEARCH_TO;
extern const char* cSEARCH_UID;
extern const char* cSEARCH_UNANSWERED;
extern const char* cSEARCH_UNDELETED;
extern const char* cSEARCH_UNDRAFT;
extern const char* cSEARCH_UNFLAGGED;
extern const char* cSEARCH_UNKEYWORD;
extern const char* cSEARCH_UNSEEN;
extern const char* cSEARCH_OLDER;
extern const char* cSEARCH_YOUNGER;
extern const char* cIMAP_WITHIN;

// E X T E N S I O N S

// SORT/THREAD

// Commands
extern const char* cSORT;
extern const char* cUIDSORT;

extern const char* cTHREAD;
extern const char* cUIDTHREAD;

// Keys
extern const char* cSORT_REVERSE;
extern const char* cSORT_ARRIVAL;
extern const char* cSORT_CC;
extern const char* cSORT_DATE;
extern const char* cSORT_FROM;
extern const char* cSORT_SIZE;
extern const char* cSORT_SUBJECT;
extern const char* cSORT_TO;
extern const char* cSORT_DISPLAYFROM;
extern const char* cSORT_DISPLAYTO;

extern const char* cTHREAD_SUBJECT;
extern const char* cTHREAD_REFERENCES;

// ACL

// Commands
extern const char* cSETACL;
extern const char* cDELETEACL;
extern const char* cGETACL;
extern const char* cLISTRIGHTS;
extern const char* cMYRIGHTS;

// Responses
extern const char* cACL;


// QUOTA

// Commands
extern const char* cSETQUOTA;
extern const char* cGETQUOTA;
extern const char* cGETQUOTAROOT;

// Responses
extern const char* cQUOTA;
extern const char* cQUOTAROOT;

// NAMESPACE

extern const char* cNAMESPACE;

// UIDPLUS

// Response codes
extern const char* cCOPYUID;
extern const char* cAPPENDUID;

// UNSELECT

// Commands
extern const char* cUNSELECT;

#endif
