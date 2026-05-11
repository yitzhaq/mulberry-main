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


// Header for Local client class

#ifndef __CLOCALCLIENT__MULBERRY__
#define __CLOCALCLIENT__MULBERRY__

#if __dest_os == __mac_os || __dest_os == __mac_os_x || __dest_os == __win32_os
#define FAST_STREAM
#else
#undef FAST_STREAM
#endif

#include "CMboxClient.h"

#ifdef FAST_STREAM
#include "cdfstream.h"
#else
#include <fstream>
#define cdfstream fstream
#endif

// consts
class CMailRecord;
class CMbox;
class CMessage;
class CLocalAttachment;
class CLocalMessage;
class CProgress;

class LStream;

class CLocalClient: public CMboxClient
{
protected:
	struct SIndexHeader
	{
		// All members must be uint32_t for correct serialization on 64-bit
		// (sizeof(unsigned long) = 8 on LP64, but file format is 4 bytes per field)
		uint32_t	mVersion;
		uint32_t	mMboxModified;
		uint32_t	mCacheModified;
		uint32_t	mLastSync;
		uint32_t	mIndexSize;
		uint32_t	mUIDValidity;
		uint32_t	mUIDNext;
		uint32_t	mLastUID;
		uint32_t	mLocalUIDNext;
		uint32_t	mHighestModSeqHi;	// RFC 7162 CONDSTORE (version >= 0x0C)
		uint32_t	mHighestModSeqLo;
		uint32_t	mMboxModifiedHi;	// Hi 32 bits of mbox mtime (version >= 0x0C)
		uint32_t	mCacheModifiedHi;	// Hi 32 bits of cache mtime (version >= 0x0C)
		uint32_t	mLastSyncHi;		// Hi 32 bits of last sync time (version >= 0x0C)

		uint32_t& Version()
			{ return mVersion; }
		const uint32_t& Version() const
			{ return mVersion; }

		uint32_t& MboxModified()
			{ return mMboxModified; }
		const uint32_t& MboxModified() const
			{ return mMboxModified; }

		uint32_t& CacheModified()
			{ return mCacheModified; }
		const uint32_t& CacheModified() const
			{ return mCacheModified; }

		uint32_t& LastSync()
			{ return mLastSync; }
		const uint32_t& LastSync() const
			{ return mLastSync; }

		uint32_t& IndexSize()
			{ return mIndexSize; }
		const uint32_t& IndexSize() const
			{ return mIndexSize; }

		uint32_t& UIDValidity()
			{ return mUIDValidity; }
		const uint32_t& UIDValidity() const
			{ return mUIDValidity; }

		uint32_t& UIDNext()
			{ return mUIDNext; }
		const uint32_t& UIDNext() const
			{ return mUIDNext; }

		uint32_t& LastUID()
			{ return mLastUID; }
		const uint32_t& LastUID() const
			{ return mLastUID; }

		uint32_t& LocalUIDNext()
			{ return mLocalUIDNext; }
		const uint32_t& LocalUIDNext() const
			{ return mLocalUIDNext; }

		uint64_t GetHighestModSeq() const
			{ return (static_cast<uint64_t>(mHighestModSeqHi) << 32) | mHighestModSeqLo; }
		void SetHighestModSeq(uint64_t v)
			{ mHighestModSeqHi = static_cast<uint32_t>(v >> 32);
			  mHighestModSeqLo = static_cast<uint32_t>(v & 0xFFFFFFFF); }

		int64_t GetMboxModified64() const
			{ return (static_cast<int64_t>(mMboxModifiedHi) << 32) | mMboxModified; }
		void SetMboxModified64(int64_t v)
			{ mMboxModifiedHi = static_cast<uint32_t>(static_cast<uint64_t>(v) >> 32);
			  mMboxModified = static_cast<uint32_t>(v & 0xFFFFFFFF); }

		int64_t GetCacheModified64() const
			{ return (static_cast<int64_t>(mCacheModifiedHi) << 32) | mCacheModified; }
		void SetCacheModified64(int64_t v)
			{ mCacheModifiedHi = static_cast<uint32_t>(static_cast<uint64_t>(v) >> 32);
			  mCacheModified = static_cast<uint32_t>(v & 0xFFFFFFFF); }

		int64_t GetLastSync64() const
			{ return (static_cast<int64_t>(mLastSyncHi) << 32) | mLastSync; }
		void SetLastSync64(int64_t v)
			{ mLastSyncHi = static_cast<uint32_t>(static_cast<uint64_t>(v) >> 32);
			  mLastSync = static_cast<uint32_t>(v & 0xFFFFFFFF); }

		void write(std::ostream& out) const;
		void write_LastSync(std::ostream& out) const;
		void write_IndexSize(std::ostream& out) const;
		void write_UIDValidity(std::ostream& out) const;
		void write_UIDNext(std::ostream& out) const;
		void write_LastUID(std::ostream& out) const;
		void write_LocalUIDNext(std::ostream& out) const;
		void write_HighestModSeq(std::ostream& out) const;
		void read(std::istream& in);
	};

	struct SIndexRecord
	{
		// All members must be uint32_t for correct serialization on 64-bit
		// (sizeof(unsigned long) = 8 on LP64, but file format is 4 bytes per field)
		uint32_t mCache;
		uint32_t mIndex;
		uint32_t mFlags;
		uint32_t mUID;
		uint32_t mLocalUID;
		uint32_t mMessageStart;
		uint32_t mModSeqHi;	// RFC 7162 CONDSTORE (version >= 0x0C)
		uint32_t mModSeqLo;

		uint32_t mSequence;		// Not part of cache but calculated on load

		SIndexRecord()
			{ mCache = 0;
			  mIndex = 0;
			  mFlags = 0;
			  mUID = 0;
			  mLocalUID = 0;
			  mMessageStart = 0;
			  mModSeqHi = 0;
			  mModSeqLo = 0;
			  mSequence = 0; }

		uint32_t& Cache()
			{ return mCache; }
		const uint32_t& Cache() const
			{ return mCache; }
		uint32_t& Index()
			{ return mIndex; }
		const uint32_t& Index() const
			{ return mIndex; }
		uint32_t& Flags()
			{ return mFlags; }
		const uint32_t& Flags() const
			{ return mFlags; }
		uint32_t& UID()
			{ return mUID; }
		const uint32_t& UID() const
			{ return mUID; }
		uint32_t& LocalUID()
			{ return mLocalUID; }
		const uint32_t& LocalUID() const
			{ return mLocalUID; }
		uint32_t& MessageStart()
			{ return mMessageStart; }
		const uint32_t& MessageStart() const
			{ return mMessageStart; }

		uint32_t& Sequence()
			{ return mSequence; }
		const uint32_t& Sequence() const
			{ return mSequence; }

		uint64_t GetModSeq() const
			{ return (static_cast<uint64_t>(mModSeqHi) << 32) | mModSeqLo; }
		void SetModSeq(uint64_t v)
			{ mModSeqHi = static_cast<uint32_t>(v >> 32);
			  mModSeqLo = static_cast<uint32_t>(v & 0xFFFFFFFF); }

		void write(std::ostream& out) const;
		void write_Flags(std::ostream& out) const;
		void write_UID(std::ostream& out) const;
		void read(std::istream& in, unsigned long version);
	};

	typedef std::vector<SIndexRecord>	SIndexList;
	typedef std::vector<SIndexRecord*>	SIndexRefList;

	// I N S T A N C E  V A R I A B L E S

	CMailRecord*	mRecorder;						// Recording object
	unsigned long	mRecordID;						// Recording ID
	bool			mSeparateUIDs;					// Local and remote UIDs in use
	bool			mRecordLocalUIDs;				// Record local UIDs only
	CMessage*		mProcessMessage;				// Message being appended
	cdstring		mCWD;							// Working directory for entire hierarchy
	EEndl			mEndl;							// Line end format for current streams
	cdfstream		mMailbox;
	cdfstream		mCache;
	cdfstream		mIndex;
	SIndexList		mIndexList;
	ulvector		mIndexMapping;					// Mapping from message number to file index
	unsigned long	mDiskHeaderSize;				// On-disk header size (version-dependent)
	unsigned long	mDiskRecordSize;				// On-disk record size (version-dependent)
	unsigned long	mMboxNew;						// Counter to indicate new messages in mbox
	bool			mInPostProcess;					// Flag to indicate post-processing already happening
	bool			mMboxUpdate;					// Flag to indicate update of mbox
	bool			mMboxReset;						// Flag to indicate reset of mbox messages
	bool			mMboxReload;					// Flag to indicate mbox needs to be reread
	bool			mMboxReadWrite;					// Flag indicating it was opened read-write

	std::istream::pos_type mAppendStart;					// Start of multiple append

	cdfstream*		mAppendMailbox;
	cdfstream*		mAppendCache;
	cdfstream*		mAppendIndex;

	char*			mSearchBuffer;					// Buffer used in text searches
	cdstring		mWorkBuffer;					// File I/O buffer

	CProgress*		mProgress;						// Progress indicator

	bool			mPendingAbort;					// Abort of operation is pending

	class StLocalProcess
	{
	public:
		StLocalProcess(CLocalClient* client)
			{ mClient = client; mClient->_PreProcess(); }
		~StLocalProcess()
			{ mClient->_PostProcess(); }
	private:
		CLocalClient* mClient;
	};

	friend class StLocalProcess;

	// C O N S T R U C T I O N / D E S T R U C T I O N  M E T H O D S

public:
			CLocalClient(CMboxProtocol* owner);
			CLocalClient(const CLocalClient& copy, CMboxProtocol* owner);
	virtual	~CLocalClient();

private:
			void	InitLocalClient();

public:
	virtual CINETClient*	CloneConnection();		// Create duplicate, empty connection

	// S T A R T  &  S T O P
	virtual void	SetRecorder(CMailRecord* recorder)
		{ mRecorder = recorder; }

	virtual void	Open();									// Start
	virtual void	Reset();								// Reset account
protected:
	virtual void	CheckCWD();								// Check CWD
public:
	virtual void	Close();								// Release TCP
	virtual void	Abort();								// Program initiated abort
	virtual void	Forceoff();								// Forced close

	// L O G I N  &  L O G O U T
	virtual void	Logon();								// Logon to server
	virtual void	Logoff();								// Logoff from server

	// P R O T O C O L
	virtual void	_Tickle(bool force_tickle);			// Do tickle
protected:
	virtual void	_PreProcess();						// About to start processing input
	virtual void	_PostProcess();						// Finished processing input

	// M B O X
	virtual void	_CreateMbox(CMbox* mbox);			// Do create
	virtual void	_TouchMbox(CMbox* mbox);			// Do touch
	virtual bool	_TestMbox(CMbox* mbox);				// Do test of mailbox existence
	virtual void	_RebuildMbox(CMbox* mbox);			// Rebuild cache
	virtual void	_OpenMbox(CMbox* mbox);				// Do open mailbox
	virtual void	_CloseMbox(CMbox* mbox);			// Do close mailbox

	virtual void	_SelectMbox(CMbox* mbox,
								bool examine = false);	// Do Selection
	virtual void	_Deselect(CMbox* mbox);				// Unselect

	virtual void	_CheckMbox(CMbox* mbox,				// Do check
								bool fast = false);
	virtual void	_MailboxSize(CMbox* mbox);			// Get mailbox size;
	virtual bool	_DoesMailboxSize() const			// Does server handle mailbox size?
		{ return true; }
	virtual bool	_ExpungeMbox(bool closing);			// Do expunge mailbox
	virtual void	_DeleteMbox(CMbox* mbox);			// Do delete mailbox
	virtual void	_RenameMbox(CMbox* mbox_old,
									const char* mbox_new);	// Do rename mbox

	virtual void	_SubscribeMbox(CMbox* mbox);		// Do subscribe mbox
	virtual void	_UnsubscribeMbox(CMbox* mbox);		// Do unsubscribe mbox
	virtual void	_Namespace(CMboxProtocol::SNamespace* names);	// Get namespace
	virtual void	_FindAllSubsMbox(CMboxList* mboxes);// Do find subscribed mboxes
	virtual void	_FindAllMbox(CMboxList* mboxes);	// Do find all mboxes in WD
	virtual void	_StartAppend(CMbox* mbox);			// Starting multiple append
	virtual void	_StopAppend(CMbox* mbox);			// Stopping multiple append
	virtual void	_AppendMbox(CMbox* mbox,
									CMessage* theMsg,
									unsigned long& new_uid,
									bool dummy_files = false);	// Do append message to mbox

	virtual void	_SearchMbox(const CSearchItem* spec,	// Search messages on the server
								ulvector* results,
								bool uids);
			void	AddSearchItem(const CSearchItem* spec);	// Add search item to command line
			void	AddSearchAddress(const CSearchItem* spec,
										const char* spec_type);	// Add search item referring to an address

	virtual void	_SetUIDValidity(unsigned long uidv);	// Set the UIDValidity
	virtual void	_SetUIDNext(unsigned long uidn);		// Set the UIDNext
	virtual void	_SetLastSync(time_t sync);				// Set the time of the last sync operation

	// M E S S A G E S
	virtual unsigned long _GetMessageLocalUID(unsigned long uid);

	virtual void	_FetchItems(const ulvector& nums,					// Do fetch envelopes
										bool uids,
										CMboxProtocol::EFetchItems items,
										bool use_saved = false);
	virtual void	_ReadHeaders(const ulvector& nums,				// Get header list from messages
									bool uids,
									const cdstring& hdrs);
	virtual void	_ReadHeader(CMessage* msg);					// Get message header text from server
	virtual void	_ReadAttachment(unsigned long msg_num,
									CAttachment* attach,
									LStream* aStream,
									bool peek = false,
									unsigned long count = 0,
									unsigned long start = 1);	// Get attachment data into stream
	virtual void	_CopyAttachment(unsigned long msg_num,
									CAttachment* attach,
									costream* aStream,
									bool peek = false,
									unsigned long count = 0,
									unsigned long start = 1);	// Copy raw attachment data into stream

	virtual void	_RemapUID(unsigned long local_uid,
							unsigned long new_uid);				// Set the UID
	virtual void	_MapLocalUIDs(const ulvector& uids,				// Map local to remote UIDs
									ulvector* missing,
									ulmap* local_map);

	virtual void	_SetFlag(const ulvector& nums,
									bool uids,
									NMessage::EFlags flags,
									bool set,
									bool use_saved = false);	// Change flag

	virtual void	_CopyMessage(const ulvector& nums,
									bool uids,
									CMbox* mbox_to,
									ulmap& copy_uids,
									bool use_saved = false);	// Do copy sequence to mailbox
	virtual void	_CopyMessage(unsigned long msg_num,
									bool uids,
									costream* aStream,
									unsigned long count = 0,
									unsigned long start = 1);			// Do copy message to stream
	virtual bool	_DoesCopy() const							// Does server handle copy?
		{ return false; }

	virtual void	_ExpungeMessage(const ulvector& nums, bool uids,
									bool use_saved = false);	// Expunge uids
	virtual bool	_DoesExpungeMessage() const					// Does server handle copy?
		{ return true; }

	// S O R T / T H R E A D
	virtual bool	_DoesSort(ESortMessageBy sortby) const;			// Does server-side sorting
	virtual void    _Sort(ESortMessageBy sortby,					// Do server-side sort
							EShowMessageBy show_by,
							const CSearchItem* search,
							ulvector* results,
							bool uids);
	
	virtual bool	_DoesThreading(EThreadMessageBy threadby) const;	// Does server-side threading
	virtual void    _Thread(EThreadMessageBy threadby,				// Do server-side thread
							const CSearchItem* search,
							threadvector* results,
							bool uids);

	// A C L S
	virtual void	_SetACL(CMbox* mbox, CACL* acl);			// Set acl on server
	virtual void	_DeleteACL(CMbox* mbox, CACL* acl);			// Delete acl on server
	virtual void	_GetACL(CMbox* mbox);						// Get all acls for mailbox from server
	virtual void	_ListRights(CMbox* mbox, CACL* acl);		// Get allowed rights for user
	virtual void	_MyRights(CMbox* mbox);						// Get current user's rights to mailbox

	// Q U O T A S
	virtual void	_SetQuota(CQuotaRoot* root);				// Set quota root values on server
	virtual void	_GetQuota(CQuotaRoot* root);				// Get quota root values from server
	virtual void	_GetQuotaRoot(CMbox* mbox);					// Get quota roots for a mailbox

protected:
	// H A N D L E  E R R O R
	virtual void	INETHandleError(std::exception& ex,
							const char* err_id,
							const char* nobad_id);					// Handle an error condition

	virtual const char*	INETGetErrorDescriptor() const;			// Descriptor for object error context

	// L O C A L  O P S
			void	GetNames(const CMbox* mbox, cdstring& mbox_name, cdstring& cache_name, cdstring& index_name) const;
			void	GetNames(const char* mbox, cdstring& mbox_name, cdstring& cache_name, cdstring& index_name) const;

			void	OpenCache(CMbox* mbox,						// Open cache files
								cdfstream& mailbox,
								cdfstream& cache,
								cdfstream& index,
								SIndexHeader& index_header,
								SIndexList& index_list,
								ulvector* index_mapping,
								bool examine);
			void	ValidateCache(CMbox* mbox,					// Check for valid cache files
								cdfstream& mailbox,
								cdfstream& cache,
								cdfstream& index,
								bool examine);

			void	SwitchCache(CMbox* mbox,					// Change streams from read-only <-> read-write
									cdfstream& index,
									cdfstream& mailbox,
									cdfstream& cache,
									bool read_only);

			void	Reconstruct(CMbox* mbox);					// Reconstruct cache and index
			bool	ReconstructRecover(CMbox* mbox,				// Reconstruct from old cache and index
								CMessageList* list,
								SIndexHeader& index_header,
								ulvector& local_uids,
								bool force = false);
			void	UpdateIndexSize(cdfstream& index,			// Update the index header size
								unsigned long size);
			void	UpdateIndexLastUID(cdfstream& index,		// Update the index last uid
								unsigned long luid);
			void	SyncIndexHeader(CMbox* mbox,				// Update the index header
								cdfstream& index);
			unsigned long CreateIndexVersion();					// Create index version

			void	ReadIndex(cdfstream& in,					// Read index file from disk
								SIndexHeader& header,
								SIndexList& index,
								ulvector* seq);
			void	ReadIndexHeader(cdfstream& in, SIndexHeader& header);	// Read index file from disk

			void	WriteIndex(cdfstream& out, unsigned long index);		// Write back single index entry
			void	WriteIndexFlag(cdfstream& out, unsigned long index);	// Write back single index flag entry
			
			void	ReadMessageIndex(CLocalMessage* lmsg,		// Read in this message's index
										ulvector* indices = NULL);
			void	ReadMessageCache(CLocalMessage* lmsg);		// Read in this message's cache

			void	ClearRecent();								// Clear all recent flags

			void	ConvertSequence(const ulvector& sequence,
										ulvector& nums,
										unsigned long total);									// Map sequence to nums
			void	MapToUIDs(const ulvector& nums, ulvector& uids, bool local) const;			// Map message numbers to (local) uids
			void	MapFromUIDs(const ulvector& uids, ulvector& nums, bool local) const;		// Map uids to message numbers
			void	MapBetweenUIDs(const ulvector& uids, ulvector& luids, bool to_local, 		// Map between uids and local uids
									ulvector* missing = NULL, ulmap* local_map = NULL) const;

			unsigned long GetIndex(unsigned long seq) const;
			unsigned long GetIndex(const CMessage* msg) const
				{ return GetIndex(msg->GetMessageNumber()); }

			void	ScanDirectory(const char* path, const cdstring& pattern, CMboxList* mboxes, bool first = false);
			void	AddMbox(const char* path_name, CMboxList* mboxes, NMbox::EFlags flags);

			void	FetchMessage(CLocalMessage* msg,					// Do fetch envelopes
								 	unsigned long seq,
									CMboxProtocol::EFetchItems items);

			void	ExpungeMessage(ulvector& nums);

			void	CheckFromIndex(CMbox* mbox, const SIndexList& index);

			void	CopyMessage(const CLocalMessage* lmsg,
										costream* aStream,
										unsigned long count,
										unsigned long start);
			unsigned long	AppendMessage(CMbox* mbox,
									CMessage* msg,
									bool add,
									bool copying,
									CLocalClient* copier,
									bool dummy_files = false);
			void	RollbackAppend(CMbox* mbox, cdfstream* stream, std::istream::pos_type old_start);

			bool	SearchMessage(const CLocalMessage* lmsg, const CSearchItem* spec);
			bool	AddressSearch(const CLocalMessage* lmsg, const CSearchItem* spec);
			bool	HeaderSearch(const CLocalMessage* lmsg, const cdstring& hdr, const cdstring& txt, unsigned long start);
			bool	TextSearch(const CLocalMessage* lmsg, const cdstring& txt, unsigned long start, bool do_header);
			bool	TextAttachmentSearch(const CLocalAttachment* lattach, const cdstring& txt, unsigned long start);
			bool	TextIndexSearch(const ulvector& indices, const cdstring& txt, unsigned long start);

			bool	DateCompare(time_t date1, time_t date2, int comp) const;
			time_t	DateRead(const CLocalMessage* lmsg);
			time_t	InternalDateRead(const CLocalMessage* lmsg);

			bool	StreamSearch(std::istream& in, unsigned long start, unsigned long length, const cdstring& txt, EContentTransferEncoding cte);

			bool	SearchBuffer(const char* str, unsigned long n, const char* pat, unsigned long& pat_pos, bool crlf_convert);

			bool	StreamSearch1522(std::istream& in, unsigned long start, unsigned long length, const cdstring& txt);

	static	bool	uid_index_sort(SIndexRecord* rec1, SIndexRecord* rec2);
};

#endif
