/*
    Copyright (c) 2007-2009 Cyrus Daboo. All rights reserved.
    
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


#include "CTCPStream.h"

#include "CErrorHandler.h"
#include "CGeneralException.h"
#include "CLog.h"
#include "CProgress.h"

#if __dest_os == __win32_os
#include <WIN_LStream.h>
#elif __dest_os == __linux_os
#include "UNX_LStream.h"
#endif

#include <iomanip>

CTCPStream::CTCPStream() :
			std::ostream(0),
			std::istream(0),
			std::ios(0)
{
	rdbuf(this);

	// Turn on exception propogation
	exceptions(badbit | failbit);
}

CTCPStream::CTCPStream(const CTCPStream& copy) :
			std::ostream(0),
			std::istream(0),
			std::ios(0),
			CTCPStreamBuf(copy)
{
	rdbuf(this);

	// Turn on exception propogation
	exceptions(badbit | failbit);
}

// Open TCP comms
void CTCPStream::TCPOpen()
{
	// Clear any previous exception state
	clear();

	CTCPStreamBuf::TCPOpen();
}

CTCPStream& CTCPStream::qgetline (CTCPStreamBuf::char_type* s, std::streamsize n)
{
	std::istream::sentry ok(*this, true);

	if (s == 0 || n <= 0)
	{
		setstate(failbit);
		return *this;
	}

	if (ok)
	{
		iostate err = goodbit;
		try
		{
			while (true)
			{
				CTCPStreamBuf::int_type ci = rdbuf()->sbumpc();
				if (CTCPStreamBuf::traits_type::eq_int_type (ci, CTCPStreamBuf::traits_type::eof ()))
				{
					err |= eofbit;
					break;
				}
				CTCPStreamBuf::char_type c = CTCPStreamBuf::traits_type::to_char_type(ci);
				if (CTCPStreamBuf::traits_type::eq(c, '\n'))
				{
					//chcount++;
					break;
				}
				if (CTCPStreamBuf::traits_type::eq(c, '\r'))
				{
					//chcount++;
					continue;
				}
				if (!--n)
				{
					rdbuf()->sputbackc (c);
					err |= failbit;
					break;
				}
				*s++ = c;
				//chcount++;
			}
			*s = CTCPStreamBuf::char_type();
		}
		catch (...)
		{
			CLOG_LOGCATCH(...);

			// Important - do not let this failure throw an exception!!!
			// Any exception here is not handled properly by caller
			try
			{
#if defined(__GNUC__) || defined(__VCPP__)
				setstate(badbit);
#else
				state() |= badbit;
#endif
			}
			catch(...)
			{
				// Ignore
			}
			// Always throw up
			CLOG_LOGRETHROW;
			throw;
		}

		// Important - do not let this failure throw an exception!!!
		// Any exception here is not handled
		try
		{
#if defined(__GNUC__) || defined(__VCPP__)
			setstate(err);
#else
			state() = err;
#endif
		}
		catch(...)
		{
			// Ignore stream exception
		}

	}

	return *this;
}

void CTCPStream::gettostream(LStream& stream, std::ostream* log, long* len, CProgress* progress)
{
	char tmp[cTCPBufferSize];
	long total = *len;
	long remaining = *len;

	// Ignore progress if length is within single buffer size
	if (progress && (total <= cTCPBufferSize))
		progress = NULL;

	// Initialise progress
	if (progress)
		progress->SetPercentage(0);

	bool err_once = false;
	while(remaining)
	{
		// Determine next amount to read
		long rcv_len = remaining;
		if (rcv_len > cTCPBufferSize)
			rcv_len = cTCPBufferSize;

		// Read in from streambuf
		read(tmp, rcv_len);

		// Do not allow failure on write
		try
		{
			// Give to stream and adjust length
			if (!err_once)
				stream.WriteData(tmp, rcv_len);
			remaining -= rcv_len;
			
			// Do log
			if (log != NULL)
				log->write(tmp, rcv_len);
		}
		catch (CGeneralException& ex)
		{
			CLOG_LOGCATCH(CGeneralException&);

			// Dump handle from stream
			stream.SetLength(0);

			// Try alert
			if (!err_once)
			{
				CErrorHandler::PutOSErrAlertRsrc("Error::IMAP::OSErrReadMsg", ex.GetErrorCode());

				err_once = true;
			}

			// Ignore
			remaining -= rcv_len;
		}
		catch (...)
		{
			CLOG_LOGCATCH(...);

			// Ignore
			remaining -= rcv_len;
		}
		
		// Update progress
		if (progress)
			progress->SetPercentage((unsigned long)(((total - remaining) * 100.0) / total));
	}

	// Dump handle from stream if error
	if (err_once)
		stream.SetLength(0);
}

void CTCPStream::gettostream(std::ostream& stream, std::ostream* log, long* len, CProgress* progress)
{
	char tmp[cTCPBufferSize];
	long total = *len;
	long remaining = *len;

	// Initialise progress
	if (progress)
		progress->SetPercentage(0);

	while(remaining)
	{
		long rcv_len = remaining;
		if (rcv_len > cTCPBufferSize)
			rcv_len = cTCPBufferSize;

		// Read in from streambuf
		read(tmp, rcv_len);

		// Do not allow failure on write
		try
		{
			// Give to stream and adjust length
			stream.write(tmp, rcv_len);
			remaining -= rcv_len;
			
			// Do log
			if (log != NULL)
				log->write(tmp, rcv_len);
		}
		catch (...)
		{
			CLOG_LOGCATCH(...);

			// Ignore
			remaining -= rcv_len;
		}
		
		// Update progress
		if (progress)
			progress->SetPercentage((unsigned long)(((total - remaining) * 100.0) / total));
	}
}

// Constructor
CTCPStreamBuf::CTCPStreamBuf() : std::streambuf()
{
	// Set buffers
	setg(mBufIn, mBufIn, mBufIn);
	setp(mBufOut, mBufOut + cTCPBufferSize);
	mCompressOn = false;
	mCompressBufInLen = 0;
	mCompressBufInPos = 0;
	mCompressRawInLen = 0;
	mCompressRawInPos = 0;
	::memset(&mInflateState, 0, sizeof(mInflateState));
	::memset(&mDeflateState, 0, sizeof(mDeflateState));
};

// Copy constructor
CTCPStreamBuf::CTCPStreamBuf(const CTCPStreamBuf& copy)
	: std::streambuf(),
	  CTLSSocket(copy)
{
	// Set buffers
	setg(mBufIn, mBufIn, mBufIn);
	setp(mBufOut, mBufOut + cTCPBufferSize);
	mCompressOn = false;
	mCompressBufInLen = 0;
	mCompressBufInPos = 0;
	mCompressRawInLen = 0;
	mCompressRawInPos = 0;
	::memset(&mInflateState, 0, sizeof(mInflateState));
	::memset(&mDeflateState, 0, sizeof(mDeflateState));
};

// Open TCP comms
void CTCPStreamBuf::TCPOpen()
{
	// Reset buffers to clear any stale data
	setg(mBufIn, mBufIn, mBufIn);
	setp(mBufOut, mBufOut + cTCPBufferSize);

	CTLSSocket::TCPOpen();
}

// Close network stream
void CTCPStreamBuf::TCPCloseConnection()
{
	// Send any remaining data
	sync();

	// Clean up compression state
	CompressStop();

	// Close the socket
	CTLSSocket::TCPCloseConnection();
}

// Sync buffer
// Start DEFLATE compression (RFC 4978)
void CTCPStreamBuf::CompressStart()
{
	::memset(&mDeflateState, 0, sizeof(mDeflateState));
	::memset(&mInflateState, 0, sizeof(mInflateState));
	int ret = deflateInit2(&mDeflateState, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
	if (ret != Z_OK)
	{
		CLOG_LOGTHROW(CGeneralException, -1L);
		throw CGeneralException(-1L);
	}
	ret = inflateInit2(&mInflateState, -15);
	if (ret != Z_OK)
	{
		deflateEnd(&mDeflateState);
		CLOG_LOGTHROW(CGeneralException, -1L);
		throw CGeneralException(-1L);
	}
	mCompressOn = true;
	mCompressBufInLen = 0;
	mCompressBufInPos = 0;
	mCompressRawInLen = 0;
	mCompressRawInPos = 0;

	// Save any bytes remaining in the get area after the OK response.
	// These are the start of the compressed stream if the TCP segment
	// contained data past the OK line.
	long leftover = egptr() - gptr();
	if (leftover > 0)
	{
		if (leftover > cTCPBufferSize)
			leftover = cTCPBufferSize;
		::memcpy(mCompressRawIn, gptr(), leftover);
		mCompressRawInLen = leftover;
		mCompressRawInPos = 0;
		setg(mBufIn, mBufIn, mBufIn);
	}
}

// Stop DEFLATE compression
void CTCPStreamBuf::CompressStop()
{
	if (mCompressOn)
	{
		deflateEnd(&mDeflateState);
		inflateEnd(&mInflateState);
		mCompressOn = false;
		mCompressBufInLen = 0;
		mCompressBufInPos = 0;
		mCompressRawInLen = 0;
		mCompressRawInPos = 0;
	}
}

int CTCPStreamBuf::sync()
{
	// flush buffers
	flush_output();

	return 0;
}

// Process chars in buffer area
int CTCPStreamBuf::overflow(int c)
{
	// If flush requested force output
    if (CTCPStreamBuf::traits_type::eq_int_type (c, CTCPStreamBuf::traits_type::eof ()))
    {
		flush_output();
        return CTCPStreamBuf::traits_type::not_eof(c);
    }

	// Check if we are at end of buffer
	if (!(pptr() && (pptr() < epptr())))
		flush_output();

	// store char
	*pptr() = c;
	pbump(1);

	return c;
}

// Flush output buffer
int CTCPStreamBuf::flush_output()
{
	// can only output when open.
	if (!is_open())
		return CTCPStreamBuf::traits_type::eof();

	int len =  pptr() - pbase();

	// Check that there is something to send
	if (len)
	{
		if (mCompressOn)
		{
			mDeflateState.next_in = (Bytef*)pbase();
			mDeflateState.avail_in = len;

			char deflated[cTCPBufferSize];
			do
			{
				mDeflateState.next_out = (Bytef*)deflated;
				mDeflateState.avail_out = cTCPBufferSize;
				int zret = deflate(&mDeflateState, Z_SYNC_FLUSH);
				if (zret != Z_OK && zret != Z_BUF_ERROR)
				{
					CLOG_LOGTHROW(CGeneralException, -1L);
					throw CGeneralException(-1L);
				}
				long out_len = cTCPBufferSize - mDeflateState.avail_out;
				if (out_len > 0)
					TCPSendData(deflated, out_len);
			} while (mDeflateState.avail_out == 0);
		}
		else
		{
			TCPSendData(pbase(), len);
		}

		// Reset buffer
		setp(mBufOut, mBufOut + cTCPBufferSize);
	}

	return len;
}

// Request for input
int CTCPStreamBuf::underflow()
{
	// Check for overrun
	if (!(gptr() && (gptr() < egptr())))
	{
		if (mCompressOn)
		{
			// Check for leftover inflated data
			if (mCompressBufInPos < mCompressBufInLen)
			{
				long copy = mCompressBufInLen - mCompressBufInPos;
				if (copy > cTCPBufferSize)
					copy = cTCPBufferSize;
				::memcpy(mBufIn, mCompressBufIn + mCompressBufInPos, copy);
				mCompressBufInPos += copy;
				setg(mBufIn, mBufIn, mBufIn + copy);
			}
			else
			{
				// Get compressed input: use leftover from previous
				// inflate, or read new data from socket
				if (mCompressRawInPos >= mCompressRawInLen)
				{
					mCompressRawInLen = cTCPBufferSize;
					TCPReceiveData(mCompressRawIn, &mCompressRawInLen);
					mCompressRawInPos = 0;
				}

				long raw_avail = mCompressRawInLen - mCompressRawInPos;

				mInflateState.next_in = (Bytef*)(mCompressRawIn + mCompressRawInPos);
				mInflateState.avail_in = raw_avail;
				mInflateState.next_out = (Bytef*)mCompressBufIn;
				mInflateState.avail_out = cTCPBufferSize;
				int ret = inflate(&mInflateState, Z_SYNC_FLUSH);
				if (ret != Z_OK && ret != Z_BUF_ERROR)
				{
					CLOG_LOGTHROW(CGeneralException, -1L);
					throw CGeneralException(-1L);
				}

				long consumed = raw_avail - mInflateState.avail_in;
				mCompressRawInPos += consumed;

				mCompressBufInLen = cTCPBufferSize - mInflateState.avail_out;
				mCompressBufInPos = 0;

				// Decompression bomb check
				if (mCompressBufInLen > 0 && consumed > 0 &&
					(mCompressBufInLen / consumed) > 1000)
				{
					CLOG_LOGTHROW(CGeneralException, -1L);
					throw CGeneralException(-1L);
				}

				long copy = mCompressBufInLen;
				if (copy > cTCPBufferSize)
					copy = cTCPBufferSize;
				::memcpy(mBufIn, mCompressBufIn, copy);
				mCompressBufInPos = copy;
				setg(mBufIn, mBufIn, mBufIn + copy);
			}
		}
		else
		{
			// Try to read into buffer
			long len = cTCPBufferSize;

			// Get data
			TCPReceiveData(eback(), &len);

			// Reset buffer
			setg(mBufIn, mBufIn, mBufIn + len);
		}
	}

	return CTCPStreamBuf::traits_type::to_int_type(*gptr());
}
