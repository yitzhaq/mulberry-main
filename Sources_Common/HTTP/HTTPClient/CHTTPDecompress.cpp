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


// CHTTPDecompress.cp — HTTP Content-Encoding decompression streambuf

#include "CHTTPDecompress.h"

#include "CGeneralException.h"
#include "CLog.h"

#include <cstring>

using namespace http;

inflate_streambuf::inflate_streambuf(std::ostream& output, EEncoding encoding)
	: mOutput(output), mEncoding(encoding), mZStreamInit(false),
	  mInBufLen(0), mTotalIn(0), mTotalOut(0)
{
	::memset(&mZStream, 0, sizeof(mZStream));

#ifdef HAVE_BROTLI
	mBrotliState = NULL;
#endif
#ifdef HAVE_ZSTD
	mZstdState = NULL;
#endif

	switch(mEncoding)
	{
	case eGzip:
	{
		int ret = ::inflateInit2(&mZStream, 15 + 16);
		if (ret != Z_OK)
		{
			CLOG_LOGTHROW(CGeneralException, -1L);
			throw CGeneralException(-1L);
		}
		mZStreamInit = true;
		break;
	}
	case eDeflate:
	{
		int ret = ::inflateInit2(&mZStream, 15 + 32);
		if (ret != Z_OK)
		{
			CLOG_LOGTHROW(CGeneralException, -1L);
			throw CGeneralException(-1L);
		}
		mZStreamInit = true;
		break;
	}
	case eBrotli:
#ifdef HAVE_BROTLI
		mBrotliState = BrotliDecoderCreateInstance(NULL, NULL, NULL);
		if (!mBrotliState)
		{
			CLOG_LOGTHROW(CGeneralException, -1L);
			throw CGeneralException(-1L);
		}
#else
		CLOG_LOGTHROW(CGeneralException, -1L);
		throw CGeneralException(-1L);
#endif
		break;
	case eZstd:
#ifdef HAVE_ZSTD
		mZstdState = ZSTD_createDStream();
		if (!mZstdState)
		{
			CLOG_LOGTHROW(CGeneralException, -1L);
			throw CGeneralException(-1L);
		}
		ZSTD_initDStream(mZstdState);
#else
		CLOG_LOGTHROW(CGeneralException, -1L);
		throw CGeneralException(-1L);
#endif
		break;
	default:
		break;
	}
}

inflate_streambuf::~inflate_streambuf()
{
	try
	{
		if (mInBufLen > 0)
			Flush();
	}
	catch(...)
	{
	}

	if (mZStreamInit)
		::inflateEnd(&mZStream);

#ifdef HAVE_BROTLI
	if (mBrotliState)
		BrotliDecoderDestroyInstance(mBrotliState);
#endif

#ifdef HAVE_ZSTD
	if (mZstdState)
		ZSTD_freeDStream(mZstdState);
#endif
}

int inflate_streambuf::overflow(int c)
{
	if (c == EOF)
		return sync();

	mInBuf[mInBufLen++] = static_cast<char>(c);
	mTotalIn++;

	if (mInBufLen >= cBufSize)
		Flush();

	return c;
}

int inflate_streambuf::sync()
{
	if (mInBufLen > 0)
		Flush();
	return 0;
}

void inflate_streambuf::Flush()
{
	if (mInBufLen == 0)
		return;

	switch(mEncoding)
	{
	case eGzip:
	case eDeflate:
		FlushZlib();
		break;
	case eBrotli:
		FlushBrotli();
		break;
	case eZstd:
		FlushZstd();
		break;
	default:
		mOutput.write(mInBuf, mInBufLen);
		mTotalOut += mInBufLen;
		break;
	}

	mInBufLen = 0;
}

void inflate_streambuf::FlushZlib()
{
	mZStream.next_in = reinterpret_cast<Bytef*>(mInBuf);
	mZStream.avail_in = mInBufLen;

	char outbuf[cBufSize];
	do
	{
		mZStream.next_out = reinterpret_cast<Bytef*>(outbuf);
		mZStream.avail_out = cBufSize;

		int ret = ::inflate(&mZStream, Z_SYNC_FLUSH);
		if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR)
		{
			CLOG_LOGTHROW(CGeneralException, -1L);
			throw CGeneralException(-1L);
		}

		size_t produced = cBufSize - mZStream.avail_out;
		if (produced > 0)
		{
			mOutput.write(outbuf, produced);
			mTotalOut += produced;
		}

		// Decompression bomb check
		if (mTotalIn > 0 && mTotalOut / mTotalIn > 1000)
		{
			CLOG_LOGTHROW(CGeneralException, -1L);
			throw CGeneralException(-1L);
		}
	} while (mZStream.avail_out == 0);
}

void inflate_streambuf::FlushBrotli()
{
#ifdef HAVE_BROTLI
	const uint8_t* next_in = reinterpret_cast<const uint8_t*>(mInBuf);
	size_t avail_in = mInBufLen;

	uint8_t outbuf[cBufSize];
	size_t avail_out;
	do
	{
		uint8_t* next_out = outbuf;
		avail_out = cBufSize;

		BrotliDecoderResult result = BrotliDecoderDecompressStream(
			mBrotliState, &avail_in, &next_in, &avail_out, &next_out, NULL);

		if (result == BROTLI_DECODER_RESULT_ERROR)
		{
			CLOG_LOGTHROW(CGeneralException, -1L);
			throw CGeneralException(-1L);
		}

		size_t produced = cBufSize - avail_out;
		if (produced > 0)
		{
			mOutput.write(reinterpret_cast<char*>(outbuf), produced);
			mTotalOut += produced;
		}

		if (mTotalIn > 0 && mTotalOut / mTotalIn > 1000)
		{
			CLOG_LOGTHROW(CGeneralException, -1L);
			throw CGeneralException(-1L);
		}
	} while (avail_out == 0);
#endif
}

void inflate_streambuf::FlushZstd()
{
#ifdef HAVE_ZSTD
	ZSTD_inBuffer input = { mInBuf, mInBufLen, 0 };

	char outbuf[cBufSize];
	do
	{
		ZSTD_outBuffer output = { outbuf, cBufSize, 0 };

		size_t ret = ZSTD_decompressStream(mZstdState, &output, &input);
		if (ZSTD_isError(ret))
		{
			CLOG_LOGTHROW(CGeneralException, -1L);
			throw CGeneralException(-1L);
		}

		if (output.pos > 0)
		{
			mOutput.write(outbuf, output.pos);
			mTotalOut += output.pos;
		}

		if (mTotalIn > 0 && mTotalOut / mTotalIn > 1000)
		{
			CLOG_LOGTHROW(CGeneralException, -1L);
			throw CGeneralException(-1L);
		}
	} while (input.pos < input.size);
#endif
}
