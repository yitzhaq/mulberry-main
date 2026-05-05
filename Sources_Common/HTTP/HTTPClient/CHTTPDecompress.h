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


// CHTTPDecompress.h — HTTP Content-Encoding decompression streambuf

#ifndef __CHTTPDECOMPRESS__MULBERRY__
#define __CHTTPDECOMPRESS__MULBERRY__

#include <zlib.h>

#ifdef HAVE_BROTLI
#include <brotli/decode.h>
#endif

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#include <ostream>
#include <streambuf>

namespace http {

class inflate_streambuf : public std::streambuf
{
public:
	enum EEncoding
	{
		eNone = 0,
		eGzip,
		eDeflate,
		eBrotli,
		eZstd
	};

	inflate_streambuf(std::ostream& output, EEncoding encoding);
	~inflate_streambuf();

protected:
	virtual int overflow(int c);
	virtual int sync();

private:
	static const size_t cBufSize = 8192;

	std::ostream&	mOutput;
	EEncoding		mEncoding;

	z_stream		mZStream;
	bool			mZStreamInit;

#ifdef HAVE_BROTLI
	BrotliDecoderState*	mBrotliState;
#endif

#ifdef HAVE_ZSTD
	ZSTD_DStream*	mZstdState;
#endif

	char			mInBuf[cBufSize];
	size_t			mInBufLen;
	size_t			mTotalIn;
	size_t			mTotalOut;

	void Flush();
	void FlushZlib();
	void FlushBrotli();
	void FlushZstd();
};

}	// namespace http

#endif	// __CHTTPDECOMPRESS__MULBERRY__
