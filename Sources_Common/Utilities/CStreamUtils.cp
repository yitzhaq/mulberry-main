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


// Header for iostream utilities

#include "CStreamUtils.h"

#include "CGeneralException.h"
#include "CLog.h"
#include "CRFC822.h"
#include "CStreamFilter.h"

#include "cdiomanip.h"
#include "cdstring.h"

#include <cerrno>
#include <istream>
#include <ostream>

#if __dest_os == __win32_os
#include <WIN_LStream.h>
#elif __dest_os == __linux_os
#include "UNX_LStream.h"

#include <netinet/in.h>
#endif

#define CHECK_STREAM(x) \
	{ if ((x).fail()) { int err_no = os_errno; CLOG_LOGTHROW(CGeneralException, err_no); throw CGeneralException(err_no); } }


void StreamCopy(std::istream& in, std::ostream& out, unsigned long start, unsigned long length, unsigned long buf_size)
{
	// Create temp buffer
	cdstring buffer;
	buffer.reserve(buf_size);

	// Go to start pos
	in.seekg(start);

	while(!in.fail() && length)
	{
		unsigned long size = (length > buf_size) ? buf_size : length;
		in.read(buffer.c_str_mod(), size);
		CHECK_STREAM(in);
		out.write(buffer.c_str(), size);
		CHECK_STREAM(out);
		length -= size;
	}

	// Maybe EOF so clear
	if (in.eof())
		in.clear();
}

void StreamCopyIO(std::iostream& inout, std::ostream& out, unsigned long start, unsigned long length, unsigned long buf_size)
{
	// Create temp buffer
	cdstring buffer;
	buffer.reserve(buf_size);

	while(!inout.fail() && length)
	{
		unsigned long size = (length > buf_size) ? buf_size : length;
		inout.seekg(start);
		inout.read(buffer.c_str_mod(), size);
		CHECK_STREAM(inout);
		inout.seekp(0, std::ios_base::end);
		out.write(buffer.c_str(), size);
		CHECK_STREAM(out);
		CHECK_STREAM(inout);
		length -= size;
		start += size;
	}

	// Maybe EOF so clear
	if (inout.eof())
		inout.clear();
}

void StreamCopy(std::istream& in, LStream& out, unsigned long start, unsigned long length, unsigned long buf_size)
{
	// Create temp buffer
	cdstring buffer;
	buffer.reserve(buf_size);

	// Go to start pos
	in.seekg(start);

	while(!in.fail() && length)
	{
		long size = (length > buf_size) ? buf_size : length;
		in.read(buffer.c_str_mod(), size);
		length -= size;
		CHECK_STREAM(in);
		out.PutBytes(buffer.c_str(), size);
	}

	// Maybe EOF so clear
	if (in.eof())
		in.clear();
}

unsigned long StreamLength(std::istream& in)
{
	std::streampos old_pos = in.tellg();
	in.seekg(0, std::ios_base::end);
	std::streampos len_pos = in.tellg();
	in.seekg(old_pos);
	
	return len_pos - old_pos;
}

#pragma mark ____________________________Network/host i/o

void WriteHost(std::ostream& out, const unsigned long& data)
{
	// htonl operates on uint32_t (4 bytes), not unsigned long (8 bytes on LP64)
	// Cast to uint32_t to avoid writing garbage upper 4 bytes on 64-bit systems
	uint32_t temp = htonl(static_cast<uint32_t>(data));
	out.write(reinterpret_cast<const char*>(&temp), sizeof(uint32_t));
}

void WriteHost(std::ostream& out, const uint32_t& data)
{
	// Direct write of uint32_t (4 bytes) - no type conversion needed
	uint32_t temp = htonl(data);
	out.write(reinterpret_cast<const char*>(&temp), sizeof(uint32_t));
}

void WriteHost(std::ostream& out, const ulvector& data)
{
	// htonl operates on uint32_t (4 bytes), not unsigned long (8 bytes on LP64)
	uint32_t size = htonl(static_cast<uint32_t>(data.size()));
	out.write(reinterpret_cast<const char*>(&size), sizeof(uint32_t));
	for(ulvector::const_iterator iter = data.begin(); iter != data.end(); iter++)
	{
		uint32_t temp = htonl(static_cast<uint32_t>(*iter));
		out.write(reinterpret_cast<const char*>(&temp), sizeof(uint32_t));
	}
}

void ReadHost(std::istream& in, unsigned long& data)
{
	// ntohl operates on uint32_t (4 bytes), not unsigned long (8 bytes on LP64)
	// Read only 4 bytes and convert properly
	uint32_t temp;
	in.read(reinterpret_cast<char*>(&temp), sizeof(uint32_t));
	data = ntohl(temp);
}

void ReadHost(std::istream& in, uint32_t& data)
{
	// Direct read of uint32_t (4 bytes) - no type conversion needed
	uint32_t temp;
	in.read(reinterpret_cast<char*>(&temp), sizeof(uint32_t));
	data = ntohl(temp);
}

void ReadHost(std::istream& in, long& data)
{
	// ntohl operates on uint32_t (4 bytes), not long (8 bytes on LP64)
	// Read only 4 bytes and convert properly
	uint32_t temp;
	in.read(reinterpret_cast<char*>(&temp), sizeof(uint32_t));
	data = static_cast<long>(ntohl(temp));
}

void ReadHost(std::istream& in, ulvector* data)
{
	// ntohl operates on uint32_t (4 bytes), not unsigned long (8 bytes on LP64)
	uint32_t size = 0;
	in.read(reinterpret_cast<char*>(&size), sizeof(uint32_t));
	size = ntohl(size);
	if (size)
	{
		if (data)
		{
			// Reserve space and then read entire array
			data->reserve(size);
			data->insert(data->begin(), size, size);
			for(ulvector::iterator iter = data->begin(); iter != data->end(); iter++)
			{
				uint32_t temp;
				in.read(reinterpret_cast<char*>(&temp), sizeof(uint32_t));
				*iter = ntohl(temp);
			}
		}
		else
			in.ignore(size * sizeof(uint32_t));
	}
}

void WriteHost64(std::ostream& out, int64_t value)
{
	unsigned char buf[8];
	buf[0] = (value >> 56) & 0xFF;
	buf[1] = (value >> 48) & 0xFF;
	buf[2] = (value >> 40) & 0xFF;
	buf[3] = (value >> 32) & 0xFF;
	buf[4] = (value >> 24) & 0xFF;
	buf[5] = (value >> 16) & 0xFF;
	buf[6] = (value >>  8) & 0xFF;
	buf[7] = value & 0xFF;
	out.write(reinterpret_cast<char*>(buf), 8);
}

int64_t ReadHost64(std::istream& in)
{
	unsigned char buf[8];
	in.read(reinterpret_cast<char*>(buf), 8);
	return (static_cast<int64_t>(buf[0]) << 56) |
	       (static_cast<int64_t>(buf[1]) << 48) |
	       (static_cast<int64_t>(buf[2]) << 40) |
	       (static_cast<int64_t>(buf[3]) << 32) |
	       (static_cast<int64_t>(buf[4]) << 24) |
	       (static_cast<int64_t>(buf[5]) << 16) |
	       (static_cast<int64_t>(buf[6]) <<  8) |
	       static_cast<int64_t>(buf[7]);
}

#pragma mark ____________________________I18L i/o

void Write1522(std::ostream& out, const cdstring& text)
{
	cdstring temp = text;
	CRFC822::TextTo1522(temp, false);
	out << temp << cd_endl;
}

void Read1522(std::istream& in, cdstring& text)
{
	getline(in, text);
	CRFC822::TextFrom1522(text);
}
