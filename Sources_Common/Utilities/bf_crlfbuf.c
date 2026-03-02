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

// bf_crlfbuf.c
//
// Copyright 2006, Cyrus Daboo.  All Rights Reserved.
//
// Created: 28-Jun-2003
// Author: Cyrus Daboo
// Platforms: Mac OS, Win32, Unix
//
// Description:
// This class implements a crlf bio stream converter for openssl.
//
// History:
// 28-Jun-2003: Created initial header and implementation.
//

#include <stdio.h>
#include <errno.h>
#include <memory.h>
//#include "cryptlib.h"
#include <openssl/bio.h>
#include <openssl/opensslv.h>

#ifdef __cplusplus
extern "C"
{
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
const BIO_METHOD *BIO_f_crlfbuffer(void);
#else
BIO_METHOD *BIO_f_crlfbuffer(void);
#endif
#ifdef __cplusplus
}
#endif

static int crlfbuffer_write(BIO *h, const char *buf,int num);
static int crlfbuffer_read(BIO *h, char *buf, int size);
static int crlfbuffer_puts(BIO *h, const char *str);
static int crlfbuffer_gets(BIO *h, char *str, int size);
static long crlfbuffer_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int crlfbuffer_new(BIO *h);
static int crlfbuffer_free(BIO *data);
static long crlfbuffer_callback_ctrl(BIO *h, int cmd, bio_info_cb *fp);
#define DEFAULT_BUFFER_SIZE	4096

/* #define DEBUG */

#define BIO_TYPE_CRLFBUFFER	(27|0x0200)		/* filter */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L

static BIO_METHOD *methods_crlfbuffer = NULL;

static void crlfbuffer_methods_init(void)
{
	if (methods_crlfbuffer != NULL)
		return;
	methods_crlfbuffer = BIO_meth_new(BIO_TYPE_CRLFBUFFER, "crlfbuffer");
	if (methods_crlfbuffer == NULL)
		return;
	BIO_meth_set_write(methods_crlfbuffer, crlfbuffer_write);
	BIO_meth_set_read(methods_crlfbuffer, crlfbuffer_read);
	BIO_meth_set_puts(methods_crlfbuffer, crlfbuffer_puts);
	BIO_meth_set_gets(methods_crlfbuffer, crlfbuffer_gets);
	BIO_meth_set_ctrl(methods_crlfbuffer, crlfbuffer_ctrl);
	BIO_meth_set_create(methods_crlfbuffer, crlfbuffer_new);
	BIO_meth_set_destroy(methods_crlfbuffer, crlfbuffer_free);
	BIO_meth_set_callback_ctrl(methods_crlfbuffer, crlfbuffer_callback_ctrl);
}

const BIO_METHOD *BIO_f_crlfbuffer(void)
{
	crlfbuffer_methods_init();
	return methods_crlfbuffer;
}

#else

static BIO_METHOD methods_crlfbuffer=
	{
	BIO_TYPE_CRLFBUFFER,
	"crlfbuffer",
	crlfbuffer_write,
	crlfbuffer_read,
	crlfbuffer_puts,
	crlfbuffer_gets,
	crlfbuffer_ctrl,
	crlfbuffer_new,
	crlfbuffer_free,
	crlfbuffer_callback_ctrl,
	};

BIO_METHOD *BIO_f_crlfbuffer(void)
	{
	return(&methods_crlfbuffer);
	}

#endif

typedef struct bio_crlfbuffer_ctx_struct
	{
	/* BIO *bio; */ /* this is now in the BIO struct */
	int ibuf_size;	/* how big is the input buffer */

	char *ibuf;		/* the char array */
	int ibuf_len;		/* how many bytes are in it */
	int ibuf_off;		/* write/read offset */

	bool got_cr;		/* got a '\r' last time */
	} BIO_CRLFBUFFER_CTX;

static int crlfbuffer_new(BIO *bi)
	{
	BIO_CRLFBUFFER_CTX *ctx;

	ctx=(BIO_CRLFBUFFER_CTX *)OPENSSL_malloc(sizeof(BIO_CRLFBUFFER_CTX));
	if (ctx == NULL) return(0);
	ctx->ibuf=(char *)OPENSSL_malloc(DEFAULT_BUFFER_SIZE);
	if (ctx->ibuf == NULL) { OPENSSL_free(ctx); return(0); }
	ctx->ibuf_size=DEFAULT_BUFFER_SIZE;
	ctx->ibuf_len=0;
	ctx->ibuf_off=0;
	ctx->got_cr=0;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	BIO_set_init(bi, 1);
	BIO_set_data(bi, ctx);
	BIO_clear_flags(bi, ~0);
#else
	bi->init=1;
	bi->ptr=(char *)ctx;
	bi->flags=0;
#endif
	return(1);
	}

static int crlfbuffer_free(BIO *a)
	{
	BIO_CRLFBUFFER_CTX *b;

	if (a == NULL) return(0);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	b=(BIO_CRLFBUFFER_CTX *)BIO_get_data(a);
	if (b->ibuf != NULL) OPENSSL_free(b->ibuf);
	OPENSSL_free(b);
	BIO_set_data(a, NULL);
	BIO_set_init(a, 0);
	BIO_clear_flags(a, ~0);
#else
	b=(BIO_CRLFBUFFER_CTX *)a->ptr;
	if (b->ibuf != NULL) OPENSSL_free(b->ibuf);
	OPENSSL_free(a->ptr);
	a->ptr=NULL;
	a->init=0;
	a->flags=0;
#endif
	return(1);
	}

static int crlfbuffer_read(BIO *b, char *out, int outl)
	{
	int ret=0;
	BIO_CRLFBUFFER_CTX *ctx;

	if (out == NULL) return(0);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (BIO_next(b) == NULL) return(0);
	ctx=(BIO_CRLFBUFFER_CTX *)BIO_get_data(b);
#else
	if (b->next_bio == NULL) return(0);
	ctx=(BIO_CRLFBUFFER_CTX *)b->ptr;
#endif

	// First copy what's in the current buffer
	int i = ctx->ibuf_len;
	if (i != 0)
	{
		if (i > outl)
			i = outl;
		memcpy(out, &(ctx->ibuf[ctx->ibuf_off]), i);
		ctx->ibuf_off += i;
		ctx->ibuf_len -= i;
		ret += i;
		outl -= i;
		out += i;
	}

	// Now read any remaining direct from source
	if (outl > 0)
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		ret += BIO_read(BIO_next(b),out,outl);
#else
		ret += BIO_read(b->next_bio,out,outl);
#endif
	BIO_clear_retry_flags(b);
	BIO_copy_next_retry(b);

	if (ret > 0)
	{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		BIO_CRLFBUFFER_CTX *new_ctx = (BIO_CRLFBUFFER_CTX *)BIO_get_data(b);
#else
		BIO_CRLFBUFFER_CTX *new_ctx = (BIO_CRLFBUFFER_CTX *)b->ptr;
#endif
		char *p = out;
		char *q = out;
		int qlen = 0;
		int plen = ret;
		while(plen > 0)
		{
			if (*p == '\r')
			{
				p++;
				plen--;
				*q++ = '\n';
				qlen++;
				new_ctx->got_cr = true;
			}
			else if (*p == '\n')
			{
				p++;
				plen--;
				if (!new_ctx->got_cr)
				{
					*q++ = '\n';
					qlen++;
				}
				new_ctx->got_cr = false;
			}
			else
			{
				*q++ = *p++;
				plen--;
				qlen++;
				new_ctx->got_cr = false;
			}
		}
		*q++ = 0;
		ret = qlen;
	}
	return(ret);
	}

static int crlfbuffer_write(BIO *b, const char *in, int inl)
	{
	int ret=0;

	if ((in == NULL) || (inl <= 0)) return(0);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (BIO_next(b) == NULL) return(0);
	ret=BIO_write(BIO_next(b),in,inl);
#else
	if (b->next_bio == NULL) return(0);
	ret=BIO_write(b->next_bio,in,inl);
#endif
	BIO_clear_retry_flags(b);
	BIO_copy_next_retry(b);
	return(ret);
	}

static long crlfbuffer_ctrl(BIO *b, int cmd, long num, void *ptr)
	{
	long ret = 0;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (BIO_next(b) == NULL) return(0);
#else
	if (b->next_bio == NULL) return(0);
#endif
	switch(cmd)
		{
    case BIO_CTRL_RESET:
    {
		BIO_CRLFBUFFER_CTX *ctx;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		ctx=(BIO_CRLFBUFFER_CTX *)BIO_get_data(b);
#else
		ctx=(BIO_CRLFBUFFER_CTX *)b->ptr;
#endif
		ctx->ibuf_len=0;
		ctx->ibuf_off=0;
		ctx->got_cr=0;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		if (BIO_next(b))
			(void)BIO_reset(BIO_next(b));
#else
		if (b->next_bio)
			(void)BIO_reset(b->next_bio);
#endif
    	break;
    }
    case BIO_C_DO_STATE_MACHINE:
		BIO_clear_retry_flags(b);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		ret=BIO_ctrl(BIO_next(b),cmd,num,ptr);
#else
		ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
#endif
		BIO_copy_next_retry(b);
		break;
	case BIO_CTRL_DUP:
		ret=0L;
		break;
	default:
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		ret=BIO_ctrl(BIO_next(b),cmd,num,ptr);
#else
		ret=BIO_ctrl(b->next_bio,cmd,num,ptr);
#endif
		}
	return(ret);
	}

static long crlfbuffer_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
	{
	long ret=1;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (BIO_next(b) == NULL) return(0);
	ret=BIO_callback_ctrl(BIO_next(b),cmd,fp);
#else
	if (b->next_bio == NULL) return(0);
	ret=BIO_callback_ctrl(b->next_bio,cmd,fp);
#endif
	return(ret);
	}

static int crlfbuffer_gets(BIO *b, char *buf, int size)
	{
	BIO_CRLFBUFFER_CTX *ctx;
	int num=0,i,flag;
	char *p;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ctx=(BIO_CRLFBUFFER_CTX *)BIO_get_data(b);
#else
	ctx=(BIO_CRLFBUFFER_CTX *)b->ptr;
#endif
	size--; /* reserve space for a '\0' */
	BIO_clear_retry_flags(b);

	for (;;)
		{
		if (ctx->ibuf_len > 0)
			{
			p= &(ctx->ibuf[ctx->ibuf_off]);
			flag=0;
			for (i=0; (i<ctx->ibuf_len) && (num<size); i++)
				{
				if (ctx->got_cr && (p[i] == '\n'))
					continue;
				if (p[i] == '\r')
				{
					ctx->got_cr = true;
					p[i] = '\n';
				}
				else
					ctx->got_cr = false;
				*(buf++)=p[i];
				num++;
				if (p[i] == '\n')
					{
					flag=1;
					i++;
					break;
					}
				}
			size-=num;
			ctx->ibuf_len-=i;
			ctx->ibuf_off+=i;
			if (flag || size == 0)
				{
				*buf='\0';
				return(num);
				}
			}
		else	/* read another chunk */
			{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			i=BIO_read(BIO_next(b),ctx->ibuf,ctx->ibuf_size);
#else
			i=BIO_read(b->next_bio,ctx->ibuf,ctx->ibuf_size);
#endif
			if (i <= 0)
				{
				BIO_copy_next_retry(b);
				if (i < 0) return((num > 0)?num:i);
				if (i == 0) return(num);
				}
			ctx->ibuf_len=i;
			ctx->ibuf_off=0;
			}
		}
	}

static int crlfbuffer_puts(BIO *b, const char *str)
	{
	return(crlfbuffer_write(b,str,strlen(str)));
	}
