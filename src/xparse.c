/*
 * xparse.c
 *		PGP packet debugging.
 *
 * Copyright (c) 2005 Marko Kreen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $PostgreSQL$
 */

#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include <postgres.h>

#include <mbuf.h>
#include <px.h>
#include <pgp.h>

#include "xparse.h"

#define STRARRAY_LEN(a) ((int)(sizeof(a) / sizeof(char *)))

static char *tag_str[] = {
	"Reserved - a packet tag must not have this value",
	"Public-Key Encrypted Session Key Packet",
	"Signature Packet",
	"Symmetric-Key Encrypted Session Key Packet",
	"One-Pass Signature Packet",
	"Secret Key Packet",
	"Public Key Packet",
	"Secret Subkey Packet",
	"Compressed Data Packet",
	"Symmetrically Encrypted Data Packet",
	"Marker Packet",
	"Literal Data Packet",
	"Trust Packet",
	"User ID Packet",
	"Public Subkey Packet",		/* 14 */
	"15",
	"Old comment",
	"PGP attribute packet",
	"Symmetrically encrypted with MDC",
	"MDC: manipulation detection code packet",
};

static const char *get_tag_str(int t)
{
	if (t < 0 || t >= STRARRAY_LEN(tag_str))
		return "Bad tag";
	return tag_str[t];
}

static const char *symalgo_str[] = {
	"Plaintext or unencrypted data",	/* 0 */
	"IDEA",					/* 1 */
	"Triple-DES",				/* 2 */
	"CAST5",				/* 3 */
	"Blowfish",				/* 4 */
	"SAFER-SK128",				/* 5 */
	"DES/SK",				/* 6 */
	"AES with 128-bit key",			/* 7 */
	"AES with 192-bit key",			/* 8 */
	"AES with 256-bit key",			/* 9 */
	"Twofish",				/* 10 */
	"Camellia with 128-bit key",		/* 11 */
	"Camellia with 192-bit key",		/* 12 */
	"Camellia with 256-bit key",		/* 13 */
};

static const char *get_cipher_str(int c)
{
	if (c < 0 || c >= STRARRAY_LEN(symalgo_str))
		return "Bad cipher";
	return symalgo_str[c];
}

static const char *s2kalgo_str[] = {
	"simple s2k",
	"salted s2k",
	"unknown s2k",
	"iterated and salted s2k",
};

static const char *get_s2k_str(int c)
{
	if (c < 0 || c >= STRARRAY_LEN(s2kalgo_str))
		return "Bad s2k algo";
	return s2kalgo_str[c];
}

static const char *hashalgo_str[] = {
	"unknown",
	"MD5",
	"SHA-1",
	"RIPE-MD/160",
	"SHA2",
	"MD2",
	"TIGER/192",
	"HAVAL-5-160"
};

static const char *get_hash_str(int c)
{
	if (c < 0 || c >= STRARRAY_LEN(hashalgo_str))
		return "Bad hash algo";
	return hashalgo_str[c];
}

/*
 * main stuff
 */

static void debug_symenc_sesskey(uint8 *p, unsigned len)
{
	unsigned	sym,
				s2k,
				hash;
	uint8	   *datend = p + len;

	fprintf(stderr, "#\tversion: %d\n", *p++);

	sym = *p++;
	fprintf(stderr, "#\tsymalgo: %s (%d)\n", get_cipher_str(sym), sym);

	s2k = *p++;
	fprintf(stderr, "#\ts2kalgo: %s\n", get_s2k_str(s2k));

	hash = *p++;
	fprintf(stderr, "#\thashalgo: %s\n", get_hash_str(hash));

	switch (s2k) {
	case 0:
		break;
	case 1:
		p += 8;
		break;
	case 3:
		p += 9;
		break;
	}
	if (p != datend) {
		fprintf(stderr, "#\tmissed bytes: %ld", (long)(datend - p));
	}
}

#define load_be32(p, res) do { \
	res = ((p)[0] << 24) + ((p)[1] << 16) + ((p)[2] << 8) + (p)[3]; \
} while (0)

static void debug_literal_packet(uint8 *p, unsigned len)
{
	uint8	   *q;
	time_t time;

	q = p + p[1] + 2;
	load_be32(q, time);
	fprintf(stderr, "#\tdata type=0x%02x '%c'\n", p[0], p[0]);
	fprintf(stderr, "#\tname len=%d\n", p[1]);
	fprintf(stderr, "#\tdate=%s", time ? ctime(&time) : "N/A\n");
	fprintf(stderr, "#\tdata len=%d\n", len - p[1] - 2 - 4);
}

static void debug_compressed_packet(uint8 *p, unsigned len)
{
	fprintf(stderr, "#\tcompr type=0x%02x\n", p[0]);
}

static void debug_symenc_data(uint8 *p, unsigned len)
{
}

static void debug_symenc_data_mdc(uint8 *p, unsigned len)
{
	fprintf(stderr, "#\tversion=%d\n", p[0]);
}

static int xparse(int tag, uint8 *buf, unsigned len)
{
	fprintf(stderr, "# %s [tag=%d len=%d]\n", get_tag_str(tag), tag, len);
	switch (tag) {
	case PGP_PKT_SYMENCRYPTED_SESSKEY:
		debug_symenc_sesskey(buf, len);
		break;
	case PGP_PKT_SYMENCRYPTED_DATA:
		debug_symenc_data(buf, len);
		break;
	case PGP_PKT_MDC:
		fprintf(stderr, "#\tlen=%d\n", len);
		break;
	case PGP_PKT_LITERAL_DATA:
		debug_literal_packet(buf, len);
		break;
	case PGP_PKT_COMPRESSED_DATA:
		debug_compressed_packet(buf, len);
		break;
	case PGP_PKT_SYMENCRYPTED_DATA_MDC:
		debug_symenc_data_mdc(buf, len);
		break;
	default:
		fprintf(stderr, "#\tpkt not supported\n");
	}
	return 0;
}

int list_packets(PullFilter *pf)
{
	int res;
	uint8 tag;
	int len;
	uint8_t *pkt;

	while (1) {
		res = pgp_parse_pkt_hdr(pf, &tag, &len, true);
		if (res < 0)
			goto err;
		if (res == 0)
			break;
		if (res == 1) { // pkt-normal
		} else if (res == 2) { // pkt stream
			goto err;
		} else {
			goto err;
		}
		res = pullf_read(pf, len, &pkt);
		if (res < 0)
			goto err;
		xparse(tag, pkt, len);
	}
	return 0;
err:
	return 1;
}

