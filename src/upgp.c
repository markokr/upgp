/*
 * upgp.c - Small gpg like tool for symmetric crypto.
 *
 * Copyright (c) 2005 Marko Kreen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 */

#include <postgres.h>

#include <unistd.h>
#include <getopt.h>

#include <px.h>
#include <px-crypt.h>
#include <mbuf.h>
#include <pgp.h>

#include "randtest.h"
#include "xparse.h"

static const char *upgp_version = "upgp version 0.2\n";

static int def_s2k_mode = -1;
static char *def_cipher_algo = NULL;
static char *def_digest_algo = NULL;
static char *def_s2k_cipher_algo = NULL;
static char *def_s2k_digest_algo = NULL;
static int def_disable_mdc = 0;
static int def_compr_algo = -1;
static int def_compr_level = -1;
static int def_use_sesskey = -1;
static int def_textmode = -1;
static int def_convert_crlf = -1;

static char *crypt_salt = NULL;
static char *crypt_salt_type = "md5";

static FILE *f_output = NULL;

void f_test(void);
const char *bin2hex(uint8 *bin, int len);

static const char *x_hash[][2] = {
	{"md5", "MD5"},
	{"sha1", "SHA1"},
	{"ripemd160", "RIPEMD160"},
	{"sha256", "SHA256"},
	{"sha384", "SHA384"},
	{"sha512", "SHA512"},
	{0, 0}
};

static const char *x_cipher[][2] = {
	{"idea-ecb", "IDEA"},
	{"des3-ecb", "3DES"},
	{"cast5-ecb", "CAST5"},
	{"bf-ecb", "Blowfish"},
	{"aes-ecb", "AES"},
	{"aes-ecb", "AES192"},
	{"aes-ecb", "AES256"},
	{"twofish-ecb", "Twofish"},
	{"camellia-ecb", "Camellia128"},
	{"camellia-ecb", "Camellia192"},
	{"camellia-ecb", "Camellia256"},
	{0, 0}
};

const char *bin2hex(uint8 *bin, int len)
{
	static char buf[8192];
	static const char *tbl = "0123456789abcdef";
	char *p = buf;
	int i;

	px_debug("bin2hex: len=%d", len);
	for (i = 0; i < len; i++) {
		*p++ = tbl[ bin[i] >> 4 ];
		*p++ = tbl[ bin[i] & 15 ];
	}
	*p = 0;
	return buf;
}

static int crypt_cmd(const char *password)
{
	return 0;
}

static void handle_px_debug(const char *msg)
{
	fprintf(stderr, "upgp dbg: %s\n", msg);
}

static void do_test(void)
{
}

static void show_algos(void)
{
	int i, got;
	const char *name, *code;
	PX_MD *md;
	PX_Cipher *ciph;

	printf("Supported algorithms:\n");
	printf("S2K: 0, 1, 3\n");
	printf("Hash: ");
	got = 0;
	for (i = 0; x_hash[i][0]; i++) {
		code = x_hash[i][0];
		name = x_hash[i][1];
		if (px_find_digest(code, &md) < 0)
			continue;
		px_md_free(md);
		got++;
		if (got == 1)
			printf("%s", name);
		else
			printf(", %s", name);
	}
	printf("\nCipher: ");
	got = 0;
	for (i = 0; x_cipher[i][0]; i++) {
		code = x_cipher[i][0];
		name = x_cipher[i][1];
		if (px_find_cipher(code, &ciph) < 0)
			continue;
		px_cipher_free(ciph);
		got++;
		if (got == 1)
			printf("%s", name);
		else
			printf(", %s", name);
	}
#ifdef HAVE_LIBZ
	printf("\nCompression: Uncompressed, ZIP, ZLIB\n");
#else
	printf("\nCompression: Uncompressed\n");
#endif
}

static MBuf *load_stream(FILE *f)
{
	MBuf *dst;

	unsigned rlen;
	uint8 buf[8192];

	dst = mbuf_create(8192);
	while (1) {
		rlen = fread(buf, 1, 8192, f);
		if (rlen <= 0)
			break;
		mbuf_append(dst, buf, rlen);
	}
	return dst;
}

static MBuf *load_keyfile(char *fn)
{
	MBuf *key;
	FILE *f;
	f = fopen(fn, "rb");
	if (!f) {
		printf("cannot read key file\n");
		return NULL;
	}
	key = load_stream(f);
	fclose(f);
	return key;
}

static int encrypt_stream(MBuf * src, const char *password, int use_armor, char *key_fn)
{
	PGP_Context *ctx;
	MBuf *dst;
	int len, err;
	uint8 *buf;
	uint8 *abuf = NULL;

	dst = mbuf_create(mbuf_size(src));
	err = pgp_init(&ctx);
	if (err < 0) {
		fprintf(stderr, "upgp: %s", px_strerror(err));
		return 1;
	}
	/*
	 * change parameters
	 */
	if (def_s2k_mode >= 0) {
		err = pgp_set_s2k_mode(ctx, def_s2k_mode);
		if (err) {
			fprintf(stderr, "upgp: s2k_algo: %s\n", px_strerror(err));
			return 1;
		}
	}
	if (def_disable_mdc >= 0) {
		err = pgp_disable_mdc(ctx, def_disable_mdc);
		if (err) {
			fprintf(stderr, "upgp: disable_mdc: %s\n", px_strerror(err));
			return 1;
		}
	}
	if (def_use_sesskey >= 0) {
		err = pgp_set_sess_key(ctx, def_use_sesskey);
		if (err) {
			fprintf(stderr, "upgp: use_sesskey: %s\n", px_strerror(err));
			return 1;
		}
	}
	if (def_cipher_algo != NULL) {
		err = pgp_set_cipher_algo(ctx, def_cipher_algo);
		if (err) {
			fprintf(stderr, "upgp: %s: %s\n",
					def_cipher_algo, px_strerror(err));
			return 1;
		}
	}
	if (def_s2k_cipher_algo != NULL) {
		err = pgp_set_s2k_cipher_algo(ctx, def_s2k_cipher_algo);
		if (err) {
			fprintf(stderr, "upgp: %s: %s\n",
					def_s2k_cipher_algo, px_strerror(err));
			return 1;
		}
	}
	if (def_s2k_digest_algo != NULL) {
		err = pgp_set_s2k_digest_algo(ctx, def_s2k_digest_algo);
		if (err) {
			fprintf(stderr, "upgp: %s: %s\n",
					def_s2k_digest_algo, px_strerror(err));
			return 1;
		}
	}
	if (def_compr_algo >= 0) {
		err = pgp_set_compress_algo(ctx, def_compr_algo);
		if (err) {
			fprintf(stderr, "upgp: compr_algo: %s\n", px_strerror(err));
			return 1;
		}
	}
	if (def_compr_level >= 0) {
		err = pgp_set_compress_level(ctx, def_compr_level);
		if (err) {
			fprintf(stderr, "upgp: compr_level: %s\n", px_strerror(err));
			return 1;
		}
	}
	if (def_textmode >= 0) {
		err = pgp_set_text_mode(ctx, def_textmode);
		if (err) {
			fprintf(stderr, "upgp: textmode: %s\n", px_strerror(err));
			return 1;
		}
	}
	if (def_convert_crlf >= 0) {
		err = pgp_set_convert_crlf(ctx, def_convert_crlf);
		if (err) {
			fprintf(stderr, "upgp: convert_crlf: %s\n", px_strerror(err));
			return 1;
		}
	}

	if (key_fn) {
		MBuf *key = load_keyfile(key_fn);
		if (!key)
			return 1;
		err = pgp_set_pubkey(ctx, key, (uint8*)password, strlen(password), 0);
		mbuf_free(key);
	} else {
		err = pgp_set_symkey(ctx, (uint8 *) password, strlen(password));
	}
	if (err) {
		fprintf(stderr, "upgp: %s\n", px_strerror(err));
		return 1;
	}

	/*
	 * ok, now encrypt
	 */
	err = pgp_encrypt(ctx, src, dst);
	if (err < 0) {
		fprintf(stderr, "upgp: %s\n", px_strerror(err));
		return 1;
	}
	pgp_free(ctx);

	len = mbuf_grab(dst, mbuf_avail(dst), &buf);

	if (use_armor) {
		int alen = pgp_armor_enc_len(len);

		abuf = px_alloc(alen);
		alen = pgp_armor_encode(buf, len, abuf);

		buf = abuf;
		len = alen;
	}
	fwrite(buf, len, 1, f_output);
	if (abuf)
		px_free(abuf);
	mbuf_free(dst);
	return 0;
}

static MBuf *try_decode(MBuf *data)
{
	int declen;
	uint8 *buf, *decbuf;
	int len;
	MBuf *dst;

	len = mbuf_grab(data, mbuf_avail(data), &buf);
	declen = pgp_armor_dec_len(len);
	decbuf = px_alloc(declen);
	declen = pgp_armor_decode(buf, len, decbuf);
	if (declen <= 0) {
		mbuf_rewind(data);
		px_free(decbuf);
		return NULL;
	}

	dst = mbuf_create(declen);
	mbuf_append(dst, decbuf, declen);
	px_free(decbuf);
	return dst;
}

static int decrypt_stream(MBuf *src, const char *password, char *key_fn)
{
	PGP_Context *ctx;
	MBuf *dst, *tmp = NULL;
	int len, err;
	uint8 *buf;

	tmp = try_decode(src);
	if (tmp)
		src = tmp;

	dst = mbuf_create(mbuf_size(src));
	err = pgp_init(&ctx);
	if (err < 0) {
		fprintf(stderr, "upgp: %s\n", px_strerror(err));
		if (tmp)
			mbuf_free(tmp);
		return 1;
	}
	if (def_textmode >= 0) {
		err = pgp_set_text_mode(ctx, def_textmode);
		if (err) {
			fprintf(stderr, "upgp: textmode: %s\n", px_strerror(err));
			return 1;
		}
	}
	if (def_convert_crlf >= 0) {
		err = pgp_set_convert_crlf(ctx, def_convert_crlf);
		if (err) {
			fprintf(stderr, "upgp: convert_crlf: %s\n", px_strerror(err));
			return 1;
		}
	}
	if (key_fn) {
		MBuf *key = load_keyfile(key_fn);
		if (!key)
			return 1;
		err = pgp_set_pubkey(ctx, key, (unsigned char *)password, strlen(password), 1);
		mbuf_free(key);
	} else {
		err = pgp_set_symkey(ctx, (uint8 *) password, strlen(password));
	}
	if (err) {
		fprintf(stderr, "upgp: set pubkey: %s\n", px_strerror(err));
		return 1;
	}

	err = pgp_decrypt(ctx, src, dst);
	if (err < 0) {
		if (tmp)
			mbuf_free(tmp);
		fprintf(stderr, "upgp: %s\n", px_strerror(err));
		return 1;
	}
	pgp_free(ctx);
	if (tmp)
		mbuf_free(tmp);

	len = mbuf_grab(dst, mbuf_avail(dst), &buf);

	fwrite(buf, len, 1, f_output);
	mbuf_free(dst);
	return 0;
}

enum {
	CMD_ENCRYPT = 'c',
	CMD_DECRYPT = 'd',
	SW_TEXTMODE_ON = 't',
	SW_COMP_LEVEL = 'z',
	CMD_DEARMOR = 1001,
	CMD_ENARMOR,
	CMD_LIST_PACKETS,
	CMD_CRYPT,
	CMD_TEST,
	SW_SALT,
	SW_SALT_TYPE,
	SW_PSW_FD,
	SW_S2K_MODE,
	SW_S2K_DIGEST,
	SW_S2K_CIPHER,
	SW_DIGEST,
	SW_CIPHER,
	SW_COMP_ALGO,
	SW_BATCH,
	SW_MDC_ON,
	SW_MDC_OFF,
	SW_SESSKEY_ON,
	SW_SESSKEY_OFF,
	SW_TEXTMODE_OFF,
	SW_KEYFILE,
	SW_CONVERT_CRLF_ON,
	SW_CONVERT_CRLF_OFF,

	CMD_TEST_HAVEGE,
	CMD_TEST_PXRAND,
};

static const struct option upgp_opt_list[] = {
	{"symmetric", 0, 0, 'c'},
	{"decrypt", 0, 0, 'd'},
	{"dearmor", 0, 0, CMD_DEARMOR},
	{"enarmor", 0, 0, CMD_ENARMOR},
	{"list-packets", 0, 0, CMD_LIST_PACKETS},
	{"test", 0, 0, CMD_TEST},

	{"armor", 0, 0, 'a'},
	{"password", 1, 0, 'p'},
	{"passprase-fd", 1, 0, SW_PSW_FD},
	{"output", 1, 0, 'o'},
	{"verbose", 0, 0, 'v'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'V'},
	{"quiet", 0, 0, 'q'},
	{"s2k-mode", 1, 0, SW_S2K_MODE},
	{"s2k-digest-algo", 1, 0, SW_S2K_DIGEST},
	{"s2k-cipher-algo", 1, 0, SW_S2K_CIPHER},
	{"digest-algo", 1, 0, SW_DIGEST},
	{"cipher-algo", 1, 0, SW_CIPHER},
	{"compress-level", 1, 0, SW_COMP_LEVEL},
	{"compress-algo", 1, 0, SW_COMP_ALGO},
	{"batch", 0, 0, SW_BATCH},
	{"force-mdc", 0, 0, SW_MDC_ON},
	{"disable-mdc", 0, 0, SW_MDC_OFF},
	{"textmode", 0, 0, SW_TEXTMODE_ON},
	{"no-textmode", 0, 0, SW_TEXTMODE_OFF},
	{"convert-crlf", 0, 0, SW_CONVERT_CRLF_ON},
	{"enable-sesskey", 0, 0, SW_SESSKEY_ON},
	{"disable-sesskey", 0, 0, SW_SESSKEY_OFF},
	{"crypt", 0, 0, CMD_CRYPT},
	{"salt", 1, 0, SW_SALT},
	{"salt-type", 1, 0, SW_SALT_TYPE},
	{"key", 1, 0, SW_KEYFILE},
	{"test-rand", 0, 0, CMD_TEST_RAND},
	{0, 0, 0, 0}
};

static const char *usage_str =
"usage: upgp [flags] [file]\n"
"Commands:\n"
"  -c, --symmetric               Symmetric encrypt\n"
"  -d, --decrypt                 Symmetric decrypt\n"
//"      --dearmor                 N/A\n"
//"      --enarmor                 N/A\n"
"      --list-packets            Parse and describe message structure\n"
"      --crypt                   unix password crypt\n"
"Switches:\n"
"      --salt SALT               Crypt: use existing salt\n"
"      --salt-type TYPE          Crypt: des,xdes,md5,bf (default: md5)\n"
"  -p, --password PSW            set password (insecure, for testing only)\n"
"  -a, --armor                   put ascii-armor on encrypt output\n"
"  -v, --verbose                 be verbose\n"
"  -q, --quiet                   NOP\n"
"      --batch                   NOP\n"
"  -V, --version                 print version\n"
"  -h, --help                    this help\n"
"      --passphrase-fd N         file descriptor to read password (default: stdin)\n"
"  -o, --output FILE             output file name (default: stdout)\n"
"      --s2k-mode N              set S2K algorithm (0, 1, 3) (default: 3)\n"
"      --s2k-digest-algo NAME    set S2K digest algorithm\n"
"      --s2k-cipher-algo NAME    set S2K cipher algorithm for separate session key\n"
"      --digest-algo NAME        NOP\n"
"      --cipher-algo NAME        set cipher algorithm\n"
"  -z, --compress-level N        set zlib compress level (0-9)\n"
"      --compress-algo N         0-none, 1-zip, 2-zlib, [3-bzip2 - N/A]\n"
"      --enable-sesskey          use separate sesskey\n"
"      --disable-sesskey         use S2K(psw) as sesskey (default)\n"
"  -t, --textmode                set packet type to text\n"
"      --no-textmode             set packet type to binary (default)\n"
"      --convert-crlf            convert crlf<->lf (default:off)\n"
"      --key FILE                read public/secret key from file\n"
;

static void usage(int err)
{
	printf("%s", usage_str);
	exit(err);
}

int main(int argc, char *argv[])
{
	FILE *f;
	char *fn = NULL;
	char *key_fn = NULL;
	char *out_fn = NULL;
	int c, cmd = 0, use_armor = 0;
	int need_password = 0;
	const char *password = NULL;
	int passfd = -1;
	MBuf *data;
	PullFilter *pf;
	int res;
	int verbose = 0;

	/*
	 * parse commandline
	 */

	while (1) {
		c = getopt_long(argc, argv, "xcdahvVp:qo:z:t", upgp_opt_list, NULL);
		if (c == -1)
			break;

		switch (c) {
		case CMD_ENCRYPT:
		case CMD_DECRYPT:
		case CMD_CRYPT:
			need_password = 1;
		case CMD_DEARMOR:
		case CMD_ENARMOR:
		case CMD_LIST_PACKETS:
			if (cmd) {
				fprintf(stderr, "conflicting command opttions");
				return 1;
			}
			cmd = c;
			break;
		case CMD_TEST:
			//f_test();
			return 1;
		case CMD_TEST_RAND:
			return randtest(0);
		case 'p':
			password = optarg;
			break;
		case 'a':
			use_armor = 1;
			break;
		case 'v':
			verbose++;
			px_set_debug_handler(handle_px_debug);
			break;
		case 'V':
			printf("%s", upgp_version);
			show_algos();
			return 0;
		case 'h':
			usage(0);
		case '?':
			usage(1);
		case 'q':
		case SW_BATCH:
			break;
		case 'o':
			out_fn = optarg;
			break;
		case SW_COMP_LEVEL:
			def_compr_level = atoi(optarg);
			break;
		case SW_COMP_ALGO:
			def_compr_algo = atoi(optarg);
			break;
		case SW_MDC_ON:
			def_disable_mdc = 0;
			break;
		case SW_MDC_OFF:
			def_disable_mdc = 1;
			break;
		case SW_SESSKEY_ON:
			def_use_sesskey = 1;
			break;
		case SW_SESSKEY_OFF:
			def_use_sesskey = 0;
			break;
		case SW_TEXTMODE_ON:
			def_textmode = 1;
			break;
		case SW_TEXTMODE_OFF:
			def_textmode = 0;
			break;
		case SW_CONVERT_CRLF_ON:
			def_convert_crlf = 1;
			break;
		case SW_S2K_MODE:
			def_s2k_mode = atoi(optarg);
			px_debug("set def_s2k_mode=%d", def_s2k_mode);
			break;
		case SW_S2K_DIGEST:
			def_s2k_digest_algo = optarg;
			break;
		case SW_S2K_CIPHER:
			def_s2k_cipher_algo = optarg;
			break;
		case SW_CIPHER:
			def_cipher_algo = optarg;
			break;
		case SW_DIGEST:
			def_digest_algo = optarg;
			break;
		case SW_PSW_FD:
			passfd = atoi(optarg);
			break;
		case SW_SALT:
			crypt_salt = optarg;
			break;
		case SW_SALT_TYPE:
			crypt_salt_type = optarg;
			break;
		case SW_KEYFILE:
			key_fn = optarg;
			break;
		case 'x':
			do_test();
			return 0;
			break;
		default:
			fprintf(stderr, "buggy option: %d\n", c);
			return 1;
		}
	}

	if (cmd == 0) {
		fprintf(stderr, "upgp: need command (use -h for help)\n");
		return 1;
	}

	if (optind < argc) {
		if (argc - optind > 1)
			usage(1);
		fn = argv[optind];
	}

	/*
	 * pick input
	 */

	if (fn) {
		f = fopen(fn, "r");
		if (f == NULL) {
			perror(fn);
			return 1;
		}
	} else {
		f = stdin;
	}

	/*
	 * pick output
	 */

	if (out_fn) {
		f_output = fopen(out_fn, "w");
		if (f_output == NULL) {
			perror(out_fn);
			return 1;
		}
	} else {
		f_output = stdout;
	}

	/*
	 * read password
	 */

	if (need_password && password == NULL) {
		if (passfd >= 0) {
			static char pwbuf[1024];
			FILE *pf = fdopen(passfd, "r");
			int len;
			if (!pf) {
				perror("passphrase-fd");
				return 1;
			}
			if (!fgets(pwbuf, sizeof(pwbuf), pf)) {
				perror("read from passphrase-fd");
				return -1;
			}
			len = strlen(pwbuf);
			if (pwbuf[len - 1] == '\n')
				pwbuf[len - 1] = 0;
			fclose(pf);
			password = pwbuf;
		} else {
			password = getpass("Password: ");
		}
		if (!password)
			return 1;
	}

	/*
	 * launch command
	 */

	switch (cmd) {
	case 'c':
		data = load_stream(f);
		res = encrypt_stream(data, password, use_armor, key_fn);
		break;
	case 'd':
		data = load_stream(f);
		res = decrypt_stream(data, password, key_fn);
		break;
	case CMD_LIST_PACKETS:
		data = load_stream(f);
		res = pullf_create_mbuf_reader(&pf, data);
		if (res < 0) {
			fprintf(stderr, "upgp: %s\n", px_strerror(res));
			res = 1;
			break;
		}
		res = list_packets(pf);
		pullf_free(pf);
		break;
	case CMD_CRYPT:
		res = crypt_cmd(password);
		break;
	case CMD_ENARMOR:
	case CMD_DEARMOR:
		fprintf(stderr, "upgp: unimplemented command\n");
		res = 1;
		break;
	default:
		fprintf(stderr, "upgp: need command (use -h for help)\n");
		res = 1;
	}

	/* done */
	if (fn)
		fclose(f);
	fclose(f_output);
	return res;
}

