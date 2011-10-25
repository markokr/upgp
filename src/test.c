
#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>

#include <postgres.h>

#include "px.h"
#include "mbuf.h"
#include "pgp.h"

#include <openssl/evp.h>
#include <openssl/des.h>

/*
 * main stuff
 */

//gpg: thekey EF F0 72 8F 76 20 C2 10 3A C1 BB F5 49 DB AF 39
//gpg: prefix 9E DA 6E 1A F6 DF D3 1A D3 1A
static char *encdata =
"-----BEGIN PGP MESSAGE-----\n"
"\n"
"jA0EAgMCNcDkMfNzRbhgyRv3UuRxKLv3bJ0RWsk1JylwWLERXVQG0TboqwM=\n"
"=5ytE\n"
"-----END PGP MESSAGE-----\n"
;

void test_decrypt()
{
	int err;
	PGP_Context *ctx = NULL;
	char *psw = "jura";
	MBuf *src, *dst;
	uint8 *res, *ebuf;
	unsigned rlen, alen, elen;

	alen = strlen(encdata);
	elen = mk_dearmor(encdata, alen, &ebuf);
	
	src = mbuf_create_from_mem(ebuf, elen);
	dst = mbuf_create(8192);
	err = pgp_init(psw, strlen(psw), &ctx);
	if (err) {
		elog(ERROR, "pgp_init: %d", err);
		goto done;
	}
	err = pgp_decrypt(ctx, src, dst);
	if (err) {
		elog(ERROR, "pgp_encrypt: %d", err);
		goto done;
	}
	rlen = mbuf_get_buf(dst, &res);
	res[rlen] = 0;
	
	printf("rlen: %d,  res=%s\n", rlen, res);
done:
	pgp_free(ctx);
}
void test_encrypt()
{
	int err;
	PGP_Context *ctx = NULL;
	char *psw = "jura";
	char *str = "Obfuscation does not work.\n";
	MBuf *src, *dst, *dec;
	uint8 *res, *armored;
	unsigned rlen, alen;

	src = mbuf_create_from_mem(str, strlen(str));
	dst = mbuf_create(8192);
	err = pgp_init(psw, strlen(psw), &ctx);
	if (err) {
		elog(ERROR, "pgp_init: %d", err);
		goto done;
	}
	err = pgp_encrypt(ctx, src, dst);
	if (err) {
		elog(ERROR, "pgp_encrypt: %d", err);
		goto done;
	}
	rlen = mbuf_get_buf(dst, &res);
	alen = mk_armor(res, rlen, &armored);
	fwrite(armored, 1, alen, stdout);
	pgp_free(ctx);

	// try to decrypt
	mbuf_rewind(dst);
	dec = mbuf_create(8192);
	err = pgp_init(psw, strlen(psw), &ctx);
	if (err) {
		elog(ERROR, "dec:pgp_init: %d", err);
		goto done;
	}
	err = pgp_decrypt(ctx, dst, dec);
	if (err) {
		elog(ERROR, "dec:pgp_encrypt: %d", err);
		goto done;
	}
	rlen = mbuf_get_buf(dec, &res);
	res[rlen] = 0;
	printf("got (%d): ", rlen);
	fwrite(res, 1, rlen, stdout);
	printf("\n------\n");
	print_hex("%s\n", res, rlen);
	if (strlen(str) != rlen || memcmp(res, str, rlen)) {
		printf("failed\n");
	} else {
		printf("ok\n");
	}
	
	// done
	
done:
	return;
}

static uint8 c5_key [] = {
0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A };
static uint8 c5_plain [] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
};
static uint8 c5_cipher [] = {
	0x23, 0x8B, 0x4F, 0xE5, 0x84, 0x7E, 0x44, 0xB2
};

void test_cast5_px()
{
	int err, len;
	uint8 buf[256];
	PX_Cipher *c;
	err = px_find_cipher("cast5-ecb", &c);
	if (err < 0) {
		printf("cast5 not found\n");
		return;
	}
	px_cipher_init(c, c5_key, 16, NULL);
	len = sizeof(c5_plain);
	px_cipher_encrypt(c, c5_plain, len, buf);
	if (memcmp(buf, c5_cipher, len)) {
		printf("c5px failed\n");
		print_hex("c5px got: %s\n", buf, len);
		print_hex("  needed: %s\n", c5_cipher, len);
	} else {
		printf("c5px ok\n");
	}
}

void test_cast5_evp()
{
	int len, klen, blen;
	uint8 buf[256], *p, iv[16];
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cast;

	klen = sizeof(c5_key);
	len = sizeof(c5_plain);
	memset(iv, 0, sizeof(iv));
	memset(&ctx, 0, sizeof(ctx));
	
	cast = EVP_get_cipherbyname("cast5-ecb");
	if (cast == NULL) {
		printf("cipher not found\n");
		return;
	}
	printf("evp_bs=%d\n", EVP_CIPHER_block_size(cast));
	printf("evp_klen=%d\n", EVP_CIPHER_key_length(cast));
	printf("evp_iv_len=%d\n", EVP_CIPHER_iv_length(cast));
	
	EVP_EncryptInit(&ctx, cast, c5_key, iv);
	//cast->init(&ctx, c5_key, iv, 1);
	printf("initok\n");
	blen = 0;
	//cast->do_cipher(&ctx, buf, c5_plain, len);
	EVP_EncryptUpdate(&ctx, buf, &blen, c5_plain, len);
	printf("updok: %d\n", blen);
	p = buf + blen;
	blen = 0;
	EVP_EncryptFinal(&ctx, p, &blen);
	printf("finok: %d\n", blen);
	p += blen;

	blen = p - buf;
	
	if (memcmp(buf, c5_cipher, len)) {
		printf("c5evp failed\n");
		print_hex("c5evp got: %s\n", buf, len);
		print_hex("  needed: %s\n", c5_cipher, len);
	} else {
		printf("c5evp ok\n");
	}
}

void test_cast5_ssl()
{
	int len, klen;
	uint8 buf[256];
	CAST_KEY k;
	klen = sizeof(c5_key);
	len = sizeof(c5_plain);

	klen = sizeof(c5_key);
	len = sizeof(c5_plain);
	CAST_set_key(&k, klen, c5_key);
	CAST_ecb_encrypt(c5_plain, buf, &k, CAST_ENCRYPT);

	if (memcmp(buf, c5_cipher, len)) {
		printf("c5ssl failed\n");
		print_hex("c5ssl got: %s\n", buf, len);
		print_hex("   needed: %s\n", c5_cipher, len);
	} else {
		printf("c5ssl ok\n");
	}
}

const uint8 d3_key [] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
	0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23
};
const uint8 d3_plain [] = {
	0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74
};
const uint8 d3_result [] = {
	0xdd, 0x17, 0xe8, 0xb8, 0xb4, 0x37, 0xd2, 0x32
};

void test_3des()
{
	int len, klen;
	uint8 buf[256];
	des_key_schedule k1, k2, k3;

	memset(k1, 0, sizeof(k1));
	memset(k2, 0, sizeof(k2));
	memset(k3, 0, sizeof(k3));
	len = 8;
	des_check_key = 0;
	des_set_key_unchecked((des_cblock*)&d3_key[0], k1);
	des_set_key_unchecked((des_cblock*)&d3_key[8], k2);
	des_set_key_unchecked((des_cblock*)&d3_key[16], k3);

	des_ecb3_encrypt(d3_plain, buf, k1, k2, k3, 1);

	if (memcmp(buf, d3_result, len)) {
		printf("d3ssl failed\n");
		print_hex("d3ssl got: %s\n", buf, len);
		print_hex("   needed: %s\n", d3_result, len);
	} else {
		printf("d3ssl ok\n");
	}
}

int main(int argc, char *argv[])
{
	//test_cast5_px();
	//test_cast5_ssl();
	//test_cast5_evp();
	//test_3des();
	test_decrypt();
	//test_encrypt();
	return 0;
}
