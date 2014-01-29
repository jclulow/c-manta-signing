

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "crypto_utils.h"

char *
base64encode(uint8_t *data, size_t datalen)
{
	BIO *b64, *bio;
	BUF_MEM *bptr;
	char *out;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_write(bio, data, datalen);
	BIO_flush(bio);

	BIO_get_mem_ptr(bio, &bptr);
	out = malloc(bptr->length + 1);
	bcopy(bptr->data, out, bptr->length);
	out[bptr->length] = '\0';

	BIO_free_all(bio);

	return (out);
}

char *
key_signature(uint8_t *key, size_t keylen)
{
	const EVP_MD *md = NULL;
	EVP_MD_CTX *mdctx = NULL;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len = 0;
	char *ret = NULL;
	unsigned int i;

	md = EVP_md5();
	if ((md = EVP_md5()) == NULL)
		return (NULL);

	if ((mdctx = EVP_MD_CTX_create()) == NULL)
		return (NULL);

	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1 ||
	    EVP_DigestUpdate(mdctx, key, keylen) != 1 ||
	    EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1) {
		goto out;
	}

	/*
	 * Output format:
	 *   00:01:02:......:NN<NUL>
	 */
	ret = malloc(md_len * 3);
	if (ret == NULL)
		goto out;

	for (i = 0; i < md_len; i++) {
		snprintf(ret + i * 3, 3, "%02x", md_value[i]);
		ret[i * 3 + 2] = (i == md_len - 1) ? '\0' : ':';
	}

out:
	if (mdctx != NULL)
		EVP_MD_CTX_destroy(mdctx);
	return (ret);
}
