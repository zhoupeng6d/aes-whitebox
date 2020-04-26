/*
 * @Date: 2020-04-18 15:11:04
 * @LastEditors: Dash Zhou
 * @LastEditTime: 2020-04-26 11:30:48
 */
// Copyright 2019 AES WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "aunit.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <math.h>
#include <string.h>
#include <stdbool.h>

#include "aes.h"
#include "aes_whitebox.h"

#include <time.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static void err_quit(const char *fmt, ...) {
  va_list ap;
  char buf[1024];

  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  strcat(buf, "\n");
  fputs(buf, stderr);
  fflush(stderr);
  va_end(ap);

  exit(1);
}

static void read_hex(const char *in, uint8_t* v, size_t size, const char* param_name) {
  if (strlen(in) != size << 1) {
    err_quit("Invalid param %s (got %d, expected %d)",
        param_name, strlen(in), size << 1);
  }
  for (size_t i = 0; i < size; i++) {
    sscanf(in + i * 2, "%2hhx", v + i);
  }
}

void syntax(const char* program_name) {
  err_quit("Syntax: %s <cfb|ofb|ctr>"
      " <hex-plain>"
      " <hex-ir-or-nonce>"
      " <hex-cipher>", program_name);
}


bool aes_encrypt(const unsigned char *plaintext, int plaintext_len,
            const unsigned char *key, const unsigned char *iv,
            unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len = 0;

    int ciphertext_len = 0;

    int ret = -1;


    /* Create and initialise the context */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) goto err;

    /* Initialise the encryption operation. */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, NULL, NULL) != 1)
        goto err;

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    //if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
    //   goto err;

    /* Initialise key and IV */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)  goto err;

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    //if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    //   handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        goto err;
    ciphertext_len = len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if (EVP_EncryptFinal_ex(ctx, ciphertext, &len) != 1)  goto err;
    //ciphertext_len += len;

    /* Get the tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
         goto err;

err:
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return (ciphertext_len==plaintext_len);
}

bool aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
            const unsigned char *tag, const unsigned char *key, const unsigned char *iv,
            unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret = -1;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) goto err;

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, NULL, NULL))
        goto err;

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    //if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL))
    //    goto err;

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto err;

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    //if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    //    handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        goto err;
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag))
        goto err;

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext, &len);
    //plaintext_len = len;

err:
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        /* Success */
        return (plaintext_len==ciphertext_len);
    }
    else
    {
        /* Verify failed */
        return false;
    }
}

au_main

{
  uint8_t plain[4*16], iv_or_nonce[16], cipher[4*16], output[4*16];
  uint8_t openssl_output[4*16];
  uint8_t openssl_key[32];
  volatile clock_t start = 0,ends = 0;

  void (*encrypt)(const uint8_t iv[16], const uint8_t* m,
      size_t len, uint8_t* c);
  void (*decrypt)(const uint8_t iv[16], const uint8_t* m,
      size_t len, uint8_t* c);

  read_hex(argv[2], plain, 4*16, "plain");
  read_hex(argv[3], iv_or_nonce, 16, "iv-or-nonce");
  read_hex(argv[4], cipher, 4*16, "cipher");

  if (argc >= 6)
    read_hex(argv[5], openssl_key, 32, "key");

  if (argc < 5) {
    syntax(argv[0]);
  } else if (strcmp(argv[1], "cfb") == 0) {
    encrypt = &aes_whitebox_encrypt_cfb;
    decrypt = &aes_whitebox_decrypt_cfb;
  } else if (strcmp(argv[1], "ofb") == 0) {
    encrypt = &aes_whitebox_encrypt_ofb;
    decrypt = &aes_whitebox_decrypt_ofb;
  } else if (strcmp(argv[1], "ctr") == 0) {
    encrypt = &aes_whitebox_encrypt_ctr;
    decrypt = &aes_whitebox_decrypt_ctr;
  } else {
    syntax(argv[0]);
  }

  start=clock();
  (*encrypt)(iv_or_nonce, plain, sizeof(plain), output);
  ends=clock();
  printf("Encrypt time consumption：%f us \n", (double)(ends - start));
  au_eq("Encrypt, vector #1", memcmp(output, cipher, sizeof(cipher)), 0);

  if (argc >= 6)
  {
    start=clock();
    aes_encrypt(plain, sizeof(plain), openssl_key, iv_or_nonce, openssl_output, NULL);
    ends=clock();
    printf("Encrypt openssl time consumption：%f us \n", (double)(ends - start));
    au_eq("Encrypt, openssl", memcmp(openssl_output, cipher, sizeof(cipher)), 0);
  }

  if (argc >= 6)
  {
    start=clock();
    aes_encrypt(plain, sizeof(plain), openssl_key, iv_or_nonce, openssl_output, NULL);
    ends=clock();
    printf("Encrypt openssl time consumption：%f us \n", (double)(ends - start));
    au_eq("Encrypt, openssl", memcmp(openssl_output, cipher, sizeof(cipher)), 0);
  }

  start=clock();
  (*decrypt)(iv_or_nonce, cipher, sizeof(cipher), output);
  ends=clock();
  printf("Decrypt time consumption：%f us \n", (double)(ends - start));
  au_eq("Decrypt, vector #1", memcmp(output, plain, sizeof(plain)), 0);

  if (argc >= 6)
  {
    start=clock();
    aes_decrypt(cipher, sizeof(cipher), NULL, openssl_key, iv_or_nonce, openssl_output);
    ends=clock();
    printf("Decrypt openssl time consumption：%f us \n", (double)(ends - start));
    au_eq("Decrypt, vector #1", memcmp(output, plain, sizeof(plain)), 0);
  }

  start=clock();
  (*encrypt)(iv_or_nonce, plain, 7, output);
  ends=clock();
  printf("encrypt time consumption：%f us \n", (double)(ends - start));
  au_eq("Encrypt, vector #2", memcmp(output, cipher, 7), 0);

  if (argc >= 6)
  {
    start=clock();
    aes_encrypt(plain, 7, openssl_key, iv_or_nonce, openssl_output, NULL);
    ends=clock();
    printf("encrypt openssl time consumption：%f us \n", (double)(ends - start));
    au_eq("Encrypt, openssl", memcmp(openssl_output, cipher, 7), 0);
  }


  start=clock();
  (*decrypt)(iv_or_nonce, cipher, 7, output);
  ends=clock();
  printf("decrypt time consumption：%f us \n", (double)(ends - start));
  au_eq("Decrypt, vector #2", memcmp(output, plain, 7), 0);

  if (argc >= 6)
  {
    start=clock();
    aes_decrypt(cipher, 7, NULL, openssl_key, iv_or_nonce, openssl_output);
    ends=clock();
    printf("Decrypt openssl time consumption：%f us \n", (double)(ends - start));
    au_eq("Decrypt, vector #1", memcmp(output, plain, 7), 0);
  }
}

au_endmain
