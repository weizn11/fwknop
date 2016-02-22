/*
 *****************************************************************************
 *
 * File:    fko_hmac.c
 *
 * Purpose: Provide HMAC support to SPA communications
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *****************************************************************************
*/
#include "fko_common.h"
#include "fko.h"
#include "cipher_funcs.h"
#include "hmac.h"
#include "base64.h"

int
fko_verify_hmac(fko_ctx_t ctx,
    const char * const hmac_key, const int hmac_key_len)
{
    char    *hmac_digest_from_data = NULL;
    char    *tbuf = NULL;
    int      res = FKO_SUCCESS;
    int      hmac_b64_digest_len = 0, zero_free_rv = FKO_SUCCESS;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_key == NULL)
        return(FKO_ERROR_INVALID_DATA);

    if (! is_valid_encoded_msg_len(ctx->encrypted_msg_len))
        return(FKO_ERROR_INVALID_DATA_HMAC_MSGLEN_VALIDFAIL);

    if(hmac_key_len < 0 || hmac_key_len > MAX_DIGEST_BLOCK_LEN)
        return(FKO_ERROR_INVALID_HMAC_KEY_LEN);

	//获取HMAC摘要类型对应的长度。
    if(ctx->hmac_type == FKO_HMAC_MD5)
        hmac_b64_digest_len = MD5_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA1)
        hmac_b64_digest_len = SHA1_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA256)
        hmac_b64_digest_len = SHA256_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA384)
        hmac_b64_digest_len = SHA384_B64_LEN;
    else if(ctx->hmac_type == FKO_HMAC_SHA512)
        hmac_b64_digest_len = SHA512_B64_LEN;
    else
        return(FKO_ERROR_UNSUPPORTED_HMAC_MODE);

    if((ctx->encrypted_msg_len - hmac_b64_digest_len)
            < MIN_SPA_ENCODED_MSG_SIZE)
        return(FKO_ERROR_INVALID_DATA_HMAC_ENCMSGLEN_VALIDFAIL);

    /* Get digest value
    */
    //从数据包中获取HMAC摘要数据。
    hmac_digest_from_data = strndup((ctx->encrypted_msg
            + ctx->encrypted_msg_len - hmac_b64_digest_len),
            hmac_b64_digest_len);

    if(hmac_digest_from_data == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* Now we chop the HMAC digest off of the encrypted msg
    */
    //在数据包的HMAC密文中除去摘要数据。
    tbuf = strndup(ctx->encrypted_msg,
            ctx->encrypted_msg_len - hmac_b64_digest_len);

    if(tbuf == NULL)
    {
        if(zero_free(hmac_digest_from_data, strnlen(hmac_digest_from_data,
                MAX_SPA_ENCODED_MSG_SIZE)) == FKO_SUCCESS)
            return(FKO_ERROR_MEMORY_ALLOCATION);
        else
            return(FKO_ERROR_ZERO_OUT_DATA);
    }

    if(zero_free(ctx->encrypted_msg, ctx->encrypted_msg_len) != FKO_SUCCESS)
        zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    ctx->encrypted_msg      = tbuf;
    ctx->encrypted_msg_len -= hmac_b64_digest_len;	//密文长度减去摘要base64编码的长度。

	//密文类型是GPG.
    if(ctx->encryption_mode == FKO_ENC_MODE_ASYMMETRIC)
    {
        /* See if we need to add the "hQ" string to the front of the
         * encrypted data.
         */
        if(! ctx->added_gpg_prefix)
        {
            res = add_gpg_prefix(ctx);
        }
    }
    else
    {
        /* See if we need to add the "Salted__" string to the front of the
         * encrypted data.
         */
        if(! ctx->added_salted_str)
        {
        	//还原加盐密文。
            res = add_salted_str(ctx);
        }
    }

    if (res != FKO_SUCCESS)
    {
        if(zero_free(hmac_digest_from_data, strnlen(hmac_digest_from_data,
                        MAX_SPA_ENCODED_MSG_SIZE)) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

        if(zero_free_rv == FKO_SUCCESS)
            return(res);
        else
            return(zero_free_rv);
    }

    /* Calculate the HMAC from the encrypted data and then
     * compare
    */
    //计算HMAC密文然后再做比较。
    res = fko_set_spa_hmac_type(ctx, ctx->hmac_type);	//设置HMAC加密类型。
    if(res == FKO_SUCCESS)
    {
    	//计算encrypted_msg的HMAC摘要，存在ctx->msg_hmac。
        res = fko_set_spa_hmac(ctx, hmac_key, hmac_key_len);

        if(res == FKO_SUCCESS)
        {
        	//校验HMAC摘要。
            if(constant_runtime_cmp(hmac_digest_from_data,
                    ctx->msg_hmac, hmac_b64_digest_len) != 0)
            {
                res = FKO_ERROR_INVALID_DATA_HMAC_COMPAREFAIL;	//不匹配则返回ERROE.
            }
        }
    }

    if(zero_free(hmac_digest_from_data, strnlen(hmac_digest_from_data,
                    MAX_SPA_ENCODED_MSG_SIZE)) != FKO_SUCCESS)
        zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(res == FKO_SUCCESS)
        return(zero_free_rv);
    else
        return(res);
}

/* Return the fko HMAC data
*/
int
fko_get_spa_hmac(fko_ctx_t ctx, char **hmac_data)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_data == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *hmac_data = ctx->msg_hmac;

    return(FKO_SUCCESS);
}

/* Set the HMAC type
*/
int
fko_set_spa_hmac_type(fko_ctx_t ctx, const short hmac_type)
{
#if HAVE_LIBFIU
    fiu_return_on("fko_set_spa_hmac_type_init",
            FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

#if HAVE_LIBFIU
    fiu_return_on("fko_set_spa_hmac_type_val",
            FKO_ERROR_INVALID_DATA_HMAC_TYPE_VALIDFAIL);
#endif

    if(hmac_type < 0 || hmac_type >= FKO_LAST_HMAC_MODE)
        return(FKO_ERROR_INVALID_DATA_HMAC_TYPE_VALIDFAIL);

    ctx->hmac_type = hmac_type;

    ctx->state |= FKO_HMAC_MODE_MODIFIED;

    return(FKO_SUCCESS);
}

/* Return the fko HMAC type
*/
int
fko_get_spa_hmac_type(fko_ctx_t ctx, short *hmac_type)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_type == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *hmac_type = ctx->hmac_type;

    return(FKO_SUCCESS);
}

int fko_set_spa_hmac(fko_ctx_t ctx,
    const char * const hmac_key, const int hmac_key_len)
{
    unsigned char hmac[SHA512_DIGEST_STR_LEN] = {0};
    char *hmac_base64 = NULL;
    int   hmac_digest_str_len = 0;
    int   hmac_digest_len = 0;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(hmac_key == NULL)
        return(FKO_ERROR_INVALID_DATA);

    if(hmac_key_len < 0 || hmac_key_len > MAX_DIGEST_BLOCK_LEN)
        return(FKO_ERROR_INVALID_HMAC_KEY_LEN);

	//根据hmac摘要类型进行相关操作。
    if(ctx->hmac_type == FKO_HMAC_MD5)
    {
        hmac_md5(ctx->encrypted_msg,	//base64编码的Rijndael密文。
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = MD5_DIGEST_LEN;
        hmac_digest_str_len = MD5_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA1)
    {
        hmac_sha1(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA1_DIGEST_LEN;
        hmac_digest_str_len = SHA1_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA256)
    {
        hmac_sha256(ctx->encrypted_msg,	//default
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA256_DIGEST_LEN;
        hmac_digest_str_len = SHA256_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA384)
    {
        hmac_sha384(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA384_DIGEST_LEN;
        hmac_digest_str_len = SHA384_DIGEST_STR_LEN;
    }
    else if(ctx->hmac_type == FKO_HMAC_SHA512)
    {
        hmac_sha512(ctx->encrypted_msg,
            ctx->encrypted_msg_len, hmac, hmac_key, hmac_key_len);

        hmac_digest_len     = SHA512_DIGEST_LEN;
        hmac_digest_str_len = SHA512_DIGEST_STR_LEN;
    }

    hmac_base64 = calloc(1, MD_HEX_SIZE(hmac_digest_len)+1);
    if (hmac_base64 == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

	//将HMAC摘要编码为base64格式。
    b64_encode(hmac, hmac_base64, hmac_digest_len);
    strip_b64_eq(hmac_base64);
	
    if(ctx->msg_hmac != NULL)
        free(ctx->msg_hmac);

	//将base64编码过的HMAC密文存储。
    ctx->msg_hmac = strdup(hmac_base64);

    free(hmac_base64);
	printf("msg_hmac:%s\n\n",ctx->msg_hmac);
    if(ctx->msg_hmac == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    ctx->msg_hmac_len = strnlen(ctx->msg_hmac, hmac_digest_str_len);

    switch(ctx->msg_hmac_len)
    {
        case MD5_B64_LEN:
            break;
        case SHA1_B64_LEN:
            break;
        case SHA256_B64_LEN:
            break;
        case SHA384_B64_LEN:
            break;
        case SHA512_B64_LEN:
            break;
        default:
            return(FKO_ERROR_INVALID_DATA_HMAC_LEN_VALIDFAIL);
    }

    return FKO_SUCCESS;
}

/***EOF***/
