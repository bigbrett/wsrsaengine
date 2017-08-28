/*
 * 
 *
 *
 *
 *
 *
 *
 *
 *
 * Author: Brett Nicholas
 */
#include <openssl/engine.h>
#include <openssl/rsa.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>

// Turn off this annoying warning that we don't care about 
//#pragma GCC diagnostic ignored "-Wsizeof-pointer-memaccess"

// TODO we need to sort out proper return values
#define FAIL -1
#define SUCCESS 1

static const char *engine_id = "  wsrsa";
static const char *engine_name = "A test engine for the ws rsa hardware encryption module, on the Xilinx ZYNQ7000";

static int wsrsaengine_rsa_init(RSA *rsa);
static int wsrsaengine_rsa_public_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
static int wsrsaengine_rsa_public_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
static int wsrsaengine_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);
static int wsrsaengine_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
static int wsrsaengine_rsa_private_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
static int wsrsaengine_rsa_private_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
static int wsrsaengine_rsa_finish(RSA *rsa);

static const RSA_METHOD *default_rsa_meth;

//
// Create our own RSA method matching that of the OpenSSL RSA_METH 
// structure (struct rsa_meth_st). 
//  - RSA_METH is typedef'ed in openssl/include/openssl/ossl_typ.h
//  - struct rsa_meth_st is defined in openssl/crypto/rsa/rsa_locl.h
// 
// Here is the struct definition for reference:
//
//  struct rsa_meth_st {
//      char *name;
//      int (*rsa_pub_enc) (int flen, const unsigned char *from,
//                          unsigned char *to, RSA *rsa, int padding);
//      int (*rsa_pub_dec) (int flen, const unsigned char *from,
//                          unsigned char *to, RSA *rsa, int padding);
//      int (*rsa_priv_enc) (int flen, const unsigned char *from,
//                           unsigned char *to, RSA *rsa, int padding);
//      int (*rsa_priv_dec) (int flen, const unsigned char *from,
//                           unsigned char *to, RSA *rsa, int padding);
//      /* Can be null */
//      int (*rsa_mod_exp) (BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);
//      /* Can be null */
//      int (*bn_mod_exp) (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
//                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
//      /* called at new */
//      int (*init) (RSA *rsa);
//      /* called at free */
//      int (*finish) (RSA *rsa);
//      /* RSA_METHOD_FLAG_* things */
//      int flags;
//      /* may be needed! */
//      char *app_data;
//      /*
//       * New sign and verify functions: some libraries don't allow arbitrary
//       * data to be signed/verified: this allows them to be used. Note: for
//       * this to work the RSA_public_decrypt() and RSA_private_encrypt() should
//       * *NOT* be used RSA_sign(), RSA_verify() should be used instead.
//       */
//      int (*rsa_sign) (int type,
//                       const unsigned char *m, unsigned int m_length,
//                       unsigned char *sigret, unsigned int *siglen,
//                       const RSA *rsa);
//      int (*rsa_verify) (int dtype, const unsigned char *m,
//                         unsigned int m_length, const unsigned char *sigbuf,
//                         unsigned int siglen, const RSA *rsa);
//      /*
//       * If this callback is NULL, the builtin software RSA key-gen will be
//       * used. This is for behavioural compatibility whilst the code gets
//       * rewired, but one day it would be nice to assume there are no such
//       * things as "builtin software" implementations.
//       */
//      int (*rsa_keygen) (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
//  };
static RSA_METHOD wsrsaengine_rsa_method = 
{
	"wsRSA1024 method",
	NULL,//wsrsaengine_rsa_public_enc,
	NULL,//wsrsaengine_rsa_public_dec,
	NULL,//wsrsaengine_rsa_private_enc, // int (*rsa_priv_enc)
	NULL,//wsrsaengine_rsa_private_dec, // int (*rsa_priv_dec)
	wsrsaengine_rsa_mod_exp, // Called for private key operations
	wsrsaengine_bn_mod_exp,  // Called for public key operations
	NULL,//wsrsaengine_rsa_init,
	NULL,//wsrsaengine_rsa_finish,		
/* NOTE ON THE FOLLOWING FIELD: RSA_FLAG_EXT_PKEY
 * This flag means the private key operations will be handled by rsa_mod_exp
 * and that they do not depend on the private key components being present:
 * for example a key stored in external hardware. Without this flag
 * bn_mod_exp gets called when private key components are absent.
 */
    RSA_FLAG_EXT_PKEY, // RSA_FLAG_CACHE_PUBLIC|RSA_FLAG_CACHE_PRIVATE
	NULL,						// char *app_data
	NULL,						// int (*rsa_sign)
	NULL,						// int (*rsa_verify)
	NULL						// int (*rsa_keygen)
}; 


/*
 * RSA_METH initialization function. 
 */
static int wsrsaengine_rsa_init(RSA *rsa)
{
   	// Initialize hardware  
    
    printf("  wsrsaengine_rsa_init()\n");
	return default_rsa_meth->init(rsa);
}



/*
 * RSA_METH cleanup function
 */
static int wsrsaengine_rsa_finish(RSA *rsa)
{
	// what should we do here? 
    printf("  wsrsaengine_rsa_finish()\n");
	//return SUCCESS;
    return default_rsa_meth->finish(rsa);
}


/*
 *
 */
static int wsrsaengine_rsa_public_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    printf("  wsrsaengine_rsa_public_enc()\n");
    return SUCCESS;
    //return default_rsa_meth->rsa_pub_enc(flen, from, to, rsa, padding);
}


/*
 * 
 */
static int wsrsaengine_rsa_public_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    printf("  wsrsaengine_rsa_public_dec()\n");
    return SUCCESS;
    //return default_rsa_meth->rsa_pub_dec(flen, from, to, rsa, padding);
}


/*
 *
 */
static int wsrsaengine_rsa_private_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    printf("  wsrsaengine_rsa_private_enc()\n");
    return SUCCESS;
    //return default_rsa_meth->rsa_priv_enc(flen, from, to, rsa, padding);
}


/*
 *
 */
static int wsrsaengine_rsa_private_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    printf("  wsrsaengine_rsa_private_dec()\n");    
    return SUCCESS;
    //return default_rsa_meth->rsa_priv_dec(flen, from, to, rsa, padding);
}


/*
 *
 */
static int wsrsaengine_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    printf("  wsrsaengine_rsa_mod_exp()\n");
    if (rsa->meth == NULL)
        printf("    null method\n");
    if (rsa->engine == NULL)
        printf("    null engine\n");
    if (rsa->n == NULL)
        printf("    null n\n");
    if (rsa->e == NULL)
        printf("    null e\n");
    if (rsa->d == NULL)
        printf("    null d\n");
    if (rsa->p == NULL)
        printf("    null p\n");
    if (rsa->q == NULL)
        printf("    null q\n");
    return default_rsa_meth->rsa_mod_exp(r0,I,rsa,ctx);
}

static int wsrsaengine_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    printf("  wsrsaengine_bn_mod_exp()\n");
    return default_rsa_meth->bn_mod_exp(r,a,p,m,ctx,m_ctx);
}


/*
 * Engine Initialization:
 */
int wsrsaengine_init(ENGINE *e)
{
    printf("  wsrsaengine_init()\n");
    return SUCCESS;
}


/*
 * Engine finish function
 */
int wsrsaengine_finish(ENGINE *e)
{
    printf("  wsrsaengine_finish()\n");
    return SUCCESS;
}


/*
 *  Engine binding function
 */
static int bind(ENGINE *e, const char *id)
{
	int ret = FAIL;

	if (!ENGINE_set_id(e, engine_id))
	{
		fprintf(stderr, "ENGINE_set_id failed\n");
		goto end;
	}
	if (!ENGINE_set_name(e, engine_name))
	{
		fprintf(stderr,"ENGINE_set_name failed\n"); 
		goto end;
	}
	if (!ENGINE_set_init_function(e, wsrsaengine_init))
	{
		fprintf(stderr,"ENGINE_set_init_function failed\n"); 
		goto end;
	}
    if (!ENGINE_set_finish_function(e, wsrsaengine_finish))
	{
		fprintf(stderr,"ENGINE_set_finish_function failed\n"); 
		goto end;
	}
	if (!ENGINE_set_RSA(e, &wsrsaengine_rsa_method )) 
	{
		fprintf(stderr,"ENGINE_set_RSA failed\n");
		goto end;
	}

    
    default_rsa_meth = RSA_PKCS1_SSLeay();
    wsrsaengine_rsa_method.rsa_pub_enc = default_rsa_meth->rsa_pub_enc;
    wsrsaengine_rsa_method.rsa_pub_dec = default_rsa_meth->rsa_pub_dec;
    wsrsaengine_rsa_method.rsa_priv_enc = default_rsa_meth->rsa_priv_enc;
    wsrsaengine_rsa_method.rsa_priv_dec = default_rsa_meth->rsa_priv_dec;
    wsrsaengine_rsa_method.init= default_rsa_meth->init;
    wsrsaengine_rsa_method.finish = default_rsa_meth->finish;

	ret = SUCCESS; 
end: 
	return ret; 
}

// REGISTER BINDING FUNCTIONS
IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
