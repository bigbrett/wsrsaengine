#include <stdio.h>							/* printf */
#include <stdlib.h> 						/* strtol */
#include <stdint.h>							/* uintXX_t */
#include <stdbool.h>						/* true/false */
#include <string.h>

#include <openssl/conf.h>				/* SSL implementation */
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>

#define HWSUCCESS 0
#define HWFAIL -1

#define BUFFSIZE 1024/8			 		 /* data buffer is 128 Bytes */
#define MAXBYTES ((uint32_t)BUFFSIZE-11) /* Largest data that can be encrypted with 128-byte modulus and PKCS#1 padding */
#define ENCSIZE 2048 			 		 /* largest encrypted data buffer */

#define RSAPUBLIC 1                         /* keytypes used for creating keys */
#define RSAPRIVATE 0

static const uint8_t publicKey[]="-----BEGIN PUBLIC KEY-----\n" \
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZ14qXEkxtTjSztRSkmpW8pVww\n" \
"ntTOzvpfDo8dZsYHSD9NLR79T/UZjsl6Mqh1b1LAKxsROP6BCFwdodGvDsRhvuAS\n" \
"i1++y3iWkMTUExjbcfRse3UOpwlqoUVWjOq4cb0It8WDg/Zq+ZpWam0PLflqliBY\n" \
"bSeonF4vEgrf+lcNtQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

static const uint8_t privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIICXAIBAAKBgQCZ14qXEkxtTjSztRSkmpW8pVwwntTOzvpfDo8dZsYHSD9NLR79\n" \
"T/UZjsl6Mqh1b1LAKxsROP6BCFwdodGvDsRhvuASi1++y3iWkMTUExjbcfRse3UO\n" \
"pwlqoUVWjOq4cb0It8WDg/Zq+ZpWam0PLflqliBYbSeonF4vEgrf+lcNtQIDAQAB\n" \
"AoGAXwtMAyN59jnP04q3My6R/ddHin5GSXKUOi/7eRWqmIspGJwcvjEs4tpVXVp4\n" \
"uvzI6hJ3iX9ltQAeMOxtaDK+XhPW761st6wGbZj1IcBPFUw1DEZ0AiaCeO+MCWKH\n" \
"vpQ2uNJuWYfApPWVRgHFkdWxy8jRw50g46olwgtyy7y/2M0CQQDKDwY0KnPMMfVT\n" \
"mwq4zM5MVIGwzF/mUFO7AFl/6azbNmiSw2Ha8cDR0ANdUIpf3/tjJ26PaAPY0LBO\n" \
"09RqwxGfAkEAwulRW2XLN4jhq9GPtLGfLKDHwrwaJ0EeoC62yhCV9e1hxsRvTWns\n" \
"s1F8yx4gkc7xjOjJtAp2I9hHZk9pZIXoKwJAOiBKU5VmzHYOsednFTRtoE2rJVYV\n" \
"vGadP61hEcgCHumu+ZFVRCvJoVHqtdxmgiAn7CU6y+xLNwMJxRNxBulo1wJAY+JP\n" \
"aAgtcSM7iuKUw2O3D5bBaCEfQfiUKkBmOfzv7Jye2860vzZGL8rVqf2hcTdc//oX\n" \
"y6UEz++4/0w41WPuCwJBAJ5CaTJ2BBmcGyLswdtfnQeUSfHvxk2Yv9SOKZQoIHeG\n" \
"5Uqgvw9wE+p1JxIVrakH+slIg7XrfyHhHNNvqsUg2f8=\n" \
"-----END RSA PRIVATE KEY-----\n"; 

static const char* engine_id = "wsrsaengine";
const char* devstr = "/dev/wsrsachar";

static int padding = RSA_PKCS1_PADDING;

static void rsa256err(char *msg) {
    char *err = malloc(130);
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("[ERROR %s] %s\n",msg, err);
    free(err);
}

#define rsaErr(msg) {   rsa256err(msg); return HWFAIL; }

void showbuff(char *prefix,unsigned char *data,int len) {
    int i;
    printf("%s (%d bytes):\n",prefix,len);
    for(i=0;i<len;i++) {
        printf("%02x",(unsigned int)(*(data+i)));
        if((i+1)%32==0)
            printf("\n");
    }
    if(i%32!=0)
        printf("\n");
}



/*
 * RSA-2048 Public/Private Key Encryption
 */
RSA *createRSA(unsigned char * key,int public, ENGINE* eng) 
{
  RSA *rsa=NULL;
  BIO *keybio;
  if((keybio = BIO_new_mem_buf(key, -1))==NULL) 
    return NULL;
  if(public) 
    rsa = PEM_read_bio_RSA_PUBKEY(keybio,&rsa,NULL,NULL);
  else 
    rsa = PEM_read_bio_RSAPrivateKey(keybio,&rsa,NULL,NULL);
    
    if (eng != NULL)
        RSA_set_method(rsa,ENGINE_get_RSA(eng));

  if (rsa->meth== NULL)
      printf("createRSA NULL method\n");
  return rsa;
}


/* The following assume a key provided in memory */
int32_t wspublic_encrypt(uint8_t *data,int data_len,RSA *key,
												 uint8_t *encrypted,uint32_t *encrypted_lenp) {
	int len;
  if((len = RSA_public_encrypt((int)data_len,(unsigned char*)data,(unsigned char*)encrypted,key,padding))<=0)
		rsaErr("wspublic_encrypt");
	*encrypted_lenp = (uint32_t)len;
	return HWSUCCESS;
}

int32_t wspublic_decrypt(uint8_t *enc_data,int data_len,RSA *key,
												 uint8_t *decrypted,uint32_t *decrypted_lenp)	{
	int len;
  if((len = RSA_public_decrypt((int)data_len,(unsigned char*)enc_data,(unsigned char*)decrypted,key,padding))<=0)
		rsaErr("wspublic_decrypt");
	*decrypted_lenp = (uint32_t)len;
		return HWSUCCESS;
}

int32_t wsprivate_encrypt(uint8_t *data,int data_len,RSA *key,
													uint8_t *encrypted,uint32_t *encrypted_lenp) {
	int len;
  if((len = RSA_private_encrypt((int)data_len,(unsigned char*)data,(unsigned char*)encrypted,key,padding))<=0)
		rsaErr("wsprivate_encrypt");
	*encrypted_lenp = (uint32_t)len;
	return HWSUCCESS;
} 

int32_t wsprivate_decrypt(uint8_t *enc_data,int data_len,RSA *key,
													uint8_t *decrypted,uint32_t *decrypted_lenp) {
	int len;
	if((len = RSA_private_decrypt((int)data_len,(unsigned char*)enc_data,(unsigned char*)decrypted,key,padding))<=0)
		rsaErr("wsprivate_encrypt");
	*decrypted_lenp = (uint32_t)len;
	return HWSUCCESS;
}


int main(int argc, char* argv[])
{
    printf("Entering engine test program...\n");
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    int status = 0;

    // store path to engine shared object
    const char* engine_so_path = argv[1];

    // load dynamic engine support
    ENGINE_load_dynamic(); 

    // (copy of the) instance of a generic "dynamic" engine that will magically morph into an instance of our
    // shared library engine once it is loaded by the LOAD command string 
    ENGINE *eng = ENGINE_by_id("dynamic");
    if (eng == NULL)
    {
        fprintf(stderr,"ERROR: Could not load engine \"dynamic\", ENGINE_by_id(\"dynamic\") == NULL\n");
        exit(1);
    }

    // BRIEF: Specify the path to our shared library engine, set the ID, and load it.
    ENGINE_ctrl_cmd_string(eng, "SO_PATH", engine_so_path, 0);
    ENGINE_ctrl_cmd_string(eng, "ID", engine_id, 0);
    ENGINE_ctrl_cmd_string(eng, "LOAD", NULL, 0);
    if (eng == NULL)
    {
        fprintf(stderr,"*TEST: ERROR, COULD NOT LOAD ENGINE:\n\tSO_PATH = %s\n\tID = %s\n", engine_so_path, engine_id);
        exit(1);
    }
    printf("wsrsa Engine successfully loaded:\n\tSO_PATH = %s\n\tID = %s\n", engine_so_path, engine_id);

    // initialize engine 
    status = ENGINE_init(eng); 
    if (status < 0)
    {
        fprintf(stderr,"*TEST: ERROR, COULD NOT INITIALIZE ENGINE\n\tENGINE_init(eng) == %d\n",status);
        exit(1);
    }
    printf("*TEST: Initialized engine [%s]\n\tinit result = %d\n",ENGINE_get_name(eng), status);

	
	/* default keys */
  uint8_t publicKey[]="-----BEGIN PUBLIC KEY-----\n" \
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZ14qXEkxtTjSztRSkmpW8pVww\n" \
"ntTOzvpfDo8dZsYHSD9NLR79T/UZjsl6Mqh1b1LAKxsROP6BCFwdodGvDsRhvuAS\n" \
"i1++y3iWkMTUExjbcfRse3UOpwlqoUVWjOq4cb0It8WDg/Zq+ZpWam0PLflqliBY\n" \
"bSeonF4vEgrf+lcNtQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

  uint8_t privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIICXAIBAAKBgQCZ14qXEkxtTjSztRSkmpW8pVwwntTOzvpfDo8dZsYHSD9NLR79\n" \
"T/UZjsl6Mqh1b1LAKxsROP6BCFwdodGvDsRhvuASi1++y3iWkMTUExjbcfRse3UO\n" \
"pwlqoUVWjOq4cb0It8WDg/Zq+ZpWam0PLflqliBYbSeonF4vEgrf+lcNtQIDAQAB\n" \
"AoGAXwtMAyN59jnP04q3My6R/ddHin5GSXKUOi/7eRWqmIspGJwcvjEs4tpVXVp4\n" \
"uvzI6hJ3iX9ltQAeMOxtaDK+XhPW761st6wGbZj1IcBPFUw1DEZ0AiaCeO+MCWKH\n" \
"vpQ2uNJuWYfApPWVRgHFkdWxy8jRw50g46olwgtyy7y/2M0CQQDKDwY0KnPMMfVT\n" \
"mwq4zM5MVIGwzF/mUFO7AFl/6azbNmiSw2Ha8cDR0ANdUIpf3/tjJ26PaAPY0LBO\n" \
"09RqwxGfAkEAwulRW2XLN4jhq9GPtLGfLKDHwrwaJ0EeoC62yhCV9e1hxsRvTWns\n" \
"s1F8yx4gkc7xjOjJtAp2I9hHZk9pZIXoKwJAOiBKU5VmzHYOsednFTRtoE2rJVYV\n" \
"vGadP61hEcgCHumu+ZFVRCvJoVHqtdxmgiAn7CU6y+xLNwMJxRNxBulo1wJAY+JP\n" \
"aAgtcSM7iuKUw2O3D5bBaCEfQfiUKkBmOfzv7Jye2860vzZGL8rVqf2hcTdc//oX\n" \
"y6UEz++4/0w41WPuCwJBAJ5CaTJ2BBmcGyLswdtfnQeUSfHvxk2Yv9SOKZQoIHeG\n" \
"5Uqgvw9wE+p1JxIVrakH+slIg7XrfyHhHNNvqsUg2f8=\n" \
"-----END RSA PRIVATE KEY-----\n"; 

	uint8_t val, data[BUFFSIZE], encrypted[ENCSIZE], decrypted[ENCSIZE];
	int i;
	uint32_t datalen,encrypted_length,decrypted_length;

	RSA *pub,*pri;								/* PEM format keys */

	datalen = MAXBYTES;

	// create public key and private key
	pub=createRSA(publicKey,RSAPUBLIC,eng);
	pri=createRSA(privateKey,RSAPRIVATE, eng);
	if(pub==NULL || pri==NULL) {
		printf("Failed to create keys\n");
		exit(EXIT_FAILURE);
	}
	
	/* fill the data buffer with numbers 0,1,2,...datalen-1 */
	for(val=0,i=0; i<datalen; i++,val++)
		data[i] = val;						
	encrypted_length = decrypted_length = -1;

    printf("\nBeginning encryption...\n");

	/* 
	 * encrypting: encrypt with public, decrypt with private
	 */
    printf("wspublic_encrypt()...\n");
	if(wspublic_encrypt(data,datalen,pub,encrypted,&encrypted_length)!=0) {
		printf("\nPublic Encrypt failed ");
		exit(EXIT_FAILURE);
	}
    printf("wsprivate_decrypt()...\n");
	if(wsprivate_decrypt(encrypted,encrypted_length,pri,decrypted,&decrypted_length)!=0) {
		printf("\nPrivate Decrypt failed ");
		exit(EXIT_FAILURE);
	}

	if(datalen!=decrypted_length || memcmp(data,decrypted,datalen)) {
		printf("Public key encryption failed (%d!=%d)\n",datalen,decrypted_length);
		exit(EXIT_FAILURE);
	}
    showbuff("plaintext: ",data,datalen);
    printf("\n");
    showbuff("RSA encrypted with public key: ",encrypted,encrypted_length);
    showbuff("RSA decrypted with private key: ",decrypted,decrypted_length);

	encrypted_length = decrypted_length = -1;
	/* 
	 * signing: encrypt with private, decrypt with public 
	 */

    printf("wsprivate_encrypt()...\n");
	if(wsprivate_encrypt(data,datalen,pri,encrypted,&encrypted_length)!=0) {
		printf("\nPrivate Encrypt failed");
		exit(EXIT_FAILURE);
	}
    printf("wspublic_decrypt()...\n");
	if(wspublic_decrypt(encrypted,encrypted_length,pub,decrypted,&decrypted_length)!=0) {
		printf("\nPublic Decrypt failed");
		exit(EXIT_FAILURE);
	}
	if(datalen!=decrypted_length || memcmp(data,decrypted,datalen) ) {
		printf("\nPrivate key encryption failed (%d!=%d)\n",datalen,decrypted_length);
		exit(EXIT_FAILURE);
	}

	printf("\n");
	showbuff("RSA encrypted with private key: ",encrypted,encrypted_length);
	showbuff("RSA decrypted with public key: ",decrypted,decrypted_length);
    printf("Success!\n'");

	RSA_free(pub);
	RSA_free(pri);
	exit(EXIT_SUCCESS);

   return 0;
}
