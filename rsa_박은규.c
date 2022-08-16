/**
 * @file rsa_박은규.c
 * @author 박은규 (ekpark97.dev@gmail.com)
 * @brief RSA
 * @version 0.1
 * @date 2022-08-16
 * @build gcc -o rsa "rsa_박은규.c" -L.. -lcrypto -I../include/crypto
 * @usage ./rsa [-k|-e e n plaintext|-d d n ciphertext]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

typedef struct _b11rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB11_RSA;

BOB11_RSA *BOB11_RSA_new();
int BOB11_RSA_free(BOB11_RSA *b11rsa);
int BOB11_RSA_KeyGen(BOB11_RSA *b11rsa, int nBits);
int BOB11_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB11_RSA *b11rsa);
int BOB11_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB11_RSA *b11rsa);
void PrintUsage();

int main (int argc, char *argv[])
{
    BOB11_RSA *b11rsa = BOB11_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        BOB11_RSA_KeyGen(b11rsa,1024);
        BN_print_fp(stdout,b11rsa->n);
        printf(" ");
        BN_print_fp(stdout,b11rsa->e);
        printf(" ");
        BN_print_fp(stdout,b11rsa->d);
    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b11rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b11rsa->e, argv[2]);
            BOB11_RSA_Enc(out,in, b11rsa);
        }else if(!strncmp(argv[1],"-d",2)){
            BN_hex2bn(&b11rsa->d, argv[2]);
            BOB11_RSA_Dec(out,in, b11rsa);
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
    }else{
        PrintUsage();
        return -1;
    }

    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b11rsa!= NULL) BOB11_RSA_free(b11rsa);

    return 0;
}

void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}
