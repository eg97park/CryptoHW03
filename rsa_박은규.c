/**
 * @file rsa_박은규.c
 * @author 박은규 (ekpark97.dev@gmail.com)
 * @brief RSA
 * @version 0.1
 * @date 2022-08-16
 * @build gcc -o rsa "rsa_박은규.c" -L.. -lcrypto -I../include/crypto -g
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
int BOB11_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB11_RSA *b11rsa);
int BOB11_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB11_RSA *b11rsa);
int BOB11_RSA_KeyGen(BOB11_RSA *b11rsa, int nBits);
int MillerRabinPrimalityTest(BIGNUM** in, int nBits);
BIGNUM *GetRandBN(int nBits);
BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b);
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m);
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


/**
 * @brief RSA 구조체를 생성하여 포인터를 리턴하는 함수.
 * 
 * @return BOB11_RSA* 메모리가 할당된 구조체 포인터.
 */
BOB11_RSA *BOB11_RSA_new(){
    BOB11_RSA* b11rsa = (BOB11_RSA*)malloc(sizeof(BOB11_RSA));
    b11rsa->e = BN_new();
    b11rsa->d = BN_new();
    b11rsa->n = BN_new();
    return b11rsa;
}


/**
 * @brief RSA 구조체 포인터를 해제하는 함수.
 * 
 * @param b11rsa[in] 메모리가 할당된 RSA 구조체 포인터.
 * @return int 기본적으로 0을 반환.
 */
int BOB11_RSA_free(BOB11_RSA *b11rsa){
    if(b11rsa->e != NULL) BN_free(b11rsa->e);
    if(b11rsa->d != NULL) BN_free(b11rsa->d);
    if(b11rsa->n != NULL) BN_free(b11rsa->n);
    if(b11rsa != NULL) free(b11rsa);
    return 0;
}


/**
 * @brief RSA 암호화 함수.
 * 
 * @param[out] c 암호화 결과.
 * @param[in] m 입력된 평문.
 * @param[in] b11rsa 입력된 공개키 쌍이 존재하는 RSA 구조체 포인터.
 * @return int 기본적으로 0을 반환, 에러 발생 시 1 반환.
 */
int BOB11_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB11_RSA *b11rsa){
    int ret = ExpMod(c, m, b11rsa->e, b11rsa->n);
    if (ret != 0){
        // Error.
        return 1;
    }
    return 0;
}


/**
 * @brief RSA 복호화 함수.
 * 
 * @param[out] m 복호화 결과.
 * @param[in] c 입력된 암호문.
 * @param[in] b11rsa 입력된 비밀키 쌍이 존재하는 RSA 구조체 포인터.
 * @return int 기본적으로 0을 반환, 에러 발생 시 1 반환.
 */
int BOB11_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB11_RSA *b11rsa){
    int ret = ExpMod(m, c, b11rsa->d, b11rsa->n);
    if (ret != 0){
        // Error.
        return 1;
    }
    return 0;
}


/**
 * @brief 지정된 비트 수의 크기를 가지고, 홀수인 랜덤 BIGNUM 값을 가리키는 포인터를 반환합니다.
 * 
 * @param[in] nBits 생성할 랜덤 BIGNUM의 비트 수.
 * @return BIGNUM* 생성된 랜덤 BIGNUM 값을 가리키는 포인터.
 * @brief 배열을 통해 문자열을 생성 후, BN_hex2bn으로 BIGNUM을 생성합니다.
 */
BIGNUM *GetRandBN(int nBits){
    // "/dev/urandom" 에서 인덱스로 사용할 랜덤 값 읽기.
    uint8_t urand[1] = { '\x00' };
    FILE* fp = fopen("/dev/urandom", "rb");
    if(fp == NULL){
        // Error.
        return NULL;
    }

    int rb = 0;
    int randIndex = 0;
    char* cand = (char*)malloc(sizeof(char) * nBits / 8);
    const char seed[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    for(int i = 0; i < (nBits / 8) - 1; i++){
        rb = fread(urand, sizeof(char), 1, fp);
        if(rb != 1){
            // Error.
            return NULL;
        }

        randIndex = urand[0] % 16;
        cand[i] = seed[randIndex];
    }

    // 홀수 뽑기 위한 마지막 읽기.
    while (1)
    {
        rb = fread(urand, sizeof(char), 1, fp);
        if(rb != 1){
            // Error.
            return NULL;
        }

        // 홀수만 break;
        if ((randIndex = urand[0] % 16) % 2 == 1){
            cand[(nBits / 8) - 1] = seed[randIndex];
            break;
        }
    }
    
    // 반환할 BIGNUM 포인터 생성.
    BIGNUM* rand = BN_new();
    BN_hex2bn(&rand, cand);

    fclose(fp);
    free(cand);
    return rand;
}


/**
 * @brief Miller-Rabin 소수 판정 테스트 함수. (probably prime!)
 *        성공한다면 BIGNUM** in에 큰 소수를 가리키는 BIGNUM* 포인터를 저장합니다.
 * @param[in] in 소수가 생성될 경우 생성된 소수를 가리키는 BIGNUM* 포인터를 저장.
 * @param[in] nBits 생성할 소수의 bits.
 * @return 소수가 생성되었다면 1 반환, 합성수가 생성되었다면 0 반환.
 * @comment https://aquarchitect.github.io/swift-algorithm-club/Miller-Rabin%20Primality%20Test/
 */
int MillerRabinPrimalityTest(BIGNUM** in, int nBits){
    // 테스트 횟수.
    const int k = 10;

    BIGNUM* two = BN_new();
    BN_dec2bn(&two, "2");

    BIGNUM* zero = BN_new();
    BN_dec2bn(&zero, "0");

    BIGNUM* rem = BN_new();
    BN_CTX* ctx = BN_CTX_new();


    // write n - 1 as 2^r * d with d odd by factoring powers of 2 from n - 1.
    int r = 0;
    BIGNUM* n = GetRandBN(nBits);
    BIGNUM* n_1 = BN_new();
    BN_sub(n_1, n, BN_value_one());
    BIGNUM* d = BN_new();
    while (1)
    {
        BN_copy(d, n_1);
        BN_div(n_1, rem, n_1, two, ctx);
        if (BN_cmp(rem, zero) == 1){
            break;
        }
        r++;
    }

    // n - 1 재설정.
    BN_sub(n_1, n, BN_value_one());

    BIGNUM* n_2 = BN_new();
    BN_sub(n_2, n, two);

    // WitnessLoop: repeat k times:
    for(int i = 0; i < k; i++){
        // pick a random integer a in the range [2, n - 2]
        BIGNUM* a = GetRandBN(nBits);
        while (BN_cmp(a, n_2) == 1 || BN_cmp(a, two) == -1)
        {
            BN_free(a);
            a = NULL;
            a = GetRandBN(nBits);
        }

        // x <- a^d mod n
        BIGNUM* x = BN_new();
        ExpMod(x, a, d, n);
        
        // if x = 1 or x = n - 1 then
        if (BN_cmp(x, BN_value_one()) == 0 || BN_cmp(x, n_1) == 0){
            // continue WitnessLoop
            continue;
        }

        // repeat r - 1 times:
        for(int j = 0; j < r - 1; j++){
            // x <- x^2 mod n
            ExpMod(x, x, two, n);

            // if x = 1 then
            if(BN_cmp(x, BN_value_one()) == 0){
                // return composite
                return 0;
            }

            // if x = n - 1 then
            if(BN_cmp(x, n_1) == 0){
                // continue WitnessLoop
                continue; 
            }
        }
        // return composite
        return 0;
    }

    // return probably prime
    *in = BN_dup(n);
    return 1;
}


/**
 * @brief RSA 키 생성 함수.
 * 
 * @param[out] b11rsa n, e, d.
 * @param[in] nBits bits of key.
 * @return int 
 * @comment
 *  Compute d = e−1 (mod φ(n)).
 */
int BOB11_RSA_KeyGen(BOB11_RSA *b11rsa, int nBits){
    BN_CTX* ctx = BN_CTX_new();

    // Choose two primes p and q, and put n := pq.
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();

    // Do Test. First, Get two primes.
    int ret = 0;
    while (ret == 0)
    {
        ret = MillerRabinPrimalityTest(&p, nBits);
    }
    ret = 0;
    while (ret == 0)
    {
        ret = MillerRabinPrimalityTest(&q, nBits);
    }
    
    // Get n = p * q.
    BN_mul(b11rsa->n, p, q, ctx);

    // Get  φ(n) = (p - 1)(q - 1).
    BIGNUM* p_1 = BN_new();
    BIGNUM* q_1 = BN_new();
    BIGNUM* phi = BN_new();
    BN_sub(p_1, p, BN_value_one());
    BN_sub(q_1, q, BN_value_one());
    BN_mul(phi, p_1, q_1, ctx);

    // Choose an integer e such that (e, φ(n)) = 1.
    /**
     * BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b);
     * a*X + b*Y = d
     * e*X + Φ(n)Y = 1
     * e*d + kΦ(n) = 1
     * ed = 1 (mod Φ(n))
     */
    while(1){
        BIGNUM* gcd;
        BIGNUM* dummy = BN_new();

        BIGNUM* tmp = GetRandBN(nBits);
        BIGNUM* phi_1 = BN_new();
        BN_sub(phi_1, phi, BN_value_one());

        // select e in range (1, φ(n) - 1).
        while (BN_cmp(tmp, phi_1) != -1)
        {
            BN_free(tmp);
            tmp = NULL;
            tmp = GetRandBN(nBits);
        }

        // get d using @XEuclid.
        BN_copy(b11rsa->e, tmp);
        gcd = XEuclid(b11rsa->d, dummy, b11rsa->e, phi);
        if (BN_cmp(gcd, BN_value_one()) == 0){
            if (BN_cmp(b11rsa->d, BN_value_one()) == -1){
                BN_add(b11rsa->d, b11rsa->d, phi);
            }
            break;
        }
    }
    return 0;
}


/**
 * @brief CryptoHW01 과제에서 구현한 XEuclid 입니다.
 * 
 * @param[in] x e
 * @param[in] y dummy
 * @param[in] a d
 * @param[in] b Φ(n)
 * @return BIGNUM* gcd
 * @comment https://github.com/Eungyu-dev/CryptoHW01/blob/main/xeuclid.c
 */
BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
        BIGNUM *a_cur = BN_dup(a);
        BIGNUM *b_cur = BN_dup(b);
        BIGNUM *x_0 = BN_new();  BN_dec2bn(&x_0, "1"); 
        BIGNUM *y_0 = BN_new();  BN_dec2bn(&y_0, "0");
        BIGNUM *x_1 = BN_new();  BN_dec2bn(&x_1, "0");
        BIGNUM *y_1 = BN_new();  BN_dec2bn(&y_1, "1");
        BIGNUM *r = BN_new();
        BIGNUM *q = BN_new();
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *tmp = BN_new();

        while (!BN_is_zero(b_cur)){
                BN_div(q, r, a_cur, b_cur, ctx);
                BN_copy(a_cur, b_cur);
                BN_copy(b_cur, r);

                BN_mul(tmp, x_1, q, ctx);
                BN_sub(x, x_0, tmp);

                BN_mul(tmp, y_1, q, ctx);
                BN_sub(y, y_0, tmp);

                BN_copy(x_0, x_1);
                BN_copy(x_1, x);
                BN_copy(y_0, y_1);
                BN_copy(y_1, y);
        }
        BN_copy(x, x_0);
        BN_copy(y, y_0);

        BIGNUM *gcd = BN_dup(a_cur);
        if(a_cur != NULL && b_cur != NULL)      BN_free(a_cur); BN_free(b_cur);
        if(x_0 != NULL && y_0 != NULL)          BN_free(x_0);   BN_free(y_0);
        if(x_1 != NULL && y_1 != NULL)          BN_free(x_1);   BN_free(y_1);
        if(r != NULL && q != NULL)              BN_free(r);     BN_free(q);
        if(tmp != NULL && ctx != NULL)          BN_free(tmp);   BN_CTX_free(ctx);

        return gcd;
}


/**
 * @brief CryptoHW02 과제에서 구현한 ExpMod 입니다.
 * 
 * @param[out] r reuslt.
 * @param[in] a base.
 * @param[in] e exponent value.
 * @param[in] m modular value.
 * @return int 0 if there were no errors.
 * @comment https://github.com/Eungyu-dev/CryptoHW02/blob/main/exp_박은규.c
 */
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m){
        const int k = BN_num_bits(e);
        const int kb = BN_num_bytes(e);
        uint8_t gap = kb * 8 - k;

        unsigned char* eCharArray = (unsigned char*)malloc(sizeof(unsigned char) * kb);
        if (eCharArray == NULL){
                return 1;
        }

        BN_bn2bin(e, eCharArray);
        uint8_t eArray[k];
        for(int i = 0; i < k + gap; i++){
                if (i < gap){
                        continue;
                }
                eArray[i - gap] = (eCharArray[i / 8] >> (7 - (i % 8))) & 0x01;
        }

        BN_CTX* ctx = BN_CTX_new();
        if (ctx == NULL){
                if(eCharArray != NULL) free(eCharArray);
                eCharArray = NULL;
                return 1;
        }

        BIGNUM* _a = BN_dup(a);

        for (int i = k - 2; 0 <= i; i--){
                BN_mod_mul(_a, _a, _a, m, ctx);
                if(eArray[(0 - i) + k - 1] == 1){
                        BN_mod_mul(_a, _a, a, m, ctx);        
                }
        }
        BN_copy(r, _a);

        if(eCharArray != NULL) free(eCharArray);
        if(ctx != NULL) BN_CTX_free(ctx);
        if(_a != NULL) BN_free(_a);
        return 0;
}


/**
 * @brief 사용법을 출력합니다.
 * @comment 기본 제공 함수.
 */
void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}
