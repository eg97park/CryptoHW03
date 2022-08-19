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
int BOB11_RSA_KeyGen(BOB11_RSA *b11rsa, int nBits);
int BOB11_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB11_RSA *b11rsa);
int BOB11_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB11_RSA *b11rsa);
int MillerRabinPrimalityTest(BIGNUM** in, int nBits);
BIGNUM *GetRandBN(int nBits);
void PrintUsage();
void printBN(char *msg, BIGNUM * a);
BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b);
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m);

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
 * @brief RSA 암호화 함수.
 * 
 * @param[out] c 
 * @param[in] m 
 * @param[in] b11rsa 
 * @return int 
 */
int BOB11_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB11_RSA *b11rsa){
    int ret = ExpMod(c, m, b11rsa->e, b11rsa->n);
    if (ret != 0){
        // @ExpMod Error.
        return 1;
    }
    printBN("m=%s", m);
    printBN("c=%s", c);
    return 0;
}


/**
 * @brief RSA 복호화 함수.
 * 
 * @param[out] m 
 * @param[in] c 
 * @param[in] b11rsa 
 * @return int 
 */
int BOB11_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB11_RSA *b11rsa){
    int ret = ExpMod(m, c, b11rsa->d, b11rsa->n);
    if (ret != 0){
        // @ExpMod Error.
        return 1;
    }
    printBN("c=%s", c);
    printBN("m=%s", m);
    return 0;
}


/**
 * @brief 
 * 
 * @param[in] msg 
 * @param[in] a 
 */
void printBN(char *msg, BIGNUM * a)
{
        char * number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
}


/**
 * @brief Get odd random BIGNUM of nBits.
 * 
 * @param nBits bits of BIGNUM.
 * @return BIGNUM* odd random BIGNUM.
 */
BIGNUM *GetRandBN(int nBits){
    BIGNUM* rand = BN_new();
    char* cand = (char*)malloc(sizeof(char) * nBits / 8);

    int randIndex = 0;

    // read random value from /dev/urandom.
    uint8_t urand[1] = { '\x00' };
    FILE* fp = fopen("/dev/urandom", "rb");
    int rb = fread(urand, sizeof(char), 1, fp);

    const char seed[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    for(int i = 0; i < (nBits / 8) - 1; i++){
        rb = fread(urand, sizeof(char), 1, fp);
        randIndex = urand[0] % 16;
        cand[i] = seed[randIndex];
    }

    // last round. pick only odd.
    while (1)
    {
        rb = fread(urand, sizeof(char), 1, fp);
        if ((randIndex = urand[0] % 16) % 2 == 1){
            cand[(nBits / 8) - 1] = seed[randIndex];
            break;
        }
    }
    
    BN_hex2bn(&rand, cand);
    fclose(fp);
    return rand;
}


/**
 * @brief Miller-Rabin Primality Test.
 * 
 * @param nBits bits of prime.
 * @return ?
 * @comment https://aquarchitect.github.io/swift-algorithm-club/Miller-Rabin%20Primality%20Test/
 *          https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
 *          test: 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41.
 */
int MillerRabinPrimalityTest(BIGNUM** in, int nBits){
    const int k = 10;

    BIGNUM* two = BN_new();
    BN_dec2bn(&two, "2");

    BIGNUM* zero = BN_new();
    BN_dec2bn(&zero, "0");

    BIGNUM* n = GetRandBN(nBits);
    BIGNUM* n_1_cur = BN_new();
    BIGNUM* d = BN_new();
    BN_sub(n_1_cur, n, BN_value_one());

    BIGNUM* rem = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    int r = 0;
    while (1)
    {
        // int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d, BN_CTX *ctx);
        // (dv=a/d, rem=a%d)
        // m_cand_1 = m_cand_1 / two
        BN_copy(d, n_1_cur);
        BN_div(n_1_cur, rem, n_1_cur, two, ctx);
        if (BN_cmp(rem, zero) == 1){
            break;
        }
        r++;
    }

    BN_sub(n_1_cur, n, BN_value_one());
    BIGNUM* n_2 = BN_new();
    BN_sub(n_2, n, two);

    // repeat k times:
    for(int i = 0; i < k; i++){
        // pick a random integer a in the range [2, n - 2]
        BIGNUM* a = GetRandBN(nBits);
        while (BN_cmp(a, n_2) == 1 || BN_cmp(a, two) == -1)
        {
            BN_free(a);
            a = NULL;
            a = GetRandBN(nBits);
        }
        BIGNUM* x = BN_new();
        
        ExpMod(x, a, d, n);
        
        if (BN_cmp(x, BN_value_one()) == 0 || BN_cmp(x, n_1_cur) == 0){
            continue;
        }

        for(int j = 0; j < r - 1; j++){
            ExpMod(x, x, two, n);
            if(BN_cmp(x, BN_value_one()) == 0){
                // 합성수
                return 0;
            }
            if(BN_cmp(x, n_1_cur) == 0){
                continue; 
            }
        }
        // 합성수
        return 0;
    }

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
 *  p=C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7
 *  q=F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F
 *  Compute d = e−1 (mod φ(n)).
 */
int BOB11_RSA_KeyGen(BOB11_RSA *b11rsa, int nBits){
    BN_CTX* ctx = BN_CTX_new();

    // Choose two primes p and q, and put n := pq.
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();

    // p, q 랜덤으로 선택되어야 함. 여기 scope에서 생성되고, 검증되고, 없어져야만 함.
    // BN_hex2bn(&p, "C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7");
    // BN_hex2bn(&q, "F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F");

    // Do Test
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
    
    
    //BN_hex2bn(&p, "11");
    //BN_hex2bn(&q, "13");
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
        if (BN_cmp(b11rsa->e, phi)){
            b11rsa->e = GetRandBN(nBits);

        }
        BN_rand_range(b11rsa->e, phi); // !TODO: 랜덤 쓰면 안됨.
        gcd = XEuclid(b11rsa->d, dummy, b11rsa->e, phi);
        if (BN_cmp(gcd, BN_value_one()) == 0){
            if (BN_cmp(b11rsa->d, BN_value_one()) == -1){
                BN_add(b11rsa->d, b11rsa->d, phi);
            }
            break;
        }
    }

    printBN("cand p: ", p);
    printBN("cand q: ", q);
    printBN("cand n: ", b11rsa->n);
    printBN("cand phi: ", phi);
    printBN("cand e: ", b11rsa->e);
    printBN("cand d: ", b11rsa->d);

    return 0;
}


/**
 * @brief RSA 구조체를 생성하여 포인터를 리턴하는 함수.
 * 
 * @return BOB11_RSA* 
 */
BOB11_RSA *BOB11_RSA_new(){
    BOB11_RSA* _ = (BOB11_RSA*)malloc(sizeof(BOB11_RSA));
    _->e = BN_new();
    _->d = BN_new();
    _->n = BN_new();
    return _;
}


/**
 * @brief RSA 구조체 포인터를 해제하는 함수.
 * 
 * @param b11rsa allocated BOB_RSA*.
 * @return int 0.
 */
int BOB11_RSA_free(BOB11_RSA *b11rsa){
    if(b11rsa->e != NULL) BN_free(b11rsa->e);
    if(b11rsa->d != NULL) BN_free(b11rsa->d);
    if(b11rsa->n != NULL) BN_free(b11rsa->n);
    if(b11rsa != NULL) free(b11rsa);
    return 0;
}


void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}



/**
 * @brief CryptoHW01 과제에서 구현한 XEuclid 입니다.
 * 
 * @param[in] x e
 * @param[in] y dummy
 * @param[in] a d
 * @param[in] b Φ(n)
 * @return BIGNUM* gcd(x, y)?
 * 
 * @comment https://github.com/Eungyu-dev/CryptoHW01/blob/main/xeuclid.c
 */
BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
        // ax + by = gcd
        BIGNUM *a_cur = BN_dup(a);
        BIGNUM *b_cur = BN_dup(b);

        // a * (1) + b * (0) = a -> a * (x_0) + b * (y_0) = a
        BIGNUM *x_0 = BN_new();  BN_dec2bn(&x_0, "1"); 
        BIGNUM *y_0 = BN_new();  BN_dec2bn(&y_0, "0");

        // a * (0) + b * (1) = b -> a * (x_1) + b * (y_1) = b
        BIGNUM *x_1 = BN_new();  BN_dec2bn(&x_1, "0");
        BIGNUM *y_1 = BN_new();  BN_dec2bn(&y_1, "1");

        BIGNUM *r = BN_new();
        BIGNUM *q = BN_new();

        // buf for mul, div operation.
        BN_CTX *ctx = BN_CTX_new();

        // tmp for mul.
        BIGNUM *tmp = BN_new();

        // x -> x_2, y -> y_2, k = 1
        while (!BN_is_zero(b_cur)){
                //      a_0 = b_0 * q_0 + r_0
                //   ┌  a_1(=b_0) = b_1(=r_0) * q_1 + r_1
                //   └> a_2(=b_1=r_0) = b_2(=r_1) * q_2 + r_2
                BN_div(q, r, a_cur, b_cur, ctx);
                BN_copy(a_cur, b_cur);
                BN_copy(b_cur, r);

                // x_0 - x_1 * q_2 = x_2
                BN_mul(tmp, x_1, q, ctx);
                BN_sub(x, x_0, tmp);

                // y_0 - y_1 * q_2 = y_2
                BN_mul(tmp, y_1, q, ctx);
                BN_sub(y, y_0, tmp);

                // k += 1
                BN_copy(x_0, x_1);
                BN_copy(x_1, x);
                BN_copy(y_0, y_1);
                BN_copy(y_1, y);
        }
        BN_copy(x, x_0);
        BN_copy(y, y_0);

        // make new object to return.
        BIGNUM *gcd = BN_dup(a_cur);

        // free everything!
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

        // Write n = (bk−1 bk−2 ··· b0)
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

        // A <- a
        BIGNUM* _a = BN_dup(a);

        // For i = k - 2 to 0 do:
        for (int i = k - 2; 0 <= i; i--){
                // A <- A**2 mod m
                BN_mod_mul(_a, _a, _a, m, ctx);

                // if bi = 1 then A <- A * a mod m
                if(eArray[(0 - i) + k - 1] == 1){
                        BN_mod_mul(_a, _a, a, m, ctx);        
                }
        }

        /** mapping my array index to lecture note 26p.
         * lecture note         my array
         * i = k - 2            i = 1
         * i = k - 3            i = 2
         * ...                  ...
         * i = k - n            i = n - 1
         * ...                  ...
         * i = k - (k - 1)      i = k - 2
         * i = k - (k - 0)      i = k - 1
         */

        BN_copy(r, _a);

        if(eCharArray != NULL) free(eCharArray);
        if(ctx != NULL) BN_CTX_free(ctx);
        if(_a != NULL) BN_free(_a);
        return 0;
}