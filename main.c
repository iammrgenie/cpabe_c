#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <pbc/pbc.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>


//Representation of a Public Key
typedef struct {
    element_t pk;   
    element_t h1;
    element_t g1;
} public_key;

typedef struct {
    element_t attr;
    element_t sk1;   
} attHash;

// Hash function for calculating SHA-256 hash
void sha256(const unsigned char* input, size_t length, element_t attrhash, pairing_t pairing) {
    // SHA256_CTX ctx;
    // SHA256_Init(&ctx);
    // SHA256_Update(&ctx, input, length);
    // SHA256_Final(output, &ctx);
    EVP_MD_CTX * ctx = NULL;
    EVP_MD * sha256 = NULL;

    unsigned int len = 0;
    unsigned char* output = NULL;
    
    int ret = 1;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto err;

    sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (sha256 == NULL)
        goto err;
    
    /* Initialise the digest operation */
    if (!EVP_DigestInit_ex(ctx, sha256, NULL))
       goto err;

    /*
     * Pass the message to be digested. This can be passed in over multiple
     * EVP_DigestUpdate calls if necessary
     */
    if (!EVP_DigestUpdate(ctx, input, length))
        goto err;

    /* Allocate the output buffer */
    output = OPENSSL_malloc(EVP_MD_get_size(sha256));
    if (output == NULL)
        goto err;

    /* Now calculate the digest itself */
    if (!EVP_DigestFinal_ex(ctx, output, &len))
        goto err;

    /* Print out the digest result */
    printf("Hashed Attribute: \n");
    BIO_dump_fp(stdout, output, len);
    printf("\n");

    element_t hash;
    element_init_G1(hash, pairing);
    element_from_hash(hash, (void*)output, len);
    
    element_set(attrhash, hash);

    ret = 0;

    err:
        /* Clean up all the resources we allocated */
        OPENSSL_free(output);
        EVP_MD_free(sha256);
        EVP_MD_CTX_free(ctx);
        if (ret != 0)
            ERR_print_errors_fp(stderr);
        //return ret;
}

int main() {
    printf("An attempt to write CPABE in C\n");

    FILE *file = fopen("param/a.param", "rb");  // Open file in binary mode for reading
    if (file == NULL) {
        printf("Failed to open the file.\n");
        return 1;
    }

    //***************************************** SETUP FUNCTION *************************************************
    pairing_t pairing;

    char param[1024];     // Buffer to store the read data
        
    size_t count = fread(param, 1, 1024, file);
    if (!count) {pbc_die("Input Error");}

    pairing_init_set_buf(pairing, param, count);

    element_t g, h;
    element_t e_gh;
    element_t msk, mpk;

    element_init_G1(g, pairing);
    element_init_G2(h, pairing);
    element_init_GT(e_gh, pairing);
    element_init_Zr(msk, pairing);
    element_init_GT(mpk, pairing);

    element_random(g);
    element_random(h);
    element_random(msk);                    // Generate a ransom msk

    pairing_apply(e_gh, g, h, pairing);     // Compute a bilinear pairing of g and h

    element_pow_zn(mpk, e_gh, msk);         // Compute the public key from msk and e_gh

    element_printf("\nMSK: %B\n", msk);
    element_printf("\nMPK: %B\n", mpk);

    //***************************************** KEYGEN FUNCTION *************************************************
    const char * attr_list[] = {"10", "20", "30", "40"};
    int length = sizeof(attr_list) / sizeof(attr_list[0]);
    printf("\nThe attribute list has: %d elements\n", length);

    element_t r, h_r;
    attHash SK[length];

    element_init_Zr(r, pairing);
    element_init_G1(h_r, pairing);

    element_random(r);                    // Generate a ransom r
    element_pow_zn(h_r, h, r);            // Compute h_r from h and r

    // Hashing the elements of attr_list in the G1 group
    for (int i = 0; i < length; i++) {
        element_init_G1(SK[i].attr, pairing);

        sha256((const unsigned char*)attr_list[i], sizeof(attr_list[i]), SK[i].attr, pairing);

        //element_printf("\nHATTR: %B\n", SK[i].attr);
    }
    printf("\n");

    return 0;
}