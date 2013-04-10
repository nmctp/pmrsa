// Obvious utility to prevent bootstrapping Openssl
// read a pem public key and output it in hexadecimal.

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <err.h>
#include <stdio.h>

int main(int argc, char* argv[]){
        FILE *key_file;
        RSA  *rsa = RSA_new();
        char *hexdump;

        if(argc<=1){
                errx(1, "Sorry, need an argument");
        }

        key_file=fopen(argv[1], "r");
        if(key_file == NULL){
                errx(1, "Inexisten file");
        }
        PEM_read_RSAPublicKey(key_file, &rsa, NULL, NULL);
        
        if(rsa == NULL || rsa->n == NULL) {
                rewind(key_file);
                PEM_read_RSA_PUBKEY(key_file, &rsa, NULL, NULL);
        }

        if(rsa == NULL || rsa->n == NULL){
                errx(1, "The public key file [%s] seems corrupted", argv[1]);
        }

        fclose(key_file);

        hexdump = BN_bn2hex(rsa->n);
        printf("modulus: [%s]\n", hexdump);
        hexdump = BN_bn2hex(rsa->e);
        printf("exponent: [%s]\n", hexdump);
        return(0);
}
