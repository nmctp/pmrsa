/* Copyright (c) 2008, Pedro Fortuny Ayuso (info@pfortuny.net) and */
/* Rafael Casado Sánchez (rafacas@gmail.com), */

/* Permission to use, copy, modify, and/or distribute this software for any */
/* purpose with or without fee is hereby granted, provided that the above */
/* copyright notice and this permission notice appear in all copies. */

/* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES */
/* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF */
/* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL ANY OF THE AUTHORS BE LIABLE FOR */
/* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES */
/* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN */
/* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF */
/* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <signal.h>
#include <err.h>

#include "pm_rsa.h"
#include "pm_rsa_server.h"

// This is the server: it is either 
//   * run as a daemon or
//
//   * run once, receiving an **hex string** to be decoded
//
// TODO: * options
//       * Server version
//       * configurable parameters
//       * allow password callback (?)

int main(int argc, char **argv) {

        char *key_filename = PM_RSA_PUBLIC_FILE;

        u_char *encrypted;
        char *challenge    = "challenge!";
        char *tempfile     = "tempfileXX";
        char *whole;

        char opt;

        // Not needed any longer: was used to transform from bin to hex,
        // which is trivial using printf("%02X", char);
        // BIGNUM *msg = BN_new();
        FILE *key_file;
        RSA *rsa = RSA_new();
        int key_length, j;

        while((opt = getopt(argc, argv, PM_RSA_OPTS)) != -1){
                switch(opt) {
                case 'k':
                        ECALLOC(key_filename, char, strlen(optarg));
                        strncpy(key_filename, optarg, strlen(optarg));
                        break;

                case 'c':
                        if(strlen(optarg)!=CHALLENGE_LENGTH){
                                errx(1, "Sorry, the challenge must be 10 chars long");
                        }
                        ECALLOC(challenge, char, strlen(optarg));
                        strncpy(challenge, optarg, strlen(optarg));
                        break;

                case 't':
                        if(strlen(optarg)!=TEMPFILE_LENGTH){
                                errx(1, "Sorry, the temporary filename must be 10 chars long");
                        }
                        ECALLOC(tempfile, char, strlen(optarg));
                        strncpy(tempfile, optarg, strlen(optarg));
                        break;
            
                case 'h':
                default:
                        usage();
                }
        }
        argc -= optind;
        argv += optind;
        // remember: argv[0] is now the first parameter, we have lost the program name

        if(argc < 1){
                usage();
                exit(-1);
        }

        if((key_file = fopen(key_filename, "r")) == NULL){
                errx(1,"Sorry, I could not open the specified private key file %s", key_filename);
        }

  
        PEM_read_RSAPublicKey(key_file, &rsa, NULL, NULL);
        if(rsa->n == NULL) {
                rewind(key_file);
                PEM_read_RSA_PUBKEY(key_file, &rsa, NULL, NULL);
        }

        if(rsa->n == NULL){
                errx(1, "The public key file [%s] seems corrupted", key_filename);
        }

        fclose(key_file);

        key_length = RSA_size(rsa);
        if(key_length*8 < 512){
                printf("Somehow your key is either too small or wrong.\n");
                printf("Its public modulus seems to be: [%s]\n", BN_bn2hex(rsa->n));
                exit(1);
        }

        ECALLOC(whole, char, (strlen(argv[0])+21));
        sprintf(whole, "%s%s%s", argv[0], challenge, tempfile);

        if(strlen(whole)>key_length*2 - 42){
                errx(1, "Sorry, the message you are trying to decode is too long.");
        }

        ECALLOC(encrypted, u_char, key_length+1);
        j = RSA_public_encrypt(key_length - 42, 
                               (u_char *)whole, encrypted, rsa, RSA_PKCS1_PADDING);

        int i;
        for(i=0; i<key_length; i++)
                printf("%02X", encrypted[i]);
        printf("\n");

        return(0);


}

void usage() {
        char * usage = "\n\
\n\
-h:          show this message\n\
-k filename: read the RSA public key from filename, which should be PEM encoded\n\
             (such as generated by ssh-keygen or openssl genrsa).\n\
-c text:     use text as the challenge for the RSA session\n\
-t text:     use text as the name of the temporary file in which the challenge is stored\n\
             on the server";

        printf("(C) 2008-2010 Pedro Fortuny Ayuso & Rafael Casado Sanchez\n");
        printf("pm_rsa_client [options] [string]\n");
        printf("\nOptions:");
        printf("%s\n", usage);

}
