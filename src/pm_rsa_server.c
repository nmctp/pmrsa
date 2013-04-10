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

// This is the decryption server. It uses a private rsa key (which
//   defaults to /etc/pm_1024 but can be set with -k). Can be
//
//   * run as a daemon or
//       When run as a daemon, it reads hex messages of the appropriate
//       size (key_size/4) from a socket listening at localhost
//       on the specified port (-P) [default 16387] and returns
//       on the same socket the decrypted message, printing both
//       the received hex message and the decrypted key on stderr.
//
//   * run once, receiving an **hex string** to be decoded, whose decryption
//       is printed on stdout.
//
// TODO: 
//       * seek more configurable parameters, if any
//       * allow password callback (that is, asking for a pwd if the private
//         key is encrypted) (reasonable?)

int main(int argc, char **argv) {

        int demo        = 0;
        int daemon      = 0;
        int port        = PM_RSA_PORT;
        int messg_error = 0;


        char *key_filename = PM_RSA_FILE;
        char *public_filename;
        char *challenge, *tempfile;

        char opt;
        char *config;
        u_char *encrypted, *decrypted;

        // was needed before, to convert from hex to bin, no longer used.
        // BIGNUM *msg = BN_new();
        FILE *key_file;

        RSA *rsa       = RSA_new();
        int key_length, j;

        // these are always needed and have fixed length.
        ECALLOC(challenge, char, CHALLENGE_LENGTH + 1);
        ECALLOC(tempfile, char, TEMPFILE_LENGTH + 1);

        while((opt = getopt(argc, argv, PM_RSA_OPTS)) != -1){
                switch(opt) {
                case 's':
                        daemon  = 1;
                        break;

                case 'k':
                        ECALLOC(key_filename, char, strlen(optarg));
                        strncpy(key_filename, optarg, strlen(optarg));
                        break;

                case 'c':
                        config  = optarg;
                        break;

                case 'P':
                        port    = atoi(optarg);
                        break;

                case 'd':
                        demo    = 1;
                        break;

                case 'h':
                        break;
                default:
                        usage();
                }
        }
        argc -= optind;
        argv += optind;

        if((key_file = fopen(key_filename, "r")) == NULL){
                err(errno,
                    "Could not open the specified private key file %s", 
                    key_filename);
        }
 
        PEM_read_RSAPrivateKey(key_file, &rsa, NULL, NULL);
        fclose(key_file);
 
#ifdef DEBUG
        ECALLOC(public_filename, char, strlen(key_filename) + 4);  // '.pub'
        strncpy(public_filename, key_filename, strlen(key_filename));
        strncat(public_filename, ".pub", 4);

        if((key_file = fopen(public_filename,"w")) != NULL){
                PEM_write_RSAPublicKey(key_file, rsa);
        }
        fclose(key_file);
#endif
        // Minimal correctness check
        if(rsa->n ==NULL || BN_num_bytes(rsa->n) < 512/8 || !RSA_check_key(rsa)){
                errx(1, "Sorry, the key you specified is either wrong or too small.");
        }

        key_length = RSA_size(rsa);

        ECALLOC(encrypted, u_char, key_length+1);
        ECALLOC(decrypted, u_char, key_length+1);

        if(daemon){

                struct sockaddr_in addr, client_addr;
                int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                int client;

                int optval = 1;
                unsigned int optlen = sizeof(optval);

                memset(&addr, 0, sizeof(addr));


                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

                if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, optlen)==-1){
                        perror("Cannot set options on socket");
                }
    
                if(bind(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1){
                        perror("Cannot bind the socket");
                }

                if(listen(sock, 10)==-1){
                        perror("Cannot create the socket");
                }

                //prevent zombies:
                signal(SIGCHLD, SIG_IGN);

                unsigned int client_addr_len = sizeof(client_addr);
                client_addr_len = sizeof(client_addr);
                while((client = accept(sock,
                                       (struct sockaddr *) &client_addr,
                                       &client_addr_len)) != -1){
                        u_int pid;
                        u_int hex_key_length;
                        char *buffer;

                        if((pid = fork())==-1){
                                perror("Unable to fork().\n");
                                exit(errno);
                        }

                        switch (pid){
                        case 0: // child
                                //close parent's server copy
                                close(sock);
                                hex_key_length = 2*key_length; // bytes -> hex
                                ECALLOC(buffer, char, hex_key_length + 1);

                                //the server receives an hex string and returns its decryption
                                recv(client, buffer, hex_key_length, 0);

                                // this was overkill but did the job and is universal.
                                // Should work if hex2bin is platform dependent
                                // BN_hex2bn(&msg, buffer);
                                // BN_bn2bin(msg, (u_char *)encrypted);
                                hex2bin(encrypted, buffer, key_length);
                                

                                // We assume the key has been RSA_PKCS1_PADDED, 
                                // which is what rsa.js does 
                                if((j = RSA_private_decrypt(key_length, 
                                                            encrypted, 
                                                            decrypted, 
                                                            rsa, 
                                                            RSA_PKCS1_PADDING)) != -1){
                                        messg_error = get_challenges(decrypted, challenge, tempfile, key_length);
                                  
				  
                                        SENDLN(client,
                                               tempfile,
                                               TEMPFILE_LENGTH + 1,
                                               0);
                                        SENDLN(client,
                                               challenge,
                                               CHALLENGE_LENGTH + 1,
                                               0);
                                        SENDLN(client,
                                               decrypted,
                                               strlen((char *)decrypted) + 1,
                                               0);

                                        if(demo == 1) {
                                                fprintf(stderr, 
                                                        "received message: %s\n", 
                                                        buffer);
                                                fprintf(stderr, 
                                                        "which translates into: [%s]\n", 
                                                        decrypted);
                                                
                                        }
                                } else {
                                        int ERR = ERR_get_error();
                                        warnx("Error %i, decryption error", ERR);
                                }
	
                                shutdown(client, SHUT_RDWR);
                                exit(j);
	
                        default: // not child -> parent
                                
                                // prevent zombies
                                waitpid(pid, (int *)0, WNOHANG);
                                close(client);
                        }
                } // while(accept...)
                errx(1,"Unable to accept connections.");
        } //daemon till this point



        // no daemon
        if(argc <= 0) {
                usage();
        }

        if(strlen(argv[0])>key_length*2){
                errx(1, "Sorry, the message you are trying to decode is too long.");
        }

        hex2bin(encrypted, argv[0], key_length);

        // We assume the key has been RSA_PKCS1_OAEP_PADDED, which is what
        // rsa.js does
        j = RSA_private_decrypt(key_length, encrypted, 
                                decrypted, rsa, RSA_PKCS1_PADDING);
        
        messg_error = get_challenges(decrypted, challenge, tempfile, key_length);

        printf("%s;", tempfile);
        printf("%s;", challenge);
        printf("%s\n", decrypted);

        return(messg_error);
}



/*
 * Extract (if possible) the challenge and temporary filenames
 * from the decrypted message.
 */
int get_challenges(unsigned char *decrypted, 
                   char *tempfile, 
                   char *challenge, 
                   int key_length){

        int len;        
        for(len=1; len <= key_length && decrypted[len] != 0; len++);
        
        if(len >= key_length){
                warnx("Sorry, the message is not a NULL-terminated string");
                return(NO_REAL_MESSAGE);
        }

        if(len<TEMPFILE_LENGTH){
                warnx("Message: [%s]\n", decrypted);
                warnx("But there should be a tempfile and a challenge");
                return(NO_TEMPFILE);
        }

        memcpy(tempfile, decrypted+len-TEMPFILE_LENGTH, TEMPFILE_LENGTH);
        decrypted[len-TEMPFILE_LENGTH]=0;
        
        len -= TEMPFILE_LENGTH;

        if(len<CHALLENGE_LENGTH){
                warnx("Message: [%s]\n", decrypted);
                warnx("But there should be a challenge");
                return(NO_CHALLENGE);                
        }
        
        memcpy(challenge, decrypted+len-CHALLENGE_LENGTH, CHALLENGE_LENGTH);
        decrypted[len-CHALLENGE_LENGTH]=0;
        return(0);

}

void usage(){
        char * usage = "\n\
\n\
-h:          show this message\n\
-k filename: read the RSA private key from filename, which should be PEM encoded\n\
             (such as generated by ssh-keygen or openssl genrsa).\n\
-s:          run as a server listening *on localhot*.\n\
\n\
-P port:     port to listen on (16387). Only useful with -s\n\
-d           run in demo mode (use only for testing purposes), will output to \n\
             stderr the received hexdump and its decryption. Only useful with -s \
\n\
If -s is specified, no hex message is needed.";

        printf("(C) 2008-2010 Pedro Fortuny Ayuso & Rafael Casado Sanchez\n");
        printf("pm_rsa_server [options] [hex message]\n");
        printf("\nOptions:");
        printf("%s\n", usage);
  
        exit(0);
}
