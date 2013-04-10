#define PM_RSA_FILE    "/etc/pm_1024"
#define PM_RSA_PUBLIC_FILE "./pm_1024.pub"
#define PM_RSA_TEMPDIR "/tmp"
#define PM_RSA_PORT    16387
#define PM_RSA_OPTS    "sk:c:dP:ht:"
#define RSA_blinding
#define RSA_BLINDING_ON
#define CHALLENGE_LENGTH 10
#define TEMPFILE_LENGTH 10

// errors
#define NO_REAL_MESSAGE 3
#define NO_TEMPFILE     4
#define NO_CHALLENGE    5


// easy with calloc's...
#define ECALLOC(x,t,s)                                  \
        if( ((x) =                                      \
             ((t *) calloc((s), sizeof(t)))) == NULL)   \
                err(1, "Calloc error.\n");

// send a str + "\n"
#define SENDLN(client, string, length, i)\
        send((client), (string), (length), (i));        \
        send((client), "\n", 1, (i));


int hex2bin(unsigned char *to, char *from, unsigned int length);

int get_challenges(unsigned char *decrypted, 
                   char *tempfile, 
                   char *challenge, 
                   int key_length);
