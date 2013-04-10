#include <stdio.h>
#include <string.h>

int hex2bin(unsigned char *to, char *from, unsigned int length){
        // this function is utterly unsafe, use at your
        // own risk. If there is not enough space on *to
        // then a segfault will happen.
        //
        // It will probably be safer to use BN's functions
        // to accomplish this.
        int i, len;
        unsigned char Mt, M, mt, m;
        len = strlen(from); 
        if(len != length * 2) { /* bytes to hexadecimal */
                return(0);
        }
        for(i = len-1; i>=0; i--){
                Mt = from[2*i];
                mt = from[2*i+1];
                M = (Mt>='A' && Mt <='F') ? (Mt - '7') : (Mt - '0');
                M = (Mt>='a' && Mt <='f') ? (Mt - 'W') : M;
                m = (mt>='A' && mt <='F') ? (mt - '7') : (mt - '0');
                m = (mt>='a' && mt <='f') ? (mt - 'W') : m;
                to[i] = M * 16 + m;
        }
        return(len);
}
