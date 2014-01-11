#include <stdio.h>

#ifndef pcy_crypt_h
#define pcy_crypt_h

typedef struct __pcy_cryptokey__ { char c1,c2,c3,c4,c5; } pcy_cryptokey;
pcy_cryptokey genkey();
void printkey(pcy_cryptokey *, FILE *);
void printkeydata(pcy_cryptokey);

void do_crypt(pcy_cryptokey, unsigned char *, unsigned int *, char);
/*mode = 0 for encrypt, anything else for decrypt*/

#define PCY_STUB_ON 0

#endif
