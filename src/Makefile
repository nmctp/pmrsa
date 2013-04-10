CC=gcc
CC_OPTS=-DDEBUG -g  -Wall -Wno-sign-compare -fsigned-char
LIBS=-lcrypto -lssl
LIBLIBS=
NUM_BITS = 1024
KEY_NAME = pmrsa_key

KEY_ENCRYPTED=key_encrypted.txt

default: lib rsa2hex pm_rsa key
	@echo
	@echo Successful build.
	@echo

clean:
	rm -f pm_rsa_server pm_rsa_client rsa2hex
	rm -rf *.dSYM
	rm -f *.mod *.exp *.pem *.pub pmrsa_key
	find . \( -name "*~" -or -name "*.o" \) -exec rm -f '{}' \;

lib:
	@$(CC) $(CC_OPTS) $(LIBLIBS) -c pm_rsa_lib.c -o pm_rsa_lib.o

key:
	@echo generating key files: pmrsa_key, pmrsa_key.pub, pmrsa_key.exp, pmrsa_key.mod
	@openssl genrsa -out $(KEY_NAME) $(NUM_BITS) 2>/dev/null > /dev/null
	@openssl rsa -text -inform pem -in $(KEY_NAME) 2>&1|grep '^publicExponent'|sed -e 's/.*0x\(.*\))/\1/' > $(KEY_NAME).exp
	@openssl rsa -modulus -inform pem -in $(KEY_NAME) 2>/dev/null|grep 'Modulus'|sed -e 's/Modulus=//g' > $(KEY_NAME).mod

pm_rsa: pm_rsa_server pm_rsa_client

pm_rsa_server: lib pm_rsa_server.* pm_rsa.h
	@$(CC) $(CC_OPTS) $(LIBS) pm_rsa_server.c pm_rsa_lib.o -o pm_rsa_server

pm_rsa_client: lib pm_rsa_client.* pm_rsa.h
	@$(CC) $(CC_OPTS) $(LIBS) -o pm_rsa_client pm_rsa_client.c pm_rsa_lib.o

rsa2hex: rsa2hex.c
	@$(CC) $(CC_OPTS) $(LIBS) -o rsa2hex rsa2hex.c

test: pm_rsa
	./pm_rsa_client -c 'Chal_lenge' -t 'TEMP.FILE_' -k rsa1.2048.pub 'Teh password' > $(KEY_ENCRYPTED)
	@echo "key encrypted: "
	@cat $(KEY_ENCRYPTED)
	./pm_rsa_server -k rsa1.2048 `cat $(KEY_ENCRYPTED)`
	@rm -f $(KEY_ENCRYPTED)

