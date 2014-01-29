

CC	= gcc
CERR	= -Wall -Wextra -Werror

LIBS	= -lsocket -lnsl -lcrypto


manta_signing_example: manta_signing_example.c ssh_signing.c crypto_utils.c
	$(CC) $(CERR) -o $@ $^ $(LIBS)

