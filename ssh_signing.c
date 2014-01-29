

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <alloca.h>

#include <openssl/bn.h>

#include "crypto_utils.h"


#define	SSH2_AGENTC_REQUEST_IDENTITIES	11
#define	SSH2_AGENT_IDENTITIES_ANSWER	12
#define	SSH2_AGENTC_SIGN_REQUEST	13
#define	SSH2_AGENT_SIGN_RESPONSE	14

typedef struct ssh_key {
	char *sk_type;
	char *sk_fingerprint;
	uint8_t *sk_blob;
	size_t sk_bloblen;
} ssh_key_t;

typedef struct ssh_agent {
	int sa_fd;
	char *sa_key_id;
	ssh_key_t *sa_key;
} ssh_agent_t;

typedef struct signing {
	uint8_t *s_keybuf;
	size_t s_keybuflen;

	uint8_t *s_sigblob;
	size_t s_sigbloblen;
} signing_t;


static int send_req_key_list(ssh_agent_t *sa);
static int opensock(const char *, int *);
static uint8_t *read_msg(ssh_agent_t *sa, char **out);

#define	UNUSED	__attribute__((unused))


/*
 * Utility functions:
 */


static uint32_t
uint_from_buf(uint8_t *buf)
{
	uint32_t val;

	bcopy(buf, &val, sizeof (val));
	val = ntohl(val);

	return (val);
}

static char *
cstring_from_buf(uint8_t *buf, size_t len)
{
	char *val = malloc(len + 1);

	bcopy(buf, val, len);
	val[len] = '\0';

	return (val);
}

/*
 * Format a buffer-with-length and send it to the SSH agent.
 */
static int
write_buf(int fd, uint8_t *buf, size_t buflen)
{
	uint32_t msglen = htonl(buflen);

	write(fd, &msglen, 4);
	write(fd, buf, buflen);

	return (0);
}

/*
 * Read a string from the SSH agent, as part of a message.
 */
static char *
read_string(int fd)
{
	char *buf;
	uint32_t strlen;

	read(fd, &strlen, sizeof (strlen));
	strlen = ntohl(strlen);

	buf = malloc(strlen + 1);
	read(fd, buf, strlen);
	buf[strlen] = '\0';

	return (buf);
}

/*
 * Read a contiguous byte blob from the SSH agent, as part of a message.
 */
static int
read_blob(int fd, uint8_t **buf, size_t *len)
{
	uint32_t bloblen;
	if (read(fd, &bloblen, sizeof (bloblen)) != sizeof (bloblen))
		return (-1);

	*len = ntohl(bloblen);

	if ((*buf = malloc(*len)) == NULL)
		return (-1);
	if (read(fd, *buf, *len) != (ssize_t) *len) {
		free(*buf);
		*buf = NULL;
		*len = 0;
		return (-1);
	}
	return (0);
}

/*
 * Read a key from the SSH agent, as part of a message.
 */
static ssh_key_t *
read_key(ssh_agent_t *sa)
{
	uint8_t *buf;
	size_t buflen;
	char *typestr;
	size_t typelen;
	ssh_key_t *key;

	if (read_blob(sa->sa_fd, &buf, &buflen) == -1)
		return (NULL);

	typelen = uint_from_buf(buf + 0);
	typestr = cstring_from_buf(buf + 4, typelen);

	fprintf(stderr, "type str %s\n", typestr);
	if (strcmp(typestr, "ssh-rsa") == 0) {
		char *sigstr = key_signature(buf, buflen);

		if (strcmp(sigstr, sa->sa_key_id) == 0) {
			fprintf(stderr, "selected key: %s\n", sigstr);

			key = malloc(sizeof (*key));
			if (key == NULL)
				abort();

			key->sk_type = typestr;
			key->sk_fingerprint = sigstr;
			key->sk_blob = buf;
			key->sk_bloblen = buflen;

			sa->sa_key = key;

			return (0);
		} else {
			fprintf(stderr, "ignored key: %s\n", sigstr);

			free(sigstr);
		}
	}

	free(buf);
	free(typestr);

	return (0);
}

/*
 * (Blocking) read of an entire message from the SSH agent.
 */
static uint8_t *
read_msg(ssh_agent_t *sa, char **out)
{
	uint8_t msgtype;
	uint32_t msglen;

	if (read(sa->sa_fd, &msglen, sizeof (msglen)) != sizeof (msglen))
		abort();

	msglen = ntohl(msglen);

	fprintf(stderr, "msg len %d\n", msglen);

	read(sa->sa_fd, &msgtype, sizeof (msgtype));
	fprintf(stderr, "msg type %d\n", msgtype);

	if (msgtype == SSH2_AGENT_IDENTITIES_ANSWER) {
		uint32_t i;
		uint32_t numkeys;

		read(sa->sa_fd, &numkeys, sizeof (numkeys));
		numkeys = ntohl(numkeys);

		fprintf(stderr, "num keys %d\n", numkeys);

		for (i = 0; i < numkeys; i++) {
			char *comment;

			read_key(sa);
			comment = read_string(sa->sa_fd);
			fprintf(stderr, "key comment: %s\n", comment);
		}
	} else if (msgtype == SSH2_AGENT_SIGN_RESPONSE) {
		uint8_t *sigblob = NULL;
		uint32_t sigbloblen = 0;
		uint32_t firstlen;
		char *first;

		fprintf(stderr, "signing response length %d\n", msglen);
		read_blob(sa->sa_fd, &sigblob, &sigbloblen);

		firstlen = uint_from_buf(sigblob);
		fprintf(stderr, "firstlen %u\n", firstlen);

		first = cstring_from_buf(sigblob + 4, firstlen);
		fprintf(stderr, "first %s\n", first);

		if (strcmp(first, "ssh-rsa") != 0) {
			fprintf(stderr, "UNEXPECTED SIG TYPE\n");
		} else {
			uint32_t secondlen = uint_from_buf(sigblob + 4 + firstlen);
			char *sig;

			fprintf(stderr, "secondlen %u\n", secondlen);

			sig = base64encode(sigblob + 4 + firstlen + 4, secondlen);
			fprintf(stderr, "sig: %s\n", sig);

			*out = sig;
		}

		free(first);
	} else {
		fprintf(stderr, "UNKNOWN MESSAGE TYPE %u (LEN %u)\n", msgtype, msglen);
	}

	return (NULL);
}

/*
 * Send a request to the agent for a list of keys.
 */
static int
send_req_key_list(ssh_agent_t *sa)
{
	uint8_t msgtype = SSH2_AGENTC_REQUEST_IDENTITIES;
	uint32_t msglen = htonl(sizeof (msgtype));

	if (write(sa->sa_fd, &msglen, 4) != 4)
		return (errno);
	if (write(sa->sa_fd, &msgtype, sizeof (msgtype)) != sizeof (msgtype))
		return (errno);

	return (0);
}

/*
 * Request that the agent sign data[datalen] with the provided key.
 */
static int
send_req_sign(ssh_agent_t *sa, uint8_t *data, size_t datalen, uint32_t flags)
{
	uint8_t msgtype = SSH2_AGENTC_SIGN_REQUEST;
	uint32_t msglen = htonl(1 + 4 + sa->sa_key->sk_bloblen + 4 + datalen + 4);
	uint32_t rflags = htonl(flags);
	int ret;

	if (write(sa->sa_fd, &msglen, 4) != 4 || write(sa->sa_fd,
	    &msgtype, 1) != 1) {
		return (errno);
	}

	if ((ret = write_buf(sa->sa_fd, sa->sa_key->sk_blob, sa->sa_key->sk_bloblen)) != 0 ||
	    (ret = write_buf(sa->sa_fd, data, datalen)) != 0)
		return (ret);

	if (write(sa->sa_fd, &rflags, 4) != 4)
		return (errno);

	return (0);
}

/*
 * Open a UNIX domain socket connection to *path and put the file
 * descriptor in *fd.
 */
static int
opensock(const char *path, int *fd)
{
	struct sockaddr_un sa;

	bzero(&sa, sizeof (sa));
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, path);
	
	if ((*fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		return (errno);

	if (connect(*fd, (struct sockaddr *)&sa, sizeof (struct sockaddr_un))
	    != 0) {
		(void) close(*fd);
		*fd = -1;
		return (errno);
	}

	return (0);
}

UNUSED
static char *
make_date_header()
{
	time_t now = time(NULL);
	struct tm gmtnow;
	char buf[1000];
	gmtime_r(&now, &gmtnow);
	strftime(buf, 1000, "%a, %d %h %Y %H:%M:%S GMT", &gmtnow);
	return (strdup(buf));
}

static int
get_key(ssh_agent_t *sa)
{
	int erv;

	if ((erv = send_req_key_list(sa)) != 0)
		return (erv);

	fprintf(stderr, "read_msg: go\n");
	read_msg(sa, NULL);
	fprintf(stderr, "read_msg: back\n");

	if (sa->sa_key != NULL) {
		fprintf(stderr, "key found: (%s) %s\n", sa->sa_key->sk_type,
		    sa->sa_key->sk_fingerprint);
		return (0);
	}

	return (-1);
}

static ssh_agent_t *
create_ssh_agent(void)
{
	ssh_agent_t *sa;

	sa = malloc(sizeof (*sa));
	bzero(sa, sizeof (*sa));
	sa->sa_fd = -1;

	return (sa);
}

static void
destroy_ssh_agent(ssh_agent_t *sa)
{
	if (sa->sa_fd != -1)
		(void) close(sa->sa_fd);
	free(sa->sa_key_id);
	free(sa);
}


/*
 * Public API:
 */

int
ssh_agent_init(ssh_agent_t **sa, const char *authsock, const char *keyid)
{
	int erv;
	ssh_agent_t *ret;

	if (authsock == NULL)
		return (EINVAL);

	if ((ret = create_ssh_agent()) == NULL)
		return (errno);
	ret->sa_key_id = strdup(keyid);

	/*
	 * Open connection to SSH Agent:
	 */
	if ((erv = opensock(authsock, &ret->sa_fd)) != 0) {
		free(ret);
		return (erv);
	}

	/*
	 * Attempt to read the key with the provided fingerprint:
	 */
	if ((erv = get_key(ret)) != 0) {
		destroy_ssh_agent(ret);
		return (erv);
	}

	*sa = ret;
	return (0);
}

int
ssh_agent_fini(ssh_agent_t *sa)
{
	destroy_ssh_agent(sa);
	return (0);
}

int
ssh_agent_sign(ssh_agent_t *sa, uint8_t *buf, size_t len, char **sigout)
{
	if (send_req_sign(sa, buf, len, 0) != 0)
		return (-1);
	read_msg(sa, sigout);
	return (0);
}
