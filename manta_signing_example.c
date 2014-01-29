

#include <string.h>
#include <errno.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "ssh_signing.h"

#define	UNUSED	__attribute__((unused))

#define	DEFAULT_ALGORITHM	"rsa-sha1"

typedef struct manta_config {
	char *mc_manta_url;
	char *mc_manta_user;
	char *mc_manta_key_id;
} manta_config_t;


static char *
make_date_header()
{
        time_t now = time(NULL);
        struct tm gmtnow;
        char buf[1000];
	char *out;
        gmtime_r(&now, &gmtnow);
        strftime(buf, 1000, "%a, %d %h %Y %H:%M:%S GMT", &gmtnow);
	asprintf(&out, "date: %s", buf);
        return (out);
}

/*
 * Generate a curl command line including a Date header and an appropriate
 * HTTP Signature for use against the provided Manta Path.
 *
 * If you use libcurl directly, it is trivial to add both of these header
 * values to the request.
 */
static void
do_sig_thing(manta_config_t *mc, ssh_agent_t *sa, char *manta_path)
{
	char *date = make_date_header();
	char *authnz_header = NULL;
	char *sign = NULL;

	ssh_agent_sign(sa, (uint8_t*)date, strlen(date), &sign);

	asprintf(&authnz_header, "keyId=\"/%s/keys/%s\",algorithm=\"%s\","
	    "signature=\"%s\"", mc->mc_manta_user, mc->mc_manta_key_id,
	    DEFAULT_ALGORITHM, sign != NULL ? sign : "<null>");

	fprintf(stdout, "curl -ki \\\n");
	fprintf(stdout, "  -H '%s' \\\n", date);
	fprintf(stdout, "  -H 'Authorization: Signature %s' \\\n", authnz_header);
	fprintf(stdout, "  %s%s\n", mc->mc_manta_url, manta_path);

	free(date);
	free(authnz_header);
	free(sign);
}

static int
manta_config_from_env(manta_config_t *mc)
{
	mc->mc_manta_user = getenv("MANTA_USER");
	if (mc->mc_manta_user == NULL || mc->mc_manta_user[0] == '\0') {
		errx(2, "MANTA_USER was not set\n");
	}

	mc->mc_manta_url = getenv("MANTA_URL");
	if (mc->mc_manta_url == NULL || mc->mc_manta_url[0] == '\0') {
		errx(2, "MANTA_URL was not set\n");
	}

	mc->mc_manta_key_id = getenv("MANTA_KEY_ID");
	if (mc->mc_manta_key_id == NULL || mc->mc_manta_key_id[0] == '\0') {
		errx(2, "MANTA_KEY_ID was not set\n");
	}

	return (0);
}

int
main(int argc, char **argv)
{
	ssh_agent_t *sap;
	char *auth_sock;
	int erv;
	manta_config_t mc;

	if (argc < 2 || argv[1][0] == '\0')
		errx(1, "usage: %s <manta_path>\n", argv[0]);

	if (manta_config_from_env(&mc) != 0) {
		errx(1, "could not configure manta from environment\n");
	}

	/*
	 * Initialise the SSH agent connection:
	 */
	auth_sock = getenv("SSH_AUTH_SOCK");
	if (auth_sock == NULL || auth_sock[0] == '\0') {
		errx(2, "SSH_AUTH_SOCK was not set\n");
	}
	if ((erv = ssh_agent_init(&sap, auth_sock, mc.mc_manta_key_id)) != 0) {
		errno = erv;
		err(3, "SSH agent could not be initialised");
	}
	fprintf(stderr, "agent initialised\n");

	do_sig_thing(&mc, sap, argv[1]);

	(void) ssh_agent_fini(sap);

	return (0);
}
