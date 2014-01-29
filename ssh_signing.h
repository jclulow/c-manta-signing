#ifndef _SSH_SIGNING_H
#define	_SSH_SIGNING_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ssh_agent ssh_agent_t;

int ssh_agent_init(ssh_agent_t **sa, char *authsock, char *keyid);
int ssh_agent_fini(ssh_agent_t *sa);
int ssh_agent_sign(ssh_agent_t *sa, uint8_t *buf, size_t len, char **outsig);

#ifdef __cplusplus
}
#endif

#endif /* _SSH_SIGNING_H */
