# Infrastructure Rules

## INFRA_DOCKER_ROOT_USER
**Title:** Docker image may run as root
**Category:** infra
**Severity:** medium
**Risk:** Containers running as root increase the blast radius of a container escape or dependency compromise.
**Recommendation:** Add a non-root `USER` directive to the Dockerfile and drop unnecessary capabilities.
**Standards:** OWASP Top 10: A05 Security Misconfiguration

## INFRA_DB_PORT_EXPOSED
**Title:** Database or cache port may be exposed to the host network
**Category:** infra
**Severity:** high
**Risk:** Publishing database/cache ports (Postgres 5432, MySQL 3306, MongoDB 27017, Redis 6379) beyond the internal Docker network can expose data stores directly to the internet on misconfigured hosts.
**Recommendation:** Remove public port mappings for data stores in production compose files and restrict access to the internal network or a VPN/bastion.
**Standards:** OWASP Top 10: A05 Security Misconfiguration
