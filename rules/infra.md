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

## TERRAFORM_PUBLIC_S3_BUCKET
**Title:** Terraform config may create a publicly readable storage bucket
**Category:** infra
**Severity:** critical
**Risk:** An S3 bucket with a public-read ACL or disabled public-access-block settings can expose every object in it to the internet, including user uploads or backups.
**Recommendation:** Keep buckets private by default and use signed URLs or a CDN with access controls for anything that needs to be public.
**Standards:** OWASP Top 10: A05 Security Misconfiguration

## TERRAFORM_OPEN_SECURITY_GROUP
**Title:** Terraform config may open a sensitive port to the entire internet
**Category:** infra
**Severity:** high
**Risk:** A security group ingress rule with `0.0.0.0/0` on an administrative port (SSH 22, RDP 3389) or a database port exposes that service to internet-wide scanning and brute force.
**Recommendation:** Restrict ingress CIDR blocks to known IP ranges or a VPN/bastion, never `0.0.0.0/0` for administrative or database ports.
**Standards:** OWASP Top 10: A05 Security Misconfiguration
