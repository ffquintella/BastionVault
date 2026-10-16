# OpenSSH target for the brokered ssh-cert phase of run.sh (Rustion T444,
# BastionVault T105). It trusts exactly one user CA, BastionVault's `ssh/`
# engine CA, and offers no password login, so the only way in is a
# certificate BastionVault minted and Rustion presented.
#
# The CA public key and the host key are not baked in: run.sh writes them
# into ./var/brokered-target/ (mounted read-only at /bv) once BastionVault
# has generated its CA, and the entrypoint copies them into place.
FROM alpine:3.20
RUN apk add --no-cache openssh-server \
    && adduser -D -s /bin/ash tester \
    # adduser -D locks the account ("!"), and sshd refuses a locked account
    # even for a certificate login. Give it a random password nobody knows;
    # PasswordAuthentication is off anyway.
    && echo "tester:$(head -c 24 /dev/urandom | base64)" | chpasswd
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
