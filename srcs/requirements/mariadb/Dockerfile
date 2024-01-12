FROM debian:bookworm-slim

RUN apt-get update -y \
    && apt-get upgrade -y \
    && apt-get install -y dumb-init mariadb-server expect \
    && apt-get clean -y

RUN mkdir -p /var/log/mysql \
    && chown -R mysql:mysql /var/log/mysql \
    && touch /var/log/mysql/error.log \
    && chown -R mysql:mysql /var/log/mysql/error.log

COPY ./conf/mariadb.cnf /etc/mysql/mariadb.conf.d/50-server.cnf

COPY ./tools/mysql_safe_install.sh /tmp/

ENTRYPOINT ["/usr/bin/dumb-init", "--"]

CMD ["/bin/bash", "/tmp/mysql_safe_install.sh"]

EXPOSE 3306