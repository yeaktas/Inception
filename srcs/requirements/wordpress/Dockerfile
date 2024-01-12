FROM debian:bookworm-slim

RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y dumb-init curl less php-fpm php-mysql php-mysqli mariadb-client && \
    apt-get clean -y

RUN curl -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && \
    chmod +x /usr/local/bin/wp

RUN mkdir -p /var/www/html/wordpress

COPY ./tools/setup.sh /tmp/
COPY ./conf/www.conf /etc/php/8.2/fpm/pool.d/www.conf

EXPOSE 9000

ENTRYPOINT [ "/usr/bin/dumb-init", "--" ] 
CMD ["/bin/bash", "/tmp/setup.sh"]