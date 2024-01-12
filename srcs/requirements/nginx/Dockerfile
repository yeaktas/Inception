FROM debian:bookworm-slim

RUN apt-get update -y \
    && apt-get upgrade -y \
    && apt-get install -y dumb-init openssl nginx \
    && apt-get clean -y

RUN openssl req -x509 -newkey rsa:4096 -subj "/C=TR/ST=KOCAELI/L=GEBZE/O=42Kocaeli/CN=yaktas.42.fr" -nodes -days 365 -keyout /etc/ssl/yaktas.42.fr.key -out /etc/ssl/yaktas.42.fr.crt

COPY conf/default.conf /etc/nginx/sites-enabled/default

EXPOSE 443

ENTRYPOINT [ "/usr/bin/dumb-init", "--" ] 
CMD ["nginx", "-g", "daemon off;"]