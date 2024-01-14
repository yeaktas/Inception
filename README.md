# Inception
This project aims to broaden your knowledge of system administration by using Docker.


## Docker

Docker, yazılım uygulamalarını konteyner adı verilen hafif, taşınabilir ve ölçeklenebilir bir birim içinde paketlemeye, dağıtmaya ve çalıştırmaya yönelik bir platformdur. Docker, uygulamaların bağımlılıklarını ve çevrelerini bir konteyner içinde izole etmeyi sağlar. Bu, uygulamaların farklı ortamlarda sorunsuz bir şekilde çalışmasını ve taşınmasını kolaylaştırır.

## Docker Compose

Docker Compose, Docker konteyner uygulamalarını yönetmek ve çoklu konteyner yapılarını tanımlamak için kullanılan bir araçtır. Docker Compose, bir YAML dosyası aracılığıyla uygulamanızın servislerini, ağlarını ve depolama birimlerini tanımlamanıza olanak tanır. Bu, uygulamanızın farklı bileşenlerini kolayca yapılandırmanızı ve başlatmanızı sağlar.

Docker Compose'un temel amacı, birden çok konteyneri tek bir yapı içinde tanımlayarak ve yöneterek, bu konteynerler arasında iletişim kurmayı ve uygulamanın farklı bileşenlerini bir araya getirmeyi kolaylaştırmaktır.

## Docker Compose kullanılan ve kullanılmayan durumlar arasındaki farklar

Docker Compose kullanılmadığında:
- Her bir Docker konteyneri için ayrı ayrı docker run komutu ile başlatma yapmanız gerekir.
- Konteynerlar arasında bağlantıları ve iletişimi yönetmek, ağları oluşturmak, ortam değişkenlerini belirlemek gibi detayları elle yapmanız gerekir.
- Örneğin, bir veritabanı ve bir web sunucusu aynı anda çalıştırılacaksa, her birini ayrı komutlarla başlatmanız gerekebilir.

Docker Compose kullanıldığında:
- Bir YAML dosyasında servisleri, ağları, ortam değişkenlerini ve diğer konfigürasyon detaylarını tanımlayabilirsiniz.
- docker-compose up komutu ile tüm bu servisleri tek bir komutla başlatabilirsiniz.
- Docker Compose, farklı servisler arasında iletişimi ve bağlantıları otomatik olarak yönetir. Örneğin, bir web uygulaması ve bir veritabanı, Docker Compose ile aynı anda başlatılabilir ve aralarındaki bağlantılar otomatik olarak sağlanabilir.

## Sanal makinelere kıyasla Docker'ın avantajları

**Hafif ve Hızlı Başlatma:**

- **Docker:** Docker konteynerleri, işletim sistemini paylaşan ve üzerine sadece uygulama ve bağımlılıkları ekleyen hafif sanal ortamlardır. Bu, konteynerlerin çok hızlı başlatılmasını sağlar.
- **VMs:** Sanal makineler, tam bir işletim sistemini ve uygulama yığınını içerir, bu nedenle başlatma süreleri genellikle Docker konteynerlerinden daha uzundur.

**Daha Az Kaynak Kullanımı:**

- **Docker:** Docker konteynerleri, host işletim sistemi kaynaklarını daha etkili bir şekilde kullanır çünkü birçok konteyner aynı çekirdeği ve işletim sistemini paylaşabilir.
- **VMs:** Sanal makineler, her biri kendi işletim sistemini çalıştırdığı için daha fazla kaynak tüketebilir.

**Taşınabilirlik ve Çalışabilirlik:**

- **Docker:** Docker konteynerleri, herhangi bir ortamda (geliştirme makineleri, test sunucuları) tutarlı bir şekilde çalışabilir. Docker'ın taşınabilirliği, yazılımın sorunsuz bir şekilde çalışmasını ve dağıtılmasını sağlar.
- **VMs:** Sanal makineler, taşınabilirliği sağlamak için daha fazla yapılandırma ve uyarlama gerektirebilir.

**Hızlı Dağıtım ve İterasyon:**

- **Docker:** Docker, konteynerlerin hızlı bir şekilde oluşturulmasını, dağıtılmasını ve güncellenmesini sağlar. Bu, hızlı iterasyon ve sürekli teslim süreçlerini destekler.
- **VMs:** VM'lerin oluşturulması ve dağıtılması genellikle daha uzun sürebilir.

**Daha İyi Kaynak Verimliliği:**

- **Docker:** Docker, uygulama ve bağımlılıkların sadece gerekli olan kısımlarını içerdiği için daha verimli kaynak kullanımı sağlar.
- **VMs:** VM'ler genellikle daha fazla kaynak tüketir çünkü her biri kendi işletim sistemini içerir.

## SSL/TLS Sertifikası

SSL (Secure Sockets Layer) ve TLS (Transport Layer Security), internet üzerindeki veri iletimini güvenli hale getirmek için kullanılan şifreleme protokolleridir. SSL'nin yerini zamanla TLS almıştır, ancak terimler genellikle birbirinin yerine kullanılmaktadır.

SSL/TLS sertifikası, bir web sitesinin veya bir sunucunun kimlik doğrulamasını ve internet trafiğini şifrelemesini sağlayan dijital bir belgedir. Bu sertifikalar, genellikle bir web tarayıcısı ve web sunucusu arasındaki iletişimi güvence altına alarak kullanıcıların verilerini koruma amacı taşırlar.

**SSL/TLS sertifikalarının temel bileşenleri:**

- **Anahtar Çifti (Public Key ve Private Key):** Her sertifika bir anahtar çifti içerir. Public key (genel anahtar) ile şifrelenmiş verileri çözebilmek için kullanılır. Private key (özel anahtar) ise sadece sunucu tarafında saklanan ve verileri şifrelemek ve çözmek için kullanılan bir anahtardır.

- **Dijital Sertifika (Digital Certificate):** Bir üçüncü taraf sertifikasyon otoritesi (Certificate Authority - CA) tarafından sağlanan dijital bir belgedir. Bu sertifika, bir sunucunun genel anahtarını onaylar ve kullanıcılara bu anahtarı güvenilir bir şekilde kullanma izni verir.

- **Sertifika Sahibi Bilgileri:** Sertifika üzerinde, genellikle şirket adı, domain adı ve coğrafi konum gibi bilgileri içeren sertifika sahibinin bilgileri bulunur.

- **Sertifika İmzası (Signature):** CA tarafından yapılan dijital bir imzadır. Bu, sertifikanın gerçekten de belirli bir sertifika otoritesi tarafından sağlandığını doğrular.

SSL/TLS sertifikaları, kullanıcıların ve sunucuların kimlik doğrulamasını sağlayarak veri iletimini şifreleyen ve güvenli bir bağlantı kurmalarına olanak tanıyan kritik bileşenlerdir. Çoğu modern web tarayıcısı, kullanıcılarına bir web sitesinin güvenli olup olmadığını göstermek için bir kilit simgesi veya "HTTPS" ifadesi gibi görsel ipuçları sağlar. Bu, web siteleri arasında güvenli bir veri iletimi sağlamak için kullanılan SSL/TLS sertifikalarının yaygın olarak kullanılmasının bir sonucudur.

## Sanal makineye ayarları

Sanal makine kurulumunu yaptıktan sonra terminali açıp aşağıdaki kodu girerek gerekli programların kurulumunu sağlıyoruz. 

```shell
apt-get install docker docker-compose make vim openssh-server
```

yaktas.42.fr adresini /etc/hosts dosyasına eklememiz gerekiyor. Bunun için hosts dosyasını açmamız gerekiyor.
```shell
vim /etc/hosts 
```
Açılan dosyaya aşağıdaki satırı ekliyoruz.
```
127.0.0.1  yaktas.42.fr
```

<details>
  <summary> 🛠️ SSH ile VScode üzerinden sanal makineye bağlanma ayarları</summary>
    </p>
    Sanal makinenin ağ ayarlarını açıp B.Noktası Yönlendirme kısmına aşağıdaki ayarları yapıyoruz.
    <img src="https://raw.githubusercontent.com/yeaktas/Inception/main/img/vm_settings_1.png" alt="VM 1">
    <img src="https://raw.githubusercontent.com/yeaktas/Inception/main/img/vm_settings_2.png" alt="VM 2">
    <p> <a href="https://github.com/Improvenss/inception/blob/main/Makefile">[Şuradaki bağlantıdan]</a>  Makefile dosyasını sanal makinemize indirip terminale <code>make setup_ssh</code> yazıyoruz. Böylelikle gerekli port ayarları yapılacak. </p>
    <p> Ana makinemizde VScode üzerinden SSH bağlantısı yapabilmek için uzak gezgini açıp, yeni bağlantı eklememiz gerekiyor, çıkan pencereye <code>ssh root@localhost -p 4242</code> yazarak bağlanabilirsiniz.</p>
    <p> Eğer eskiden yaptığınız bağlantılar var ise ve bunları silmek istiyorsanız <code>.ssh/</code>  dizinine gidip, <code>config</code> ve <code>known_host</code> dizinlerini silebilirsiniz.</p>
</details>

## Wordpress setup.sh açıklamaları

WordPress dizinine geçiş yapılır.
```shell
cd /var/www/html/wordpress
```
WordPress çekirdek dosyalarını indirme
```shell
wp core download --path=/var/www/html/wordpress --allow-root
```
WordPress yapılandırma dosyasını oluşturma
```shell
wp config create --path=/var/www/html/wordpress --allow-root --dbname=$DB_DATABASE --dbhost=$DB_HOST --dbprefix=wp_ --dbuser=$DB_USER_NAME --dbpass=$DB_USER_PASSWORD
```
WordPress çekirdek kurulumu
```shell
wp core install --path=/var/www/html/wordpress --allow-root --url=$DOMAIN_NAME --title="$WP_SITE_TITLE" --admin_user=$WP_ADMIN_NAME --admin_password=$WP_ADMIN_PASSWORD --admin_email=$WP_ADMIN_EMAIL
```
Tüm eklentileri güncelleme
```shell
wp plugin update --path=/var/www/html/wordpress --allow-root --all
```
Veritabanını oluşturma
```shell
wp db create --allow-root
```
Yeni bir kullanıcı oluşturma
```shell
wp user create --path=/var/www/html/wordpress --allow-root $WP_USER_NAME $WP_USER_EMAIL --user_pass=$WP_USER_PASSWORD
```
İzinleri düzenleme
```shell
chown www-data:www-data /var/www/html/wordpress/wp-content/uploads --recursive
```
Gerekli dizini oluşturma
```shell
mkdir -p /run/php/
```
PHP-FPM'yi başlatma
```shell
php-fpm8.2 -F
```

## Source 

https://gokhansengun.com/docker-nedir-nasil-calisir-nerede-kullanilir/

https://github.com/temasictfic/Inception

https://github.com/Improvenss/inception/blob/main/Makefile