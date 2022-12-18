# Настройка хоста

```sh
SERVER_IP=vds-ip
USER=oddmin
PASSWORD='***'
SSH_PORT=12345

```

## Создать пользователя с правом повышения

```sh

# У себя создать и зарегать ключ

mkdir .ssh && chmod 700 .ssh

ssh-keygen -t ed25519 -f .ssh/id_vps -P ''

ssh-copy-id -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -i .ssh/id_vps root@${SERVER_IP}

# Юзер

adduser --disabled-password --gecos "" "${USER}"
echo "${USER}:${PASSWORD}" | chpasswd
adduser "${USER}" sudo

mkdir -p "/home/${USER}/.ssh"
chown "${USER}" "/home/${USER}/.ssh"
chmod 700 "/home/${USER}/.ssh"

cp "/root/.ssh/authorized_keys" "/home/${USER}/.ssh/authorized_keys"
chown "${USER}" "/home/${USER}/.ssh/authorized_keys"
chmod 600 "/home/${USER}/.ssh/authorized_keys"


# Зайти под юзером по ключу
ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -i vps/.ssh/id_vps \
    -p 32931 oddmin@${SERVER_IP}

```


## Тюнинг ssh

- Вырубить рутовый логин
- Вырубить парольный логин
- Оставить только логин по ключу
- Задать упоротый порт

```sh

sed -r \
-e "s/^#?Port 22$/Port ${SSH_PORT}/" \
-e 's/^#?LoginGraceTime (120|2m)$/LoginGraceTime 30/' \
-e 's/^#?PermitRootLogin yes$/PermitRootLogin no/' \
-e 's/^#?X11Forwarding yes$/X11Forwarding no/' \
-e 's/^#?UsePAM yes$/UsePAM no/' \
-e "s/^#?PasswordAuthentication yes$/PasswordAuthentication no/" \
-i.original /etc/ssh/sshd_config

service ssh restart

# проверка

cat <<!
ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -i .ssh/id_vps -p "${SSH_PORT}" "${USER}@${SERVER_IP}"
!
```


## Сетевой доступ

+ ssh
+ lo
+ icmp
+ other
+ established,related
+ policy DROP

```sh
# Удалить ufw

systemctl disable ufw

# Поставить iptables

apt install iptables iptables-persistent


# Настроить базовую защиту


# политика по умолчанию для INPUT и FORWARD
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT

# очистка таблиц и статистики
iptables -F
iptables -Z

# правила INPUT таблицы filter
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport "${SSH_PORT}" -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -P INPUT DROP


# Сохранить настроки
netfilter-persistent save
netfilter-persistent reload
```


# VPN

## Конфигурация

```sh
SERVER_IP=${SERVER_IP}
IFACE=eth0
WORK_DIR=~/swan-vpn
CLIENT_ID=
CLIENT_SECRET=

mkdir -p "${WORK_DIR}" &&
cd "${WORK_DIR}"
```

## Установка пакетов сервера

```sh
sudo apt update
sudo apt install \
    strongswan \
    strongswan-pki \
    libcharon-extra-plugins \
    libcharon-extauth-plugins \
    libstrongswan-extra-plugins
```

## Создание сертификатов

```sh
mkdir -p pki/{cacerts,certs,private}
chmod 700 pki/private

# Сертификат ЦС

pki --gen --type rsa --size 4096 --outform pem > pki/private/ca-key.pem
pki --self --ca --lifetime 3650 --in pki/private/ca-key.pem \
    --type rsa --dn "CN=VPN root CA" --outform pem > pki/cacerts/ca-cert.pem


# Сертификат сервера

pki --gen --type rsa --size 4096 --outform pem > pki/private/server-key.pem
pki --pub --in pki/private/server-key.pem --type rsa | pki --issue --lifetime 1825 \
    --cacert pki/cacerts/ca-cert.pem \
    --cakey pki/private/ca-key.pem \
    --dn "CN=${SERVER_IP}" \
    --san "@${SERVER_IP}" \
    --san "${SERVER_IP}" \
    --flag serverAuth \
    --flag ikeIntermediate \
    --outform pem \
    >  pki/certs/server-cert.pem
```

## Генерация файлов конфигурации

```sh

cat > ipsec-server.conf <<EOF
config setup
    #charondebug="ike 1, knl 1, cfg 0"
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2,  mgr 2"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=${SERVER_IP}
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity
    ike=chacha20poly1305-sha512-curve25519-prfsha512,aes256gcm16-sha384-prfsha384-ecp384,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=chacha20poly1305-sha512,aes256gcm16-ecp384,aes256-sha256,aes256-sha1,3des-sha1!
EOF

cat > ipsec-server.secrets <<EOF
: RSA "server-key.pem"
${CLIENT_ID} : EAP "${CLIENT_SECRET}"
EOF


cat > ipsec-client.conf <<EOF
config setup

conn ikev2-rw
    right=${SERVER_IP}
    # This should match the 'leftid' value on your server's configuration
    rightid=${SERVER_IP}
    rightsubnet=0.0.0.0/0
    rightauth=pubkey
    leftsourceip=%config
    leftid=${CLIENT_ID}
    leftauth=eap-mschapv2
    eap_identity=%identity
    auto=start
EOF

cat > ipsec-client.secrets <<EOF
${CLIENT_ID} : EAP "${CLIENT_SECRET}"
EOF


cat > ipsec-server-2rw.conf <<EOF
config setup
    #charondebug="ike 1, knl 1, cfg 0"
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2,  mgr 2"
    uniqueids=no

conn %default
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=${SERVER_IP}
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    eap_identity=%identity
    ike=chacha20poly1305-sha512-curve25519-prfsha512,aes256gcm16-sha384-prfsha384-ecp384,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=chacha20poly1305-sha512,aes256gcm16-ecp384,aes256-sha256,aes256-sha1,3des-sha1!

conn doll7
    right=%any
    rightid=me2
    rightsourceip=10.10.10.7
    rightsendcert=never
    rightauth=eap-mschapv2
    auto=add

conn other
    right=%any
    rightid=%any
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    rightauth=eap-mschapv2
    auto=add
EOF


cat > ipsec-client-doll7.conf <<EOF
config setup

conn ikev2-rw
    right=${SERVER_IP}
    # This should match the 'leftid' value on your server's configuration
    rightid=${SERVER_IP}
    # rightsubnet=0.0.0.0/0
    rightauth=pubkey
    leftsourceip=%config
    leftid=doll7
    leftauth=eap-mschapv2
    eap_identity=%identity
    auto=start
EOF


cat > ipsec-client-lemon5.conf <<EOF
config setup

conn ikev2-rw
    right=${SERVER_IP}
    # This should match the 'leftid' value on your server's configuration
    rightid=${SERVER_IP}
    rightsubnet=10.10.10.0/24
    rightauth=pubkey
    leftsourceip=%config
    leftid=lemon5
    leftauth=eap-mschapv2
    eap_identity=%identity
    auto=start
EOF

```


## Применение настроек

```sh
# certs
sudo cp -r pki/* /etc/ipsec.d/

# config
sudo mv /etc/ipsec.conf{,.original}
sudo cp ipsec-server.conf /etc/ipsec.conf

# secrets
sudo cp ipsec-server.secrets /etc/ipsec.secrets

# restart
sudo systemctl restart strongswan-starter
```


## Настройка ядра

```sh

cat >> /etc/sysctl.conf <<EOF

### ipsec ###
net.ipv4.ip_forward=1 # включить переадресацию пакетов
net.ipv4.conf.all.accept_redirects = 0 # предотвратить MITM-атаки
net.ipv4.conf.all.send_redirects = 0 # запретить отправку ICMP-редиректов
net.ipv4.ip_no_pmtu_disc = 1 # запретить поиск PMTU
EOF

sysctl -p

```

## Настройка сетвого фильтра

```sh
sudo sh -c "
iptables -A INPUT -p udp --dport  500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT

iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s 10.10.10.0/24 -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d 10.10.10.0/24 -j ACCEPT

# iptables -t nat -A POSTROUTING -d 10.10.10.0/24 -o ${IFACE} -j ACCEPT # не пускать в nat пакеты
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o ${IFACE} -m policy --pol ipsec --dir out -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o ${IFACE} -j MASQUERADE

iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.0/24 -o ${IFACE} -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

iptables -P FORWARD DROP

netfilter-persistent save
netfilter-persistent reload

iptables -S
"
```

# Установка клиента

```sh
# packages
apt update
apt install strongswan libcharon-extra-plugins
systemctl disable --now strongswan-starter

# certs
cp pki/cacerts/ca-cert.pem /etc/ipsec.d/cacerts/

# config
mv /etc/ipsec.conf{,.original}
cp ipsec-client.conf /etc/ipsec.conf

# secrets
mv /etc/ipsec.secrets{,.original}
cp ipsec-client.secrets /etc/ipsec.secrets

# Start/stop
systemctl start strongswan-starter
systemctl stop strongswan-starter

# TODO: tune apparmor
cat >> /etc/resolv.conf <<!
nameserver 77.88.8.8
!


# Alternative start/stop
charon-cmd --cert ca-cert.pem --host "${SERVER_IP}" --identity "${CLIENT_ID}"
```
