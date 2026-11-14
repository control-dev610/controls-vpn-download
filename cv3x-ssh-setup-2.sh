#!/bin/bash
# C-V3-X : serveur SSH-SSL + payload + udpgw. Ne touche pas à CONTROLS (ports, fichiers, services séparés).
# Usage : bash cv3x-ssh-setup.sh        (ou PORT=8443 bash cv3x-ssh-setup.sh pour imposer le port SSL)
set -u
[ "$(id -u)" = 0 ] || { echo "Lance ce script en root."; exit 1; }
D=/opt/cv3x-ssh; U=cv3x; PROXY=2200; UDPGW=7300
mkdir -p $D
busy(){ ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"; }
say(){ echo; echo "== $*"; }

say "1/7 Paquets"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq stunnel4 openssl python3 cmake build-essential git >/dev/null 2>&1 || { echo "Échec apt-get install"; exit 1; }
ST=$(command -v stunnel4 || command -v stunnel) || { echo "stunnel introuvable"; exit 1; }

say "2/7 Port SSL"
[ -z "${PORT:-}" ] && [ -f $D/stunnel.conf ] && PORT=$(sed -n 's/^accept = 0.0.0.0://p' $D/stunnel.conf)
if [ -z "${PORT:-}" ]; then
  for p in 443 8443 2083 2087 2096; do
    if ! busy $p; then PORT=$p; break; fi
  done
fi
[ -n "${PORT:-}" ] || { echo "Aucun port libre parmi 443 8443 2083 2087 2096. Relance avec PORT=xxxx"; exit 1; }
if busy $PORT && ! systemctl is-active -q cv3x-stunnel; then echo "Le port $PORT est déjà pris (CONTROLS ?). Relance avec PORT=xxxx"; exit 1; fi
for p in $PROXY $UDPGW; do
  if busy $p && ! systemctl is-active -q cv3x-payload cv3x-udpgw; then echo "Port interne $p déjà pris. Arrêt (rien n'a été modifié)."; exit 1; fi
done
echo "Port SSL : $PORT"

say "3/7 Relais payload"
cat > $D/payload_proxy.py <<'PYEOF'
#!/usr/bin/env python3
"""C-V3-X : accepte « payload HTTP puis SSH » ou SSH direct, et relaie vers le sshd local."""
import asyncio, sys

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 2200
TARGET = ("127.0.0.1", 22)
MAXHDR = 16384
OK_CONNECT = b"HTTP/1.1 200 Connection established\r\n\r\n"
OK_WS = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"


async def pipe(r, w):
    try:
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(d)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def more(cr, wait=30):
    d = await asyncio.wait_for(cr.read(4096), wait)
    if not d:
        raise ConnectionError
    return d


async def handle(cr, cw):
    buf = b""
    answered = False
    try:
        while True:                       # on avale chaque requête du payload, on répond, jusqu'au « SSH- »
            buf = buf.lstrip(b"\r\n")
            if not buf:
                # Le client attend peut-être la bannière du serveur SSH avant de parler : on ne le fait pas attendre.
                try:
                    buf = (await more(cr, 1.5 if answered else 3)).lstrip(b"\r\n")
                except asyncio.TimeoutError:
                    break
                continue
            m = buf.find(b"SSH-2.0-")
            if m == 0:
                break
            if m > 0:
                # Payload mal terminé (pas de ligne vide) ou collé à la bannière : on bascule dès qu'on voit « SSH-2.0- ».
                if not answered:
                    cw.write(OK_WS)
                    await cw.drain()
                buf = buf[m:]
                break
            if len(buf) < 8 and b"SSH-2.0-".startswith(buf):
                buf += await more(cr)
                continue
            end, n = buf.find(b"\r\n\r\n"), 4
            if end < 0:
                end, n = buf.find(b"\n\n"), 2
            if end < 0:
                if len(buf) > MAXHDR:
                    raise ConnectionError
                buf += await more(cr)
                continue
            first = buf[:end].split(b"\n", 1)[0].upper()
            buf = buf[end + n:]
            cw.write(OK_CONNECT if first.startswith(b"CONNECT") else OK_WS)
            await cw.drain()
            answered = True
        ur, uw = await asyncio.open_connection(*TARGET)
    except Exception:
        cw.close()
        return
    uw.write(buf)
    await uw.drain()
    await asyncio.gather(pipe(cr, uw), pipe(ur, cw))


async def main():
    srv = await asyncio.start_server(handle, "127.0.0.1", LISTEN_PORT)
    async with srv:
        await srv.serve_forever()

asyncio.run(main())
PYEOF
cat > /etc/systemd/system/cv3x-payload.service <<EOF
[Unit]
Description=C-V3-X relais payload -> sshd
After=network.target
[Service]
User=nobody
ExecStart=/usr/bin/python3 $D/payload_proxy.py $PROXY
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF

say "4/7 SSL (stunnel)"
[ -f $D/cert.pem ] || openssl req -new -x509 -days 3650 -nodes -subj "/CN=cv3x" -keyout $D/key.pem -out $D/cert.pem >/dev/null 2>&1
chmod 600 $D/key.pem
cat > $D/stunnel.conf <<EOF
foreground = yes
pid =
setuid = nobody
setgid = nogroup
[cv3x]
accept = 0.0.0.0:$PORT
connect = 127.0.0.1:$PROXY
cert = $D/cert.pem
key = $D/key.pem
EOF
cat > /etc/systemd/system/cv3x-stunnel.service <<EOF
[Unit]
Description=C-V3-X SSL -> relais payload
After=network.target cv3x-payload.service
[Service]
ExecStart=$ST $D/stunnel.conf
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF

say "5/7 udpgw (UDP : DNS, appels, jeux) — 1 à 2 minutes"
if [ ! -x /usr/local/bin/badvpn-udpgw ]; then
  rm -rf $D/badvpn && git clone -q --depth 1 https://github.com/ambrop72/badvpn.git $D/badvpn >/dev/null 2>&1 \
  && mkdir -p $D/badvpn/build && cd $D/badvpn/build \
  && cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 >/dev/null 2>&1 && make -j2 >/dev/null 2>&1 && make install >/dev/null 2>&1
  cd /
fi
if [ -x /usr/local/bin/badvpn-udpgw ]; then
cat > /etc/systemd/system/cv3x-udpgw.service <<EOF
[Unit]
Description=C-V3-X udpgw
After=network.target
[Service]
User=nobody
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:$UDPGW --max-clients 1000 --max-connections-for-client 64
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
else echo "ATTENTION : udpgw n'a pas pu être compilé (le reste marche, mais pas l'UDP)."; fi

say "6/7 Compte SSH $U (tunnel seulement, pas de shell)"
id $U >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin $U
PASS=$(sed -n 's/^Mot de passe : //p' /root/cv3x-ssh-infos.txt 2>/dev/null)
[ -n "$PASS" ] || PASS=$(openssl rand -base64 30 | tr -dc 'A-Za-z0-9' | head -c 16)
echo "$U:$PASS" | chpasswd
C=/etc/ssh/sshd_config
if ! grep -q '# >>> cv3x' $C; then
  cp $C /root/sshd_config.avant-cv3x
  cat >> $C <<'EOF'

# >>> cv3x (C-V3-X)
Match User cv3x
    PasswordAuthentication yes
    AllowTcpForwarding yes
    PermitTTY no
    X11Forwarding no
    AllowAgentForwarding no
# <<< cv3x
EOF
  if ! sshd -t 2>/tmp/cv3x-sshd.err; then
    cp /root/sshd_config.avant-cv3x $C
    echo "Config SSH refusée, remise d'origine faite. Erreur :"; cat /tmp/cv3x-sshd.err; exit 1
  fi
fi
grep -qiE '^\s*AllowUsers' $C /etc/ssh/sshd_config.d/*.conf 2>/dev/null && echo "ATTENTION : une ligne AllowUsers existe. Ajoute-y cv3x, sinon le compte sera refusé."
systemctl reload ssh 2>/dev/null || systemctl reload sshd

say "7/7 Démarrage et vérification"
systemctl daemon-reload
for s in cv3x-payload cv3x-stunnel cv3x-udpgw; do
  [ -f /etc/systemd/system/$s.service ] && { systemctl enable -q $s; systemctl restart $s; }
done
command -v ufw >/dev/null && ufw status | grep -q "Status: active" && ufw allow $PORT/tcp >/dev/null
sleep 3
T=$(timeout 6 bash -c "printf 'GET / HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\n\r\n' | openssl s_client -connect 127.0.0.1:$PORT -quiet 2>/dev/null" | head -c 300)
IP=$(hostname -I | awk '{print $1}')
echo "$T" | grep -q "SSH-" && OK="OK (SSL + payload + SSH répondent)" || OK="ÉCHEC"
U_ST=$(systemctl is-active cv3x-udpgw 2>/dev/null)
cat > /root/cv3x-ssh-infos.txt <<EOF
===== C-V3-X : serveur SSH-SSL =====
Test local   : $OK
Hôte         : $IP
Port SSL     : $PORT
Utilisateur  : $U
Mot de passe : $PASS
UDPGW        : 127.0.0.1:$UDPGW ($U_ST)
CONTROLS     : non modifié
EOF
echo; cat /root/cv3x-ssh-infos.txt
echo "(Infos gardées dans /root/cv3x-ssh-infos.txt)"
if [ "$OK" = "ÉCHEC" ]; then echo; echo "---- diagnostic ----"; for s in cv3x-payload cv3x-stunnel; do systemctl is-active $s; journalctl -u $s -n 6 --no-pager 2>/dev/null; done; fi
