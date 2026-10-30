#!/bin/bash
# Instaleaza contul read-only soc-reader pe web-prod (pasul 1b). Root, o data, de OM:
#   scp -r deploy/web-prod/soc-reader tiberiu@172.30.6.249:/tmp/soc-reader   (+ cheia publica)
#   ssh -t tiberiu@172.30.6.249 'sudo bash /tmp/soc-reader/install.sh /tmp/soc-reader/soc-reader.pub'
#
# - cont de sistem soc-reader, fara parola (blocat), shell /bin/sh: sshd ruleaza comanda
#   fortata prin shell-ul contului; cu nologin ar refuza-o. Login interactiv imposibil:
#   authorized_keys forteaza gate-ul si `restrict` (fara pty, forwarding, agent, X11, rc).
# - authorized_keys si ~/.ssh sunt ale lui root: contul nu-si poate schimba comanda fortata.
# - NU se modifica sshd_config (un bloc Match intr-un drop-in poate „curge” peste setarile
#   globale de dupa Include); nu e nevoie de reload.
# - Webroot-ul e deja citibil de oricine, cu exceptia wp-config.php (640 root:www-data):
#   ramane INACCESIBIL pentru soc-reader. Fara ACL-uri.
# Revenire: userdel -r soc-reader; rm /usr/local/bin/soc-reader-gate
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd)
PUB=${1:?folosire: install.sh /cale/cheie.pub}
H=/var/lib/soc-reader

[ "$(id -u)" -eq 0 ] || { echo "ruleaza ca root" >&2; exit 1; }
grep -qE '^ssh-ed25519 [A-Za-z0-9+/=]+ ' "$PUB" || { echo "cheie publica ed25519 invalida" >&2; exit 1; }
bash -n "$D/soc-reader-gate"

id soc-reader >/dev/null 2>&1 || useradd --system --shell /bin/sh --home-dir "$H" --no-create-home soc-reader
passwd -l soc-reader >/dev/null
install -d -o root -g root -m 755 "$H" "$H/.ssh"
install -o root -g root -m 755 "$D/soc-reader-gate" /usr/local/bin/soc-reader-gate
printf 'restrict,command="/usr/local/bin/soc-reader-gate" %s\n' "$(cut -d' ' -f1,2 "$PUB") soc-reader@es-node-1" \
    > "$H/.ssh/authorized_keys"
chmod 644 "$H/.ssh/authorized_keys"

echo "cont: $(id soc-reader)  parola: $(passwd -S soc-reader | awk '{print $2}')"
ls -ld "$H" "$H/.ssh" "$H/.ssh/authorized_keys" /usr/local/bin/soc-reader-gate
cut -c1-60 "$H/.ssh/authorized_keys"
# setarile efective ale sshd pentru cont (nimic schimbat, doar afisat)
sshd -T -C user=soc-reader,host=es-node-1,addr=192.168.10.121 2>/dev/null \
    | grep -E '^(passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin) '
echo "Gata. Test de pe es-node-1: ssh -i ~/.ssh/soc-reader soc-reader@192.168.10.138 'cat /etc/passwd'"
