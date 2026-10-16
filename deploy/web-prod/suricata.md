# Suricata pe web-prod (faza 12, pasul 5)

Suricata 7.0.10 din Debian 13 (JA4 compilat). Mod IDS pasiv, af-packet pe
enp0s3: doar observa traficul. NU nfqueue (inline): acolo o cadere a lui
Suricata opreste traficul.

Limita: af-packet pe enp0s3 nu vede loopback. Atacurile simulate local de harness
(curl catre ::1) nu apar in Suricata; traficul real din retea, da.

Resurse: web-prod are 2 nuce si 2 GB RAM; ET Open incarcat ia ~400-600 MB.
Verifica memoria dupa pornire.

## Etapa A — instalare si inspectie (facuta 2026-10-16)

    sudo apt-get install -y suricata suricata-update

Rezultat: default-rule-path /var/lib/suricata/rules; community-id: false (linia
136); af-packet `- interface: eth0` (linia 622); `#ja4-fingerprints: auto`
(linia 910); JA4 support: yes.

## Etapa B — configurare si pornire

Sed-urile au numarul liniei SI textul vechi: daca linia nu e cea asteptata, nu
schimba nimic (verifica cu afisarea de dupa).

    sudo cp -n /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.orig
    sudo sed -i '136s/community-id: false/community-id: true/' /etc/suricata/suricata.yaml
    sudo sed -i '622s/- interface: eth0/- interface: enp0s3/' /etc/suricata/suricata.yaml
    sudo sed -i '910s/#ja4-fingerprints: auto/ja4-fingerprints: yes/' /etc/suricata/suricata.yaml
    sed -n '136p;622p;910p' /etc/suricata/suricata.yaml
    systemctl cat suricata | grep ExecStart
    sudo suricata-update
    sudo suricata -T -c /etc/suricata/suricata.yaml
    sudo systemctl restart suricata

Verificare (dupa ~30 s):

    systemctl is-active suricata
    sudo tail -5 /var/log/suricata/suricata.log
    sudo ls -l /var/log/suricata/eve.json
    free -m | head -2

## Fleet

Integrations -> "Suricata" -> Add -> politica lui web-prod. Calea implicita
/var/log/suricata/eve.json. Datele ajung in logs-suricata.eve-*, indexul pe care
il citeste deja tool_suricata_alerts (Tier 2).

## Revenire

    sudo systemctl disable --now suricata
    sudo cp /etc/suricata/suricata.yaml.orig /etc/suricata/suricata.yaml

## Ajustari facute la instalare (2026-10-16)

- `bpf-filter: "not (host 172.20.99.220 and tcp port 9200)"` (linia 687): agentul
  trimite la Elasticsearch prin HTTP cu ApiKey; fiecare _bulk declansa alerta
  2221034 si dubla volumul. Defend vede in continuare conexiunile.
- `ja4: on` in iesirea eve tls (linia 257): JA4 se calcula, dar nu se scria.
- threshold.config: `suppress gen_id 1, sig_id 2221034, track by_dst, ip 172.20.99.220`
  (check-in-urile Fleet pe 8220, tot HTTP cu ApiKey).
- Memorie dupa pornire: ~550 MB RSS, ~630 MB disponibili pe host.

In Elasticsearch: host.name lipseste din documentele Suricata (integrarea il trateaza
ca senzor); hostul e observer.hostname. JA4 e in suricata.eve.tls.ja4.

De facut: actualizarea zilnica a regulilor (suricata-update + reload), cu aprobare.
