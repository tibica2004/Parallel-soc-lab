# Intarire web-prod (expuneri gasite la auto-atacul de masurare 2026-11-03)

NU sunt honeytokens. `.env.bak`, `backup.sql`, `/db-backup/`, `/wp-admin-old/` SUNT honeytokens
(faza 12) si se PASTREAZA. Mai jos doar expunerile reale.

## 1. Directory listing (Options Indexes) — Apache
`/wp-content/uploads/` si `/wp-includes/` listau continutul. Comenzi (cont cu sudo pe web-prod):

    TS=$(date -u +%Y%m%dT%H%M%SZ)
    sudo cp -p /etc/apache2/apache2.conf /root/apache2.conf.pre-hardening-$TS
    sudo sed -i -E 's/^([[:space:]]*)Options Indexes FollowSymLinks/\1Options FollowSymLinks/' /etc/apache2/apache2.conf
    sudo apache2ctl configtest && sudo systemctl reload apache2
    curl -s -o /dev/null -w 'uploads: %{http_code}\n' http://localhost/wp-content/uploads/   # astept 403

Revenire: `sudo cp /root/apache2.conf.pre-hardening-$TS /etc/apache2/apache2.conf && sudo systemctl reload apache2`.

## 2. Enumerare de utilizatori (REST /wp/v2/users, ?author=N) — WordPress
Deploy mu-plugin (cont cu sudo pe web-prod):

    sudo install -o root -g root -m 644 disable-user-enum.php /var/www/html/wp-content/mu-plugins/disable-user-enum.php
    # (daca lipseste directorul) sudo mkdir -p /var/www/html/wp-content/mu-plugins
    curl -s 'http://localhost/?rest_route=/wp/v2/users' | head -c 80   # astept eroare / gol

Revenire: `sudo rm /var/www/html/wp-content/mu-plugins/disable-user-enum.php`.

## 3. Parola slaba admin (de VERIFICAT de om)
hydra a raportat `admin:0` ca valid — posibil parola slaba reala sau fals pozitiv hydra. NU am
verificat prin login. Daca e reala: schimba parola admin din wp-admin. Nu e ceva ce prinde SOC-ul.
