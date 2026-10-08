# Reverse shell: shell interactiv sau /dev/tcp

## Ce inseamna
Shell cu conexiune de retea inversa (bash -i, /dev/tcp, nc -e). Aproape nimic
legitim nu foloseste aceste constructii.

## Verifica
- command_line contine /dev/tcp, /dev/udp, bash -i, nc -e sau ncat -e
  -> reverse shell, CRITIC. T1059.004.
- destination.ip din egress: IP extern nevazut -> C2 confirmat.
  Intern sau loopback -> poate fi test, dar tot suspect.

## Verifica contextul
- Un pentest programat de un admin cunoscut, in fereastra de mentenanta, poate
  produce asta legitim. Fara fereastra, sau de la www-data -> atac.

## Concluzie
/dev/tcp in afara unei ferestre de mentenanta -> malicious, escaladeaza.
