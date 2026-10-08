#!/bin/bash
# Daca opresti cu Ctrl+C, Defend se reporneste automat
trap 'echo; echo "Intrerupt - repornesc Defend"; ssh $WEB_PROD_HOST "sudo systemctl start ElasticEndpoint"; exit 1' INT

echo "$(date +%H:%M) 1. Opresc Defend pe web-prod"
ssh $WEB_PROD_HOST 'sudo systemctl stop ElasticEndpoint'
sleep 60
echo "$(date +%H:%M)    Stare dupa 1 minut: $(ssh $WEB_PROD_HOST 'systemctl is-active ElasticEndpoint')"

echo "$(date +%H:%M) 2. Astept 15 minute..."
sleep 900

echo "$(date +%H:%M) 3. Logul canarului:"
tail -5 ~/lab/results/canary.log

echo "$(date +%H:%M) 4. Repornesc Defend"
ssh $WEB_PROD_HOST 'sudo systemctl start ElasticEndpoint'

echo "$(date +%H:%M) 5. Astept 10 minute revenirea..."
sleep 600
tail -3 ~/lab/results/canary.log
echo "$(date +%H:%M) Test terminat."
