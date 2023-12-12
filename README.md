Creare 4 macchine virtuali
Abbiamo usato:
- Debian 11 per il Router
- Debian 12 per Risorsa e Bastion Host
- Kali per come macchina esterna

Per il Router inserire 4 schede di rete: 1 NAT, le altre 3 con Rete Interna 
(abilitando la modalità promiscua nella Inerfaccia di rete che si collega a Risorsa e Bastion Host)

Per le altre 3 Macchine virtuali inserire 2 schede di rete: 1 NAT, e 1 Rete Interna

Aprire le VM, per vedere quali reti sono presenti digitare il comando sul terminale:
	ip a oppure ifconfig
-per Risorsa e Bastion Host si avrà enp0s3 per la NAT e enp0s8 per la Rete Interna
-per Kali si avrà eth0 per la NAT e eth1 per la Rete Interna
-per Router si avrà enp0s3 per la NAT e enp0s8, enp0s9, enp0s10 per le Reti Interne

successivamente, digitale il comando:
	sudo nano /etc/network/interfaces
questo ci permette di configurare le nostre interfacce di rete con indirizzi che vogliamo assegnare noi
-per Kali aggiungere sotto le seguenti righe:
	auto eth1
	iface eth1 inet static
		address 192.168.1.11 #210.10.10.2
		gateway 192.168.1.1 #210.10.10.1
		
-per Risorsa aggiungere sotto le seguenti righe:
	auto enp0s8
	iface enp0s8 inet static
		address 192.168.2.22 #192.168.1.2
		gateway 192.168.2.2 #192.168.1.1
		
-per Bastion Host aggiungere sotto le seguenti righe:
	auto enp0s8
	iface enp0s8 inet static
		address 192.168.3.33 #211.11.11.2
		gateway 192.168.3.3 #211.11.11.1
		
-per Router aggiungere sotto le seguenti righe:
	#Kali
	auto enp0s8
	iface enp0s8 inet static
		address 192.168.1.1 #210.10.10.1
		
	#Risorsa
	auto enp0s9
	iface enp0s9 inet static
		address 192.168.2.2 #192.168.1.1
	
	#Bastion Host
	auto enp0s10
	iface enp0s10 inet static
		address 192.168.3.3 #211.11.11.1

Dopo aver salvato le varie il file interfaces, digitare il seguente  comando per ognuna delle VM:
	sudo systemctl restart networking
	
Inoltre soltanto nel router impostare il comando per abilitare il forwarding dei pacchetti di rete
tra le macchine:
	sudo sysctl -w net.ipv4.ip_forward=1
Per verificare se il comando precedente sia attivo si può digitare:
	cat /prc/sys/net/ipv4/ip_forward

Per vedere la tabella di routing usa
	sudo ip route show
Per pulire la tabella di routing usa
	sudo ip route flush table all
	
Sempre in Router impostare il traffico tra Kali e Risorsa, digitando:
	sudo ip route add 192.168.2.0/24 via 192.168.1.1 dev enp0s8
oppure:
	sudo ip route add 192.168.1.0/24 via 210.10.10.1 dev enp0s8

Puoi fare il ping dalle varie VM digitando il seguente commento:
	ping <indirizzo_VM_destinazione> -c2 -R
	
Se hai riavviato la VM , potrebbe non funzionare internet, una delle soluzioni è andare a modificare
il file resolv.conf, digitando:
	sudo nano /etc/resolv.conf
se c'è scritto 'nameserver 192.168.1.1', cancellare questa riga e scrivere:
	nameserver 8.8.8.8
	nameserver 8.8.4.4
salvare e tornare al terminale

IPTABLES
Successivamente digitare i seguenti comandi, che sono 3 regole dove si rifiuta la comunicazione con 
tutte e tre le interfacce di rete del Eouter come destinatario:
	sudo iptables -I INPUT -s 210.10.10.2 -j DROP -d 210.10.10.1
	sudo iptables -I INPUT -s 210.10.10.2 -j DROP -d 211.11.11.1
	sudo iptables -I INPUT -s 210.10.10.2 -j DROP -d 192.168.1.1
	
Poi, nella catena di FORWARD si inseriscono le regole per tutti i pacchetti in transito nel router 
e non destinati direttamente ad esso, stabiliamo quindi di scartare tutti i pacchetti destinati 
direttamente alla Risorsa e al Bastion Host:
	sudo iptables -A FORWARD -s 210.10.10.2 -j DROP -d 192.168.1.2
	sudo iptables -A FORWARD -s 210.10.10.2 -j DROP -d 211.11.11.2
	
Poi, le successive regole sono invece inserite in testa alla catena(opzione -I), e consentono di 
stabilire connessioni tcp stateful, nel quale si tiene conto anche del continuo cambio di porte 
per la connessione:
	sudo iptables -I FORWARD -s 211.11.11.2 -d 210.10.10.2 -p tcp -m conntrack --ctstate 
		NEW,ESTABLISHED,RELATED -j ACCEPT
	sudo iptables -I FORWARD -s 210.10.10.2 -d 211.11.11.2 -p tcp -m conntrack --ctstate 
		NEW,ESTABLISHED,RELATED -j ACCEPT
		
Per vedere il risultato finale digitare:
	sudo iptables -L -n -v

SNORT
Successivamente si può iniziare a scaricare Snort, con il seguente comando:
	sudo apt-get install snort -y
durante l'installazione chiederà le interfacce che snort ascolta, qui si può inserire il nome 
delle interfacce per Risorsa e Bastion Host, quindi enp0s9 e enp0s10, in più chiederà anche il 
range degli indirizzi che andranno in HOME_NET. (comunque può essere fatto anche avanti)

Andare a lavorare sul file di configurazione snort creando però una copia:
noi abbiamo  /etc/snort/snort.conf, vogliamo creare snort_copy.conf, per fare questo scriviamo i comandi:
	sudo cp /etc/snort/snort.conf /etc/snort/snort_copy.conf
	
andare ad aprire il snort_copy.conf, digitando il comando:
	sudo nano /etc/snort/snort_copy.conf
	
aggiungere gli indirizzi in ipvar HOME_NET any, sostituendo 'any' con gli indirizzi da aggiungere, quindi:
	ipvar HOME_NET [192.168.2.0/24,192.168.3.0/24] #Address di Bastion Host e Risorsa
oppure:
	ipvar HOME_NET [211.11.11.0/24,192.168.1.0/24] #Address di Bastion Host e Risorsa
slavare e tornare al terminale.

Controllare che la modalità promiscua sia abilitata, si può fare in 2 modi: 
-direttamente dalle impostazioni della VM
-andando a digitare i comandi sul terminale:
	sudo ip link set enp0s9 promisc on
	sudo ip link set enp0s10 promisc on
	
Per controllare che il file di configurazione sia implementato correttamente si digita:
	sudo snort -i enp0s10 -c /etc/snort/snort_copy.conf -T #per Bastion Host
Questo comando fa il seguente:
[] -i enp0s10: specifica l'interfaccia di rete del Bastion Host.
[] -c /etc/snort/snort2.conf: specifica il percorso del file di configurazione di Snort.
[] -T: esegue una verifica di sintassi nel file di configurazione senza effettuare effettivamente 
	l'analisi del traffico.

Andare a vere le regole in snort col comando:
	sudo nano /etc/snort/rules/local.rules
Le REGOLE possono essere scritte anche utilizzando SNORPY (http://snorpy.cyb3rs3c.net/)

Inserira la seguenta regola:
	alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; sid:100001; rev:1;) 
	(sid è un indice univoco per ogni allert)
Poi andare a digitare il comando:
	sudo snort -q -l /var/log/snort -i enp0s8 -A console -c /etc/snort/snort_copy.conf
(se non fa vedere niente significa che funziona)
Una volta fatto questo andare a provare a fare il ping alla Risorsa con Kali, quindi nel terminale di
kali digitare:
	192.168.1.1 #gateway della Risorsa
	
Inserire un'ulteriore regola:
	alert tcp any any -> $HOME_NET 22 (msg:"SSH Authentication Attempt"; sid:100002; rev:1;) 
Poi andare su Kali e cercare di fare una connessione ssh con la Risorsa digitando il seguente comando:
	ssh debian@192.168.1.1 #ssh <nome_utente_Router>@<indirizzo>
provanod ad inserire la password del VM Router.


SQUID
Innanzitutto scaricare ed installare Squid sulla VM Bastion Host attraverso il seguente comando:
	sudo apt-get install squid -y

Poi, andare a modificare il file squid.conf:
	sudo nano /etc/squid/squid.conf
Nella sezione INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS, scriver:
	acl localnet src 192.168.1.0/24
	http access allow localnet
	
	acl badurl url_regex “/etc/squid/url.txt”
	http_access deny badurl
	
	http_access allow localhost
	
	http_access allow all

Una volta inserito i comandi su squid.conf salvare e tornare al terminale, e digitare:
	sudo systemctl restart squid
	
Andare sulla VM Risorsa e settare il proxy in manuale inserendo come indirizzo 211.11.11.2 e 
porta 3128 sia per HTTP che HTTPS (questo si può fare andando nelle impostazioni di FireFox)

E possibile osservare i log generati da squid durante la connessione della VM con l'impostazione proxy:
digitare il seguente comando in Bastion Host:
	tail -f /var/log/squid/access.log

Se qualcosa non va è bene cancellare la cache arrestando prima squid, digitando i seguenti comandi:
	sudo systemctl stop squid
poi:
	rm -rf /var/spool/squid/*
Riavviare squid.
Si può controllare lo stato di squid digitando il seguente comando:
	systemctl status squid

