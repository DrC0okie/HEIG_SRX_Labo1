[![Open in Visual Studio Code](https://classroom.github.com/assets/open-in-vscode-c66648af7eb3fe8bc4f294546bfd86ef473780cde1dea487d3c4ff354943c9ae.svg)](https://classroom.github.com/online_ide?assignment_repo_id=10207398&assignment_repo_type=AssignmentRepo)
# HEIGVD - Sécurité des Réseaux - 2023
# Laboratoire n°1 - Port Scanning et initiation à Nmap

[Introduction](#introduction)
[Auteurs](#auteurs)
[Fichiers nécessaires](#fichiers-nécessaires)
[Rendu](#rendu)
[Le réseau de test](#le-réseau-de-test)
[Infrastructure virtuelle](#infrastructure-virtuelle)
[Connexion à l’infrastructure par OpenVPN](#connexion-à-linfrastructure-par-wireguard)
[Réseau d’évaluation](#réseau-dévaluation)
[Scanning avec Nmap](#scanning-avec-nmap)
[Scanning du réseau (découverte de hôtes)](#scanning-du-réseau-découverte-de-hôtes)
[Scanning de ports](#scanning-de-ports)
[Identification de services et ses versions](#identification-de-services-et-ses-versions)
[Détection du système d’exploitation](#détection-du-système-dexploitation)
[Vulnérabilités](#vulnérabilités)

# Introduction

Toutes les machines connectées à un LAN (ou WAN, VLAN, VPN, etc…) exécutent des services qui « écoutent » sur certains ports. Ces services sont des logiciels qui tournent dans une boucle infinie en attendant un message particulier d’un client (requête). Le logiciel agit sur la requête ; on dit donc qu’il « sert ».

Le scanning de ports est l’une des techniques les plus utilisées par les attaquants. Ça permet de découvrir les services qui tournent en attendant les clients. L’attaquant peut souvent découvrir aussi la version du logiciel associé à ce service, ce qui permet d’identifier des éventuelles vulnérabilités.

Dans la pratique, un port scan n’est plus que le fait d’envoyer un message à chaque port et d’en examiner la réponse. Plusieurs types de messages sont possibles et/ou nécessaires. Si le port est ouvert (un service tourne derrière en attendant des messages), il peut être analysé pour essayer de découvrir les vulnérabilités associées au service correspondant.

## Auteurs

Ce texte est basé sur le fichier préparé par Abraham Ruginstein Scharf dans le cadre du
cours Sécurité des Réseaux (SRX) à l'école HEIG/VD, Suisse.
Il a été travaillé et remis en forme pour passer dans un github classroom par
Linus Gasser (@ineiti) du C4DT/EPFL.
L'assistant pour le cours SRX de l'année 2023 est Axel Vallon (@AxelVallon).

## Fichiers nécessaires
Vous recevrez par email tous les fichiers nécessaires pour se connecter à l'infrastructure de ce laboratoire.

## Rendu
Ce laboratoire ne sera ni corrigé ni évalué.
Mais je vous conseille quand même de faire une mise à jour de votre répo avec les réponses.
C'est un bon exercice pour le labo-02 qui sera corrigé et noté.

# Le réseau de test

## Infrastructure virtuelle 
Durant ce laboratoire, nous allons utiliser une infrastructure virtualisée. Elle comprend un certain nombre de machines connectées en réseau avec un nombre différent de services.

Puisque le but de ce travail pratique c’est de découvrir dans la mesure du possible ce réseau, nous ne pouvons pas vous en donner plus de détails ! 

Juste un mot de précaution: vous allez aussi voir tous les autres ordinateurs des étudiants qui se connectent au réseau.
C'est voulu, afin que vous puissiez aussi faire des scans sur ceux-ci.
Par contre, il est formellement interdit de lancer quelconque attaque sur un ordinateur d'un des élèves!
Si on vous demande de s'attaquer aux machines présents dans l'infrastructure de teste, si vous arrivez à en sortir,
contactez immédiatement le prof ou l'assistant pour récolter des points bonus.
Ce n'est pas prévu - mais ça peut arriver :)

## Connexion à l’infrastructure par WireGuard

Notre infrastructure de test se trouve isolée du réseau de l’école. L’accès est fourni à travers une connexion WireGuard.

La configuration de WireGuard varie de système en système. Cependant, dans tous les cas, l’accès peut être géré par un fichier de configuration qui contient votre clé privée ainsi que la clé publique du serveur.

Il est vivement conseillé d’utiliser Kali Linux pour ce laboratoire. WireGuard est déjà préinstallé sur Kali.
Mais ça marche aussi très bien directement depuis un ordinateur hôte - en tout cas j'ai testé Windows et Mac OSX.
Vous trouvez les clients WireGuard ici: https://www.wireguard.com/install/

Vous trouverez dans l’email reçu un fichier de configuration WireGuard personnalisé pour vous (chaque fichier est unique) ainsi que queleques informations relatives à son utilisation. Le fichier contient un certificat et les réglages correctes pour vous donner accès à l’infra.

Une fois connecté à l’infrastructure, vous recevrez une adresse IP correspondante au réseau de test.

Pour vous assurer que vous êtes connecté correctement au VPN, vous devriez pouvoir pinger l’adresse 10.1.2.2.

### Configuration Kali Linux

Pour l'installation dans Kali-Linux, il faut faire la chose suivante:

```bash
sudo -i
apt update
apt install -y wireguard resolvconf
vi /etc/wireguard/wg0.conf # copier le contenu de peerxx.conf
wg-quick up wg0
```

### Réseau d’évaluation

Le réseau que vous allez scanner est le 10.1.1.0/24 - le réseaux 10.1.2.0/24 est le réseaux WireGuard avec tous les
ordinateurs des élèves. On va essayer de le scanner vite fait, mais **INTERDICTION DE FAIRE DU PENTEST SUR CES MACHINES**!

### Distribution des fichiers de configuration

Pour simplifier ce labo, je vous ai directement envoyer les fichiers de configuration.
Mais dans un environnement où on ne fait pas forcément confiance au serveur, ni à la personne qui distribue les
fichiers, ceci n'est pas une bonne pratique.

Quels sont les vectuers d'attaque pour cette distribution?
Qui est une menace?
Toutes les requètes passent par la configuration donnée. On pourrait envisager une attaque man-in-the-middle.

Comment est-ce qu'il faudrait procéder pour palier à ces attaques?
Qui devrait envoyer quelle information à qui? Et dans quel ordre?
Le client devrait contacter le distributeur. Une manière sécurisée de communication devrait être crée (email n'étant pas sûr) et le fichier devrait être transmis de cette manière.

# Scanning avec Nmap

Nmap est considéré l’un des outils de scanning de ports les plus sophistiqués et évolués. Il est développé et maintenu activement et sa documentation est riche et claire. Des centaines de sites web contiennent des explications, vidéos, exercices et tutoriels utilisant Nmap.

## Scanning du réseau (découverte de hôtes)

Le nom « Nmap » implique que le logiciel fut développé comme un outil pour cartographier des réseaux (Network map). Comme vous pouvez l’imaginer, cette fonctionnalité est aussi attirante pour les professionnels qui sécurisent les réseaux que pour ceux qui les attaquent.

Avant de pouvoir se concentrer sur les services disponibles sur un serveur en particulier et ses vulnérabilités, il est utile/nécessaire de dresser une liste d’adresses IP des machines présentes dans le réseau. Ceci est particulièrement important, si le réseau risque d’avoir des centaines (voir des milliers) de machines connectées. En effet, le scan de ports peut prendre long temps tandis que la découverte de machines « vivantes », est un processus plus rapide et simple. Il faut quand-même prendre en considération le fait que la recherche simple de hôtes ne retourne pas toujours la liste complète de machines connectées.

Nmap propose une quantité impressionnante de méthodes de découverte de hôtes. L’utilisation d’une ou autre méthode dépendra de qui fait le scanning (admin réseau, auditeur de sécurité, pirate informatique, amateur, etc.), pour quelle raison le scanning est fait et quelle infrastructure est présente entre le scanner et les cibles.

Questions

a.	Quelles options sont proposées par Nmap pour la découverte de hôtes ? Servez-vous du menu « help » de Nmap (nmap -h), du manuel complet (man nmap) et/ou de la documentation en ligne.   

HOST DISCOVERY:
  -sL: List Scan - simply list targets to scan
  -sn: Ping Scan - disable port scan
  -Pn: Treat all hosts as online -- skip host discovery
  -PS/PA/PU/PY[portlist]: TCP SYN/ACK, UDP or SCTP discovery to given ports
  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
  -PO[protocol list]: IP Protocol Ping
  -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
  --system-dns: Use OS's DNS resolver
  --traceroute: Trace hop path to each host

b.	Essayer de dresser une liste des hôtes disponibles dans le réseau en utilisant d’abord un « ping scan » (No port scan) et ensuite quelques autres des méthodes de scanning (dans certains cas, un seul type de scan pourrait rater des hôtes).

Adresses IP trouvées :

Nmap scan report for 10.1.1.2
Nmap scan report for 10.1.1.3
Nmap scan report for 10.1.1.4
Nmap scan report for 10.1.1.5
Nmap scan report for 10.1.1.10
Nmap scan report for 10.1.1.11
Nmap scan report for 10.1.1.12
Nmap scan report for 10.1.1.14
Nmap scan report for 10.1.1.20
Nmap scan report for 10.1.1.21
Nmap scan report for 10.1.1.22
Nmap scan report for 10.1.1.23

Avez-vous constaté des résultats différents en utilisant les différentes méthodes ? Pourquoi pensez-vous que ça pourrait être le cas ?

Oui, en utilisant nmap -O -sV on peut non-seulement connaitre les OS tournant sur la plupart des hôtes, mais aussi le nom et la version des services qui écoutent sur certains ports.

Quelles options de scanning sont disponibles si vous voulez être le plus discret possible ?

nmap -sS [host]

## Scanning de ports

Il y a un total de 65'535 ports TCP et le même nombre de ports UDP, ce qui rend peu pratique une analyse de tous les ports, surtout sur un nombre important de machines. 

N’oublions pas que le but du scanning de ports est la découverte de services qui tournent sur le système scanné. Les numéros de port étant typiquement associés à certains services connus, une analyse peut se porter sur les ports les plus « populaires ».

Les numéros des ports sont divisés en trois types :

-	Les ports connus : du 0 au 1023
-	Les ports enregistrés : du 1024 au 49151
-	Les ports dynamiques ou privés : du 49152 au 65535

Questions
c.	Complétez le tableau suivant :

**LIVRABLE: tableau** :

| Port  | Service             | Protocole (TCP/UDP) |
| :---: | :---:               | :---:               |
| 20/21 | FTP (File Transfer) | TCP                 |
| 22    | SSH (Secure Shell)  | TCP                 |
| 23    | Telnet              | TCP                 |
| 25    | SMTP (Simple Mail Transfer) | TCP          |
| 53    | DNS (Domain Name System) | TCP/UDP         |
| 67/68 | DHCP (Dynamic Host Configuration Protocol) | UDP |
| 69    | TFTP (Trivial File Transfer Protocol) | UDP |
| 80    | HTTP (Hypertext Transfer Protocol) | TCP     |
| 110   | POP3 (Post Office Protocol version 3) | TCP   |
| 443   | HTTPS (HTTP Secure) | TCP                 |
| 3306  | MySQL Database | TCP                      |

d.	Par défaut, si vous ne donnéz pas d’option à Nmap concernant les port, quelle est la politique appliquée par Nmap pour le scan ? Quels sont les ports qui seront donc examinés par défaut ? Servez-vous de la documentation en ligne pour trouver votre réponse.

nmap utilise les 1023 ports (well known). La liste complète: [wikipedia](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers/)


e.	Selon la documentation en ligne de Nmap, quels sont les ports TCP et UDP le plus souvent ouverts ? Quels sont les services associés à ces ports ?   

Les 5 ports les plus utilisés (TCP et UDP respectivement) sont:


Pour TCP:

| Port  | Service             |
| :---: | :---:               |
| 80 | HTTP |
| 23    | Telnet              |
| 443   | HTTPS (HTTP Secure) |
| 21    | FTP |
| 22    | SSH |

Pour UDP:

| Port  | Service             |
| :---: | :---:               |
| 631  | IPP (Internet Printing Protocol) |
| 161 | SNMP (Simple Network Management Protocol) |
| 137   | NETBIOS-NS |
| 123   | NTP |
| 138  | NETBIOS-DGM |

f.	Dans les commandes Nmap, de quelle manière peut-on cibler un numéro de port spécifique ou un intervalle de ports ? Servez-vous du menu « help » de Nmap (nmap -h), du manuel complet (man nmap) et/ou de la documentation en ligne.   

C'est avec l'extension -p qu'on peut préciser un/des port-s spécifique-s ou un intervalle.

Par exemple:
```
nmap -p 80 10.2.2.1/24
nmap -p 1-100 10.2.2.1/24
nmap -p 80,5,32,1-100 10.2.2.1/24
```


g.	Quelle est la méthode de scanning de ports par défaut utilisée par Nmap si aucune option n’est donnée par l’utilisateur ?

**LIVRABLE: texte** :


h.	Compléter le tableau suivant avec les options de Nmap qui correspondent à chaque méthode de scanning de port :

| Type de scan     | Option nmap     |
| :---:            | :---:           |
| TCP (connect)    | -sT             |
| TCP SYN          | -sS             |
| TCP NULL         | -sN             |
| TCP FIN          | -sF             |
| TCP XMAS         | -sX             |
| TCP idle (zombie)| -sI             |
| UDP              | -sU             |

i.	Lancer un scan du réseau entier utilisant les méthodes de scanning de port TCP, SYN, NULL et UDP. Y a-t-il des différences aux niveau des résultats pour les scans TCP ? Si oui, lesquelles ? Avez-vous un commentaire concernant le scan UDP ?

Exemple de résultats pour 10.1.1.5:
TCP (-sT):
```bash
Nmap scan report for 10.1.1.5
Host is up (0.024s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT     STATE SERVICE
9100/tcp open  jetdirect
```

TCP SYN(-sS):
```bash
Nmap scan report for 10.1.1.5
Host is up (0.029s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE
9100/tcp open  jetdirect
```

TCP NULL(-sN):
```bash
Nmap scan report for 10.1.1.5
Host is up (0.022s latency).
All 1000 scanned ports on 10.1.1.5 are in ignored states.
Not shown: 1000 open|filtered tcp ports (no-response)
```

UDP (-sU):
```bash
Nmap scan report for 10.1.1.5
Host is up (0.022s latency).
Not shown: 981 closed udp ports (port-unreach)
PORT      STATE         SERVICE
997/udp   open|filtered maitrd
1031/udp  open|filtered iad2
3456/udp  open|filtered IISrpc-or-vat
16402/udp open|filtered unknown
16711/udp open|filtered unknown
16948/udp open|filtered unknown
17077/udp open|filtered unknown
19283/udp open|filtered keysrvr
20249/udp open|filtered unknown
20445/udp open|filtered unknown
20518/udp open|filtered unknown
25157/udp open|filtered unknown
34892/udp open|filtered unknown
38498/udp open|filtered unknown
43370/udp open|filtered unknown
49179/udp open|filtered unknown
49202/udp open|filtered unknown
51255/udp open|filtered unknown
59193/udp open|filtered unknown
```

Nous pouvons voir que pour l'hote 101.1.5, l'utilisation de TCP NULL ne nous permet de pas de voir le port 9100 ouvert.
Par contre l'analyse UDP nou montre que beaucoup plus de ports UDP sont ouverts.

j.	Ouvrir Wireshark, capturer sur votre interface réseau et relancer un scan TCP (connect) sur une seule cible spécifique. Observer les échanges entre le scanner et la cible. Lancer maintenant un scan SYN en ciblant spécifiquement la même machine précédente. Identifier les différences entre les deux méthodes et les contraster avec les explications théoriques données en cours. Montrer avec des captures d’écran les caractéristiques qui définissent chacune des méthodes.

Capture pour TCP (connect)

**LIVRABLE: capture d'écran** :
![TCP(connect)](TCP(connect).png)

Capture pour SYN :

![TCP(SYN)](TCP(SYN).png)

k.	Quelle est l’adresse IP de la machine avec le plus grand nombre de services actifs ? 

10.1.1.1 avec 13 ports ouverts

## Identification de services et ses versions

Le fait de découvrir qu’un certain port est ouvert, fermé ou filtré n’est pas tellement utile ou intéressant sans connaître son service et son numéro de version associé. Cette information est cruciale pour identifier des éventuelles vulnérabilités et pour pouvoir tester si un exploit est réalisable ou pas.

Questions

l.	Trouver l’option de Nmap qui permet d’identifier les services (servez-vous du menu « help » de Nmap (nmap -h), du manuel complet (man nmap) et/ou de la documentation en ligne). Utiliser la commande correcte sur l’un des hôtes que vous avez identifiés avec des ports ouverts (10.1.1.10 vivement recommandé…). Montrer les résultats.   

Résultat du scan d’identification de services :

Commande: nmap -sV

```bash
Nmap scan report for 10.1.1.10
Host is up (0.022s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
53/tcp   open  domain      dnsmasq 2.86
80/tcp   open  http        Apache httpd 2.4.52 ((Ubuntu))
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
631/tcp  open  ipp         CUPS 2.4
3306/tcp open  mysql       MySQL (unauthorized)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Détection du système d’exploitation
Nmap possède une base de données contenant plus de 2600 systèmes d’exploitation différents. La détection n’aboutit pas toujours mais quand elle fonctionne, Nmap est capable d’identifier le nom du fournisseur, l’OS, la version, le type de dispositif sur lequel l’OS tourne (console de jeux, routeur, switch, dispositif générique, etc.) et même une estimation du temps depuis le dernier redémarrage de la cible.

Questions
m.	Chercher l’option de Nmap qui permet d’identifier le système d’exploitation (servez-vous du menu « help » de Nmap (nmap -h), du manuel complet (man nmap) et/ou de la documentation en ligne). Utiliser la commande correcte sur la totalité du réseau. Montrer les résultats.   

Résultat du scan d’identification du système d’exploitation :

```bash
Nmap scan report for 10.1.1.10
Host is up, received echo-reply ttl 62 (0.024s latency).
Scanned at 2023-03-06 13:31:28 CET for 573s
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE     REASON         VERSION
22/tcp   open  ssh         syn-ack ttl 62 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
53/tcp   open  domain      syn-ack ttl 62 dnsmasq 2.86
80/tcp   open  http        syn-ack ttl 62 Apache httpd 2.4.52 ((Ubuntu))
139/tcp  open  netbios-ssn syn-ack ttl 62 Samba smbd 4.6.2
445/tcp  open  netbios-ssn syn-ack ttl 62 Samba smbd 4.6.2
631/tcp  open  ipp         syn-ack ttl 62 CUPS 2.4
3306/tcp open  mysql       syn-ack ttl 62 MySQL (unauthorized)
Aggressive OS guesses: HP P2000 G3 NAS device (90%), Linux 2.6.32 - 3.13 (88%), Linux 2.6.32 (88%), Linux 2.6.32 - 3.1 (88%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (88%), Linux 3.7 (88%), Linux 5.1 (88%), Linux 5.4 (88%), Netgear RAIDiator 4.2.21 (Linux 2.6.37) (88%), Ubiquiti Pico Station WAP (AirOS 5.2.6) (88%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=3/6%OT=22%CT=1%CU=33670%PV=Y%DS=3%DC=I%G=Y%TM=6405DF5D
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=F8%GCD=1%ISR=104%TI=Z%CI=Z%II=I%TS=A)OPS(O
OS:1=M564ST11NW7%O2=M564ST11NW7%O3=M564NNT11NW7%O4=M564ST11NW7%O5=M564ST11N
OS:W7%O6=M564ST11)WIN(W1=FB28%W2=FB28%W3=FB28%W4=FB28%W5=FB28%W6=FB28)ECN(R
OS:=Y%DF=Y%T=40%W=FD5C%O=M564NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RU
OS:CK=11AA%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)
```

Avez-vous trouvé l’OS de toutes les machines ? Sinon, en utilisant l’identification de services, pourrait-on se faire une idée du système de la machine ?

La plus grande probabilité est un OS HP P2000 G3 NAS

Vous voyez une différence entre les machines mis à disposition pour le cours et les machines connectés au réseau.
Expliquez pourquoi cette différence est là.

**LIVRABLE: texte** : Je n'ai pas compris la question

## Vulnérabilités 
Servez-vous des résultats des scans d’identification de services et de l’OS pour essayer de trouver des vulnérabilités. Vous pouvez employer pour cela l’une des nombreuses bases de données de vulnérabilités disponibles sur Internet. Vous remarquerez également que Google est un outil assez puissant pour vous diriger vers les bonnes informations quand vous connaissez déjà les versions des services et des OS.

**IL EST INTERDIT DE S'ATTAQUER AUX ORDINATEURS DES AUTRES éTUDIANTS!**

Questions

n.	Essayez de trouver des services vulnérables sur la machine que vous avez scannée avant (vous pouvez aussi le faire sur d’autres machines. Elles ont toutes des vulnérabilités !). 

Résultat des recherches :

**LIVRABLE: texte** :

Challenge : L’une des vulnérabilités sur la machine 10.1.1.2 est directement exploitable avec rien d’autre que Netcat. Est-ce que vous arrivez à le faire ?

**LIVRABLE: texte** :
