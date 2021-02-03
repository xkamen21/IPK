# IPK - PROJEKT_1
## Řešení:
Projekt týkající se vytvoření HTTP serveru, který bude přijímat dva základní příkazy (GET, POST).
Programovací jazyk byl libovolný. Zvolil jsem tedy Python ve kterém jsem daný problém vyřešil pomocí Socketu. Celý program je rozdělený na dvě části.
### Spuštění
Program zpustíme v cílové složce pomocí příkazu **make run PORT=****** (hvězdičky zastupují číslo od **1024** do **65535**). Dále v druhém terminálu zadáme příkaz k zahájení dotazu. viz sekce **GET** a **POST**
### 1. část "GET"
První část programu řeší příkaz "**GET**", který je zadaný pevným stylem, například : **curl localhost:5353/resolve?name=www.fit.vutbr.cz\&type=A**
Program vrací hodnotu podle předaných parametrů. Při **type=a** známe zadanout URL adresu a vracíme její IP adresu. Při **type=ptr** naopak známe IP adresu a program na vrací URL adresu.

### 2. část "POST"
Druhá část se zabívá příkazem "**POST**", kterému je předaný soubor obsahujicí data ve tvaru: **DOTAZ:TYP**. Soubor muže vypadat například takhle:
```sh
www.fit.vutbr.cz:A
apple.com:A
147.229.14.131:PTR
seznam.cz:A
```
Poté program prozkoumá celý soubor a stejně jak u **GET** zjistí jakého typu daný dotaz je a co má vyhodnotit. Výsledek je nasledovný:
```sh
HTML/1.1 200 OK

www.fit.vutbr.cz:A=147.229.9.23
apple.com:A=17.178.96.59
147.229.14.131:PTR=dhcpz131.fit.vutbr.cz
seznam.cz:A=77.75.75.176
```
Post zadáme například: **curl --data-binary @queries.txt -X POST http://localhost:5353/dns-query**
### Navratové hodnoty
Ze zadání nebylo zřejmé jak by se měl daný program chovat a velice se o tom spekulovalo.
U příkazu **GET** to bylo jednoduché. Při spravném zadání a vyřešení dotazu program vrací **HTML/1.1 200 OK** a výsledek. Při špatném zadání typu či jména program vrací **HTML/1.1 400 Bad Request** a při správném zadání, ale daná IP nebo URL byla neplatná vrací **HTML/1.1 404 Not Found**

U příkazu **POST** program vrací při aspoň jednom validním vstupu **HTML/1.1 200 OK** a všechny výsledky. Když soubor neobsahuje jediný prázdný řádek a vše bylo zadáno správně, ale zároveň všechny URL či IP byly neplatné, program vrací **HTML/1.1 404 Not Found**. Při špatném zadání jména či typu dotazu a nebo při výskytu prázdného řádku program vrací **HTML/1.1 400 Bad Request**. 
