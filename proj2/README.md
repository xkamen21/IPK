## packet sniffer, ipk-sniffer.c
##### **Jméno a příjmení:** Daniel Kamenický
##### **Login:** xkamen21
---
### packet sniffer
Program pomocí kterého je možné zachytávat a zaznamenávat komunikaci v počítačové síti. Zachycuje jednotlivé pakety a vypisuje jejich data.

### Spuštění ipk-sniffer.c
Nejdříve přeložíme zdrojový kód (pokud již nebyl přeložen). Použijeme připravený Makefile v daném adresáři.

```ssh
make
```

Zde je uveden příklad spuštění:

```ssh
sudo ./ipk-sniffer -i eth0 --tcp -n 10
```

Pro zjištění informací k parametrům spusťte pouze s jediným parametrem --help

```ssh
./ipk-sniffer --help
```

### Omezení
Packet sniffer lze používat pouze pro adresy typu IPv4.
Program nepodporuje typ hlavičky linkové vrstvy poskytované zařízením.

### Rozšíření
Parametr --help. Vypíše všechny parametry, jejich funkci a také syntax zápisu.

### Seznam odevzdaných souborů
- ipk-sniffer.c
- readme.md
- manual.pdf
- Makefile
