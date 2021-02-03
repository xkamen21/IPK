CC=gcc
CFLAGS=-Wall -Wextra -pedantic

ipk-sniffer: ipk-sniffer.o
	$(CC) $(CFLAGS) -o ipk-sniffer ipk-sniffer.c -lpcap

ipk-sniffer.o:
	$(CC) $(CFLAGS) -c ipk-sniffer.c

clean:
	rm *.o ipk-sniffer
