iptv_scanner: iptv_scanner.o
	$(CC) $(LDFLAGS) iptv_scanner.o -o iptv_scanner -lpcap

iptv_scanner.o: iptv_scanner.c
	$(CC) $(CFLAGS) -c iptv_scanner.c

clean:
	rm -f *.o iptv_scanner
