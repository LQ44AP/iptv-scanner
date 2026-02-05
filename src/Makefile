all: iptv_scanner

iptv_scanner: iptv_fast_scan.o
	$(CC) $(LDFLAGS) iptv_fast_scan.o -o iptv_scanner -lpcap

iptv_fast_scan.o: iptv_fast_scan.c
	$(CC) $(CFLAGS) -c iptv_fast_scan.c

clean:
	rm -f *.o iptv_scanner
