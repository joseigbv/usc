# usc (UDP Simple Scanner)
Simple dependency free UDP scan tool for UNIX/Linux and MS Windows. Very useful in pentesting when you have a pivot machine and you cannot install anything. You simply copy the binary and start scanning.

udp is simple enough to extend it with the functionalities you need. 

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

The usc scanner should run on any UNIX/Linux or Win32 box. You only need a relatively modern gcc compiler. To compile for another architecture (Solaris SPARC) you will need a cross compiler. 
There are two versions: non block or threads.

### Installing

Download a copy of the project from github: 

```
$ git clone https://github.com/joseigbv/usc.git
```

Edit 'usc.c' and change configuration (optional).

Compile.

* linux: 
```
$ gcc -Wall -O2 tsc.c -o usc -lpthread
```
* osx: 
```
$ gcc -Wall -O2 usc.c -o usc
```
* win32 (mingw): 
```
$ gcc -Wall -O2 usc.c -o usc -lwsock32
```
* solaris: 
```
$ gcc -Wall -O2 usc.c -o usc -lsocket -lnsl
```

### Usage 

The command line is very simple: 

```
$ usc {network|filename|ip} [port,from-to]
```

It scans port for any address in ips.txt and creates an index.txt in csv format:

```
...
199.88.100.225;80;401;RomPager/4.07 UPnP/1.0
199.88.100.217;80;301;Apache/2.2.9 (Unix) mod_ssl/2.2.9 OpenSSL/0.9.7e mod_wsgi/2.4 Python/2.6.2
199.88.0.85;80;200;thttpd/2.20c 21nov01
...
```

#### Analysis:

Example: searching for dns servers

```
$ usc ips-all.txt 53 | tee ips-all-open-dns.txt
$ cut -d: -f1 ips-all-open-dns.txt > ips-all-open-dns-ips.txt
$ xargs -I% sh -c 'echo -n %";"; geoiplookup %' < ips-all-open-dns-ips.txt | sed -n 's/GeoIP Country Edition: //p' > ips-all-open-dns-ips-country.txt
$ awk -F ';' '{ x[$2]++ } END { for(k in x) print x[k], k; }' < ips-all-open-dns-ips-country.txt | sort -nr | tee ips-all-open-dns-ips-country-count.txt
...

```

Example: searching for snmp servers

```
$ usc ips-all.txt 161 | tee ips-all-open-snmp.txt
$ cut -d: -f1 ips-all-open-snmp.txt > ips-all-open-snmp-ips.txt
$ xargs -I% sh -c 'echo -n %";"; geoiplookup %' < ips-all-open-snmp-ips.txt | sed -n 's/GeoIP Country Edition: //p' > ips-all-open-snmp-ips-country.txt
$ awk -F ';' '{ x[$2]++ } END { for(k in x) print x[k], k; }' < ips-all-open-snmp-ips-country.txt | sort -nr | tee ips-all-open-snmp-ips-country-count.txt
...
```

Example: searching for ntp

```
$ usc ips-all.txt 123 | tee ips-all-open-ntp.txt
$ sed -e 's/:.*$//' ips-all-open-ntp.txt > tee ips-all-open-ntp-ips.txt
$ xargs -I% sh -c 'echo -n %";"; geoiplookup %' < ips-all-open-ntp-ips.txt | sed -n 's/GeoIP Country Edition: //p' > ips-all-open-ntp-ips-country.txt
awk -F ';' '{ x[$2]++ } END { for(k in x) print x[k], k; }' < ips-all-open-ntp-ips-country.txt | sort -nr | tee ips-all-open-ntp-ips-country-count.txt
...
```

## Authors

* **José Ignacio Bravo** - *Initial work* - nacho.bravo@gmail.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

