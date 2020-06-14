/***************************************************************
* simple udp port scan (threads)
*
* linux: gcc -Wall -O2 udp_scan.c -o udp_scan -lpthread
* osx: gcc -Wall -O2 udp_scan.c -o udp_scan
* win32: gcc -Wall -O2 udp_scan.c -o udp_scan -lwsock32
* solaris: gcc -Wall -O2 udp_scan.c -o udp_scan -lsocket -lnsl
* 
****************************************************************/

#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#else 
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>


/*************************
 * parametrizacion
 *************************/

// configuracion
#define MAX_THREADS 1000 	// concurrencia (ej. 25 threads)
#define INTERVAL 0 		// ms entre peticiones (ej. 10 ms)
#define TIMEOUT 2000 		// timeout en r/w (ej. 6000 ms)
#define SZ_SBUF	1024		// tamanio de buffer de lectura
#define SZ_HOST 24		// longitud de hostname maxima
#ifdef WIN32
#define SZ_BANNER 40		// long banner, mejor 40 para win32
#else
#define SZ_BANNER 80 		// long. banner
#endif
#define WH 16			// ancho hex

// puertos por defecto (pendiente definir)
uint16_t DEFAULT_PORTS[] = 
{ 
	53, 69, 123, 161 
};



/*******************
 * peticiones udp 
********************/

// snmpget -v1 -c public [ip] 1.3.6.1.2.1.1.1.0
const unsigned char SNMP[] =
{
	0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 
	0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x1c, 0x02, 
	0x04, 0x52, 0x64, 0x4c, 0x04, 0x02, 0x01, 0x00, 
	0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 
	0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 
	0x00, 0x05, 0x00
};

// nslookup www.google.com [ip]
const unsigned char DNS[] = 
{ 
	0x4f, 0x56, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 
	0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 
	0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01 
}; 

// ntpdate -q [ip]
const unsigned char NTP[] = 
{ 
	0xe3, 0x00, 0x03, 0xfa, 0x00, 0x01, 0x00, 0x00, 
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0xd6, 0xad, 0x0e, 0x94, 0x49, 0x34, 0xfb, 0x63 
};



/***************************
* tipos y variables globales
****************************/

#ifdef WIN32
typedef uint32_t socklen_t;
#endif 

// tipo scan line host:port
typedef struct 
{
	char host[SZ_HOST];
	struct in_addr addr;
	uint16_t port;

} t_sl;

// lista host:port 
t_sl *sl;
size_t sz_sl;

/*************************
 * threads
 *************************/

#define ARGS(x)	(*(t_args *)args).x
#ifdef WIN32
#define LOCK(x)	WaitForSingleObject(lck_##x, INFINITE)
#define UNLOCK(x) ReleaseMutex(lck_##x)
#else
#define LOCK(x) pthread_mutex_lock(&lck_##x)
#define UNLOCK(x) pthread_mutex_unlock(&lck_##x)
#endif

// bloqueos 
#if WIN32
HANDLE lck_print;
HANDLE lck_read;
HANDLE lck_path;
#else
pthread_mutex_t lck_print;
pthread_mutex_t lck_read;
pthread_mutex_t lck_path;
#endif

// argumentos thread
typedef struct 
{ 
	uint16_t thread_id; 

} t_args;


/*************************
 * funciones aux
 *************************/

// mensaje de error y salimos
void xabort(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}


// copia con final nulo
char *xstrncpy(char *s1, const char *s2, size_t sz)
{
	char *r = NULL;

	if (sz) 
	{
		r = strncpy(s1, s2, sz - 1);
		s1[sz - 1] = 0;
	}

	return r;
}


// asignacion de memoria, control errores
void *xmalloc(size_t sz)
{
	void *p;

	if ((p = malloc(sz)) == NULL)
		xabort("malloc error");

	return p;
}


// devuelve "ahora" en milisegundos 
double crono()
{
	struct timeval tim;

	gettimeofday(&tim, NULL);

	return ((tim.tv_sec * 1000000) + 
		tim.tv_usec) / 1000;
}


// quita caracteres no impr
char *do_printable(char *s, size_t sz, const unsigned char *sbuf, 
		size_t sz_sbuf)
{
	size_t i, max; 

	// tamanio buffer mas pequenio, reserv para fin nulo
	max = sz < sz_sbuf ? sz : sz_sbuf; 

	// copiamos caracter si imprimible
	for (i = 0; i < max; i++, sbuf++) 
		s[i] = (*sbuf < 32 || *sbuf > 126 ? '.' : *sbuf);

	// siempre termina en 0
	s[sz - 1] = 0;

	return s;
}


// mostramos paquete en hexadecimal
void print_hex(const unsigned char *sbuf, size_t sz)
{
	size_t i; 
	char s[WH + 1];

	// init string
	s[0] = s[WH] = 0;
	
	// imprime cada caracter en hex
	for (i = 0; i < sz; i++)
	{
		if (i % WH == 0) printf("\t%s\n> ", s);
		printf("%.2x ", 0x000000ff & sbuf[i]);
		s[i % WH] = sbuf[i] < 32 || sbuf[i] > 126 ? 
			'.' : sbuf[i];
	}

	// finalizamos salida
	if (i %= WH) 
		for (s[i] = 0; i < WH; i++) 
			printf("   ");

	printf("\t%s\n\n", s);
}


// intento establecimiento de conexion 
int udp_open()
{
	int sock;
	long arg;

	// creamos socket
	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) 
		xabort("socket error");

#ifdef WIN32
	// sin bloqueo
	arg = 1; ioctlsocket(sock, FIONBIO, &arg);
#else
	// sin bloqueo
	arg = fcntl(sock, F_GETFL, NULL); 
	arg |= O_NONBLOCK; 
	fcntl(sock, F_SETFL, arg); 
#endif 

	return sock;
}


// desconexion 
int udp_close(int sock) 
{ 
#ifdef WIN32
	return closesocket(sock);
#else
	return close(sock); 
#endif
}


// respuesta
size_t udp_recv(int sock, struct in_addr addr, uint16_t port, 
		unsigned char *sbuf, size_t sz_sbuf)
{
	size_t sz = 0;
	struct sockaddr_in sa; 
	socklen_t len = sizeof(sa);
	struct timeval tv;
	fd_set set;

	// estructura server_addr
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr = addr;
	memset(&(sa.sin_zero), 0, 8);
	
	FD_ZERO(&set);
	FD_SET(sock, &set);

	tv.tv_sec = (TIMEOUT / 1000);
	tv.tv_usec = (TIMEOUT % 1000) * 1000;

	// leemos de socket si hay datos
	if (select(sock + 1, &set, NULL, NULL, &tv) > 0)
		sz = recvfrom(sock, sbuf, sz_sbuf, 0, 
			(struct sockaddr*)&sa, &len);

	return sz;
}


// peticion
size_t udp_send(int sock, struct in_addr addr, uint16_t port, 
		const unsigned char *sbuf, int sbuf_len)
{
	size_t sz = 0; 
	struct sockaddr_in sa; 
	socklen_t len = sizeof(sa);

	// estructura server_addr
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr = addr;
	memset(&(sa.sin_zero), 0, 8);

	// enviamos datos
	if ((sz = sendto(sock, sbuf, sbuf_len, 0, 	
		(struct sockaddr *)&sa, len)) < sbuf_len)
			xabort("sendto error");

	return sz;
}


// leemos hostnames de fichero de texto
size_t read_hosts(const char *fname, char **hosts[], char **sbuf)
{
	size_t sz = 0;
	char *p, *s;
	struct stat st;
	FILE *F;

	// existe el fichero ?
	if ((stat(fname, &st) != -1) && (F = fopen(fname, "r")))
	{
		// tamanio fichero?
		if (st.st_size) 
		{
			// reservamos memoria
			*sbuf = p = (char *)xmalloc(st.st_size);

			// leemos contenido
			fread(*sbuf, 1, st.st_size, F);

			// contamos el numero de hosts
			while (*p) if (*p++ == '\n') sz++; 
			if (sz) sz++;

			// reservamos memoria
			*hosts = (char **)xmalloc(sz * sizeof(char *));

			// contamos lineas y saltamos comments o vacios
			for (p = *sbuf, sz = 0; (s = strtok(p, "\n")); p = NULL)
				if (*s && *s != '#') (*hosts)[sz++] = s;
		}

		// cerramos fichero
		fclose(F);
	}
	
	return sz;
}


// calculamos ips a partir de red (formato cidr)
size_t calc_ips(const char *cidr, char **hosts[], char **txt)
{
	char s[5], *p;
	size_t cnt;
	unsigned int net, o[4];
	unsigned int m, i = 0, j = 0;

	while (*cidr)
	{
		switch (*cidr)
		{
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':

				// numero 
				if (j > 3) return 0;
				s[j++] = *cidr;

				break;

			case '.':
			case '/':
			
				// procesamos octeto
				if (i > 3 || j > 3) return 0;
				j = s[j] = 0;
				if ((o[i++] = atoi(s)) > 255) return 0;

				break;

			default: return 0;
		}

		cidr++;
	}

	// calculamos mask
	j = s[j] = 0; 
	if ((m = atoi(s)) > 32) return 0;

	// calcula ip numerica a partir de octetos
	cnt = 1 << (32 - m); 
	net = (0xffffffff << (32 - m)) & 
		(o[0] << 24 | o[1] << 16 | o[2] << 8 | o[3]);

	// reservamos memoria para 
	*txt = p = (char *)xmalloc(cnt * 16);
	*hosts = (char **)xmalloc(cnt * sizeof(char *));

	// generamos todas las posibles IPs
	for (i = 0; i < cnt; i++)
	{
		(*hosts)[i] = p;
		p += sprintf(p, "%d.%d.%d.%d", 
			((net | i) & 0xff000000) >> 24, 
			((net | i) & 0x00ff0000) >> 16, 
			((net | i) & 0x0000ff00) >> 8, 
			((net | i) & 0x000000ff)) + 1;
	}

	return cnt;
}


// devuelve lista de puertos 
size_t get_ports(char *str, uint16_t **ports)
{
	char *p, *tok, *idx;
	unsigned int from, to, i;
	size_t sz = 0;

	// reservamos memoria
	*ports = (uint16_t *)xmalloc(65536 * sizeof(uint16_t));

	// parseamos string, separada por comas
	for (tok = str; (p = strtok(tok, ",")); tok = NULL)
	{
		// puerto origen valido ?
		if ((from = atoi(p))  && from < 65536) 
		{
			// hay hasta ?
			if ((idx = strchr(p, '-')))
			{
				// hasta valido ?
				if ((to = atoi(++idx)) > from && to < 65536)  
					for (i = from; i <= to; i++) 
						(*ports)[sz++] = i;
			}
			else (*ports)[sz++] = from;
		}
	}

	return sz;	
}


// peticiones tcp
#ifdef WIN32
static DWORD WINAPI run(void* args)
#else
void *run(void *args)
#endif
{
	int s, p = 0, pa = 0; 
	uint16_t th_id;
	unsigned int i;
	size_t sz;
	unsigned char sbuf[SZ_SBUF];
	double start, stop;
	char banner[SZ_BANNER];
	char *status[] = { "open", "close" };

	// argumentos (in)
	th_id = ARGS(thread_id);

	// porcentaje
	if (!th_id) fprintf(stderr, "[compl. 0%%]\n");

	// fuzz de parametros
	for (i = th_id; i < sz_sl; i += MAX_THREADS)
	{
		// iniciamos cronometro
		start = crono();

		// inicializamos cadenas
		memset(sbuf, 0, SZ_SBUF);
		memset(banner, 0, SZ_BANNER);

		// conectamos
		if ((s = udp_open()))
		{
			switch (sl[i].port)
			{
				// DNS 
				case 53:
		
					// enviamos peticion dns y esperamos respuesta
					udp_send(s, sl[i].addr, sl[i].port, DNS, sizeof(DNS));
					sz = udp_recv(s, sl[i].addr, sl[i].port, sbuf, SZ_SBUF);

					break;

				// NTP
				case 123:

					// enviamos peticion ntp y esperamos respuesta
					udp_send(s, sl[i].addr, sl[i].port, NTP, sizeof(NTP));
					sz = udp_recv(s, sl[i].addr, sl[i].port, sbuf, SZ_SBUF);

					break;

				// SNMP
				case 161:

					// enviamos peticion snmp y esperamos respuesta
					udp_send(s, sl[i].addr, sl[i].port, SNMP, sizeof(SNMP));
					sz = udp_recv(s, sl[i].addr, sl[i].port, sbuf, SZ_SBUF);
					
					break;

				// OTROS
				default:

					// enviamos peticion generica y esperamos respuesta
					udp_send(s, sl[i].addr, sl[i].port, (unsigned char *) ".\n", 1);
					sz = udp_recv(s, sl[i].addr, sl[i].port, sbuf, SZ_SBUF);
			}

			// cerramos socket
			udp_close(s);

			// paramos cronometro
			stop = crono();

			// ha habido respuesta ?
			if (sz) 
			{
				// imprimimos resultado
				LOCK(print);  // --
				do_printable(banner, SZ_BANNER, sbuf, sz), 
				printf("%s:%d\t%s\t%.0f ms\t%s\n", sl[i].host, sl[i].port, 
					status[sz == 0], stop - start, banner);
				print_hex(sbuf, sz); 
				UNLOCK(print); // --
			}
		}

		// porcentaje 
		if (!th_id && (p = (i * 100 / sz_sl)) > pa)
		{
			fprintf(stderr, "[compl. %d%%]\n", p);
			pa = p;
		}

		// esperamos
		usleep(INTERVAL);
	}

	// porcentaje
	if (!th_id) fprintf(stderr, "[compl. 100%%]\n");

	return 0;
}


// funcion principal
int main(int argc, char **argv)
{
	t_args args[MAX_THREADS];
	struct hostent *host;
	char *sbuf, **hosts;
	unsigned int i, j, k;
	size_t sz_hosts, sz_ports;
	uint16_t th, *ports;
#ifdef WIN32
	WSADATA wsaData;
	HANDLE threads[MAX_THREADS];
	DWORD threads_id[MAX_THREADS];
	
	// init winsock
	if (WSAStartup(MAKEWORD(1, 1), &wsaData)) 
		xabort("WSAStartup error");
	
	// init mutexs
	lck_print = CreateMutex(NULL, FALSE, NULL);
	lck_read = CreateMutex(NULL, FALSE, NULL);
#else 
	pthread_t threads[MAX_THREADS];
#endif

	// desactivamos buffer salida
	setbuf(stdout, NULL);

	// usage
	if (argc < 2)
	{
		printf("usage: %s {network|filename|ip} [port,from-to]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	// --------------------
	// primer parametro ...
	// --------------------

	// hostnames en fichero ?
	if (!access(argv[1], F_OK))
		sz_hosts = read_hosts(argv[1], &hosts, &sbuf);

	// network ?
	else if (strchr(argv[1], '/')) 
		sz_hosts = calc_ips(argv[1], &hosts, &sbuf);

	// ip unica ?
	else
	{	
		sbuf = (char *)xmalloc(SZ_HOST);
		hosts = (char **)xmalloc(sizeof(char *));
		xstrncpy(sbuf, argv[1], SZ_HOST);
		hosts[0] = sbuf; sz_hosts = 1;
	}

	// especificado puertos ?
	if (argc > 2)
		sz_ports = get_ports(argv[2], &ports);

	else 
	{
		ports = DEFAULT_PORTS;
		sz_ports = sizeof(DEFAULT_PORTS) / 	
			sizeof(uint16_t);
	}

	// tamanio tabla scan ?
	sz_sl = sz_hosts * sz_ports;

	// reservamos memoria tabla scan 
	sl = (t_sl *)xmalloc(sz_sl * sizeof(t_sl));

	// construimos tabla scan
	for (j = k = 0; j < sz_hosts; j++)
	{
		// resolucion host
		if ((host = gethostbyname(hosts[j])) == 0)
			fprintf(stderr, "host no valido: %s\n", hosts[j]);

		else
			// matriz ip x puertos 
			for (i = 0; i < sz_ports; i++, k++)
			{
				xstrncpy(sl[k].host, hosts[j], SZ_HOST);
				sl[k].addr = *(struct in_addr *)host->h_addr;
				sl[k].port = ports[i]; 
			}
	}

	// lanzamos todas las tareas
	for (th = 0; th < MAX_THREADS; th++)
	{
		// identificador tarea
		args[th].thread_id = th;
#ifdef WIN32
		// ejecuta thread
		if (!(threads[th] = CreateThread(NULL, 0, run, 
			(void*)&args[th], 0, &threads_id[th])))
				xabort("CreateThread error");
#else 
		// ejecuta thread
		if (pthread_create(&threads[th], NULL, run, &args[th]))
			xabort("pthread_create error");
#endif
	}

	// espera a que terminen todas las tareas
	for (th = 0; th < MAX_THREADS; th++)
	{
#ifdef WIN32
		if (WaitForSingleObject(threads[th], INFINITE))	
			xabort("WaitForSingleObject error");

		CloseHandle(threads[th]);
#else
		if (pthread_join(threads[th], NULL))
			xabort("pthread_join error");
#endif
	}

	// borramos buffers
	free(hosts); free(sbuf);
	if (ports != DEFAULT_PORTS) free(ports);
	free(sl);

#ifdef WIN32
	// cerramos mutexs
	CloseHandle(lck_print);
	CloseHandle(lck_read);

	// cerramos winsock
	WSACleanup();		
#endif 

	return 0;
}
