#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include<sys/types.h>
#include<arpa/inet.h>
#include<sys/epoll.h>
#include<signal.h>

/* Recommended max cache and object sizes */
#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400
#define MAXEVENTS 64
#define MAXLINE 2048


static const char *user_agent_hdr = "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:97.0) Gecko/20100101 Firefox/97.0\r\n";
static const char *httpProtocol = "HTTP/1.0\r\n";
static const char *connectClose = "Connection: close\r\n";
static const char *proxyConnectClose = "Proxy-Connection: close\r\n\r\n";

struct client_info {
	int fd;
	char desc[1024];
	int sfd;
	int state;
	char request[MAX_OBJECT_SIZE];
	char response[MAX_OBJECT_SIZE];
	int bytesReadClient;
	int bytesWroteServer;
	int bytesReadServer;
	int bytesWroteClient;
};

int efd; 

int interrupt = 0;

void sigint_handler(int sig) {
	interrupt = 1;
}


int all_headers_received(char *);
int parse_request(char *, char *, char *, char *, char *, char *);
void test_parser();
void print_bytes(unsigned char *, int);
int open_sfd(int);
void handle_new_clients(struct client_info*);
void handle_client(struct client_info*);
void readClientReq(struct client_info*);
void sendProxyReq(struct client_info*);
void readServerRes(struct client_info*);
void sendProxyRes(struct client_info*);

int main(int argc, char ** argv)
{

	struct sigaction sigact;
	sigact.sa_handler = sigint_handler;
	sigaction(SIGINT, &sigact, NULL);

	size_t n;
	struct epoll_event event;
	struct epoll_event *events;

	int i;
	//int len;

	struct client_info *listener;
	struct client_info *active_client;
	//char buf[MAXLINE]; 

	int port = atoi(argv[1]);

	if ((efd = epoll_create1(0)) < 0) {
		fprintf(stderr, "error creating epoll fd\n");
		exit(1);
	}

	//comment so it will show up

	int sfd = open_sfd(port);

	// allocate memory for a new struct client_info, and populate it with
	// info for the listening socket
	listener = malloc(sizeof(struct client_info));
	listener->fd = sfd;
	sprintf(listener->desc, "Listen file descriptor (accepts new clients)");

	// register the listening file descriptor for incoming events using
	// edge-triggered monitoring
	event.data.ptr = listener;
	event.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &event) < 0) {
		fprintf(stderr, "error adding event\n");
		exit(1);
	}

	events = calloc(MAXEVENTS, sizeof(struct epoll_event));

	while(1) {
		n = epoll_wait(efd, events, MAXEVENTS, 1);

		for (i = 0; i < n; i++) {
			// grab the data structure from the event, and cast it
			// (appropriately) to a struct client_info *.
			active_client = (struct client_info *)(events[i].data.ptr);

			if (interrupt == 1) {
				printf("interrupted\n");
				exit(1);
			}

			//printf("New event for %s\n", active_client->desc);

			if ((events[i].events & EPOLLERR) ||
					(events[i].events & EPOLLHUP) ||
					(events[i].events & EPOLLRDHUP)) {
				/* An error has occured on this fd */
				fprintf(stderr, "epoll error on %s\n", active_client->desc);
				close(active_client->fd);
				free(active_client);
				continue;
			}

			if (active_client->fd == sfd) {
				handle_new_clients(active_client);
			}
			else {
				handle_client(active_client);
			}
		}
	}
	free(events);
	free(listener);
	return 0;
}

int all_headers_received(char *request) {
	//check for end of header
	if (strstr(request, "\r\n\r\n") != NULL) {
		return 1;
	}
	return 0;
}

int parse_request(char *request, char *method,
		char *hostname, char *port, char *path, char *headers) {
	if (!all_headers_received(request)) {
		return 0;
	}

	int endOfString = strlen(request);
	int begin = 0;
	int end = 0;
	int portFound = 0;

	while (end < endOfString) {
		if (request[end] == ' ') {
			strncpy(method, request, end);
			method[end] = '\0';
			break;
		}
		end += 1;
	}
	end += 1;
	end += 7;
	begin = end;
	while (end < endOfString) {
		if (request[end] == ':' || request[end] == '/') {
			if (request[end] == ':') {
				portFound = 1;
			}
			strncpy(hostname, (request + begin), (end - begin) + 1);
			hostname[end - begin] = '\0';
			break;
		}
		end += 1;
	}
	begin = end;
	if (portFound) {
		end += 1;
		begin = end;
		while (end < endOfString) {
			if (request[end] == '/') {
				strncpy(port, request + begin, (end - begin) + 1);
				port[end - begin] = '\0';
				break;
			}
			end += 1;
		}
	}
	else {
		strncpy(port, "80", 3);
	}
	begin = end;
	while (begin < endOfString) {
		if (request[end] == ' ') {
			strncpy(path, request + begin, (end - begin) + 1);
			path[end - begin] = '\0';
			break;
		}
		end += 1;
	}
	begin = end;
	while (end < endOfString) {
		if (request[end] == '\n') {
			break;
		}
		end += 1;
	}
	end += 1;
	headers = strncpy(headers, request + end, (endOfString - end));
	headers[endOfString - end] = '\0';
	return 1;
}

int open_sfd(int port) {
	int address_family;
	int sock_type;
	struct sockaddr_in ipv4addr;

	int sfd;
	struct sockaddr *local_addr;
	socklen_t local_addr_len;

	sock_type = SOCK_STREAM;
	address_family = AF_INET;

	ipv4addr.sin_family = address_family;
	ipv4addr.sin_addr.s_addr = INADDR_ANY;
	ipv4addr.sin_port = htons(port);
	local_addr = (struct sockaddr *)&ipv4addr;
	local_addr_len = sizeof(ipv4addr);

	if ((sfd = socket(address_family, sock_type, 0)) < -1) {
		perror("Error creating socket");
		exit(EXIT_FAILURE);
	}
	int optval = 1;
	setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

	if (bind(sfd, local_addr, local_addr_len) < 0) {
		perror("Could not bind");
		exit(EXIT_FAILURE);
	}

	listen(sfd, 100);

	// set listening file descriptor non-blocking
	if (fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL, 0) | O_NONBLOCK) < 0) {
		fprintf(stderr, "error setting socket option\n");
		exit(1);
	}

	return sfd;
}

void handle_new_clients(struct client_info *active_client) {

	//printf("called handle_new_clients\n");

	struct sockaddr_storage clientaddr;
	int connfd;
	socklen_t clientlen;
	clientlen = sizeof(struct sockaddr_storage); 
	struct client_info *new_client;
	new_client = malloc(sizeof(struct client_info));
	struct epoll_event event;

	while (1) {
		connfd = accept(active_client->fd, (struct sockaddr *)&clientaddr, &clientlen);

		if (connfd < 0) {
			if (errno == EWOULDBLOCK ||
					errno == EAGAIN) {
				// no more clients ready to accept
				break;
			} else {
				perror("accept");
				exit(EXIT_FAILURE);
			}
		}

		// set client file descriptor non-blocking
		if (fcntl(connfd, F_SETFL, fcntl(connfd, F_GETFL, 0) | O_NONBLOCK) < 0) {
			fprintf(stderr, "error setting socket option\n");
			exit(1);
		}

		new_client->fd = connfd;
		new_client->state = 0;
		new_client->bytesReadClient = 0;
		new_client->bytesReadServer = 0;
		new_client->bytesWroteClient = 0;
		new_client->bytesWroteServer = 0;
		bzero(new_client->response, MAX_OBJECT_SIZE);
		bzero(new_client->request, MAX_OBJECT_SIZE);
		//sprintf(new_client->desc, "Client with file descriptor %d", connfd);

		// register the client file descriptor

		// for incoming events using
		// edge-triggered monitoring
		event.data.ptr = new_client;
		event.events = EPOLLIN | EPOLLET;
		if (epoll_ctl(efd, EPOLL_CTL_ADD, connfd, &event) < 0) {
			fprintf(stderr, "error adding event\n");
			exit(1);
		}
	}
}

void handle_client(struct client_info* active_client) {
	printf("called handle client\n");
	printf("state: %d\n", active_client->state);
    switch (active_client->state) {
	 	case 0:
	 		readClientReq(active_client);
	 		break;
	 	case 1:
	 		sendProxyReq(active_client);
	 		break;
	 	case 2:
	 		readServerRes(active_client);
			break;
	 	case 3:
	 		sendProxyRes(active_client);
	 		break;
		
	 	default:
	 		printf("Switch Err\n");
	 		break;
    }
}

void readClientReq(struct client_info* active_client) {

	//printf("reading from client\n");
	int nread = 0;
	while (!all_headers_received(active_client->request)) {
		nread = read(active_client->fd, active_client->request + active_client->bytesReadClient, 256);
		if (nread < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return;
			}
			else {
				printf("error read readClientReq %s\n", strerror(errno));
				//printf("errno %d\n", errno);
			}
			break;
		}
		else {
			active_client->bytesReadClient += nread;
			printf("nread readClientReq %d\n", nread);
		}
		
	}

	printf("reading: %s\n", active_client->request);
	
	char method[16], hostname[64], port[8], path[64], headers[1024];

	parse_request(active_client->request, method, hostname, port, path, headers);


	if (atoi(port) == 80) {
		sprintf(active_client->request,"%s %s %sHost: %s\r\n%s%s%s", method, path, httpProtocol, hostname, user_agent_hdr, connectClose, proxyConnectClose);
	}
	else {
		sprintf(active_client->request, "%s %s %sHost: %s:%s\r\n%s%s%s", method, path, httpProtocol, hostname, port, user_agent_hdr, connectClose, proxyConnectClose);
	}

	printf("request: %s\n", active_client->request);

	struct addrinfo hints;
	struct addrinfo *result;
	int sfd;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET; 
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	getaddrinfo(hostname, port, &hints, &result);

	sfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	connect(sfd, result->ai_addr, result->ai_addrlen);

	if (fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL, 0) | O_NONBLOCK) < 0) {
		fprintf(stderr, "error setting socket option\n");
		exit(1);
	}

	active_client->sfd = sfd;

	struct epoll_event event;

	event.data.ptr = active_client;
	event.events = EPOLLOUT | EPOLLET;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, active_client->sfd, &event) < 0) {
		fprintf(stderr, "error adding event readClientReq\n");
		exit(1);
	}

	if (epoll_ctl(efd, EPOLL_CTL_DEL, active_client->fd, NULL) < 0) {
		fprintf(stderr, "error deleting event readClientReq\n");
		exit(1);
	}

	active_client->state = 1;

}

void sendProxyReq(struct client_info* active_client) {
	//printf("gonna write proxy req state %d \n", active_client->state);

	int nwrote = 0;
	while (strlen(active_client->request) != active_client->bytesWroteClient) {
		nwrote = write(active_client->sfd, (active_client->request + active_client->bytesWroteClient), (strlen(active_client->request) - active_client->bytesWroteClient));
		if (nwrote < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return;
			}
			else {
				printf("error writing sendProxyReq %s\n", strerror(errno));
			}
		}
		else {
			active_client->bytesWroteClient += nwrote;
			printf("nwrote sendProxyReq %d\n", nwrote);
		}
	}

	//printf("wrote: %d\n", active_client->bytesWroteClient); 

	struct epoll_event event;
	event.data.ptr = active_client;
	event.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(efd, EPOLL_CTL_MOD, active_client->sfd, &event) < 0) {
		fprintf(stderr, "error modding event sendProxyReq\n");
		exit(1);
	}

	active_client->state = 2;
	printf("finish writing proxy state %d\n", active_client->state);
}

void readServerRes(struct client_info* active_client) {
	int nread = 1;
	printf("gonna read from server state %d\n", active_client->state);
	while (nread != 0) {
		nread = read(active_client->sfd, (active_client->response + active_client->bytesReadServer), 256);
		if (nread < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return;
			}
			else {
				printf("error read readServerRes %s\n", strerror(errno));
				if (epoll_ctl(efd, EPOLL_CTL_DEL, active_client->sfd, NULL) < 0) {
					fprintf(stderr, "error deleting event readServerRes\n");
					exit(1);
				}
				close(active_client->sfd);
				close(active_client->fd);
				return;
			}
		}
		else {
			active_client->bytesReadServer += nread;
			printf("nread readServerRes %d\n", nread);
		}
	}

	printf("response %s\n", active_client->response);

	if (epoll_ctl(efd, EPOLL_CTL_DEL, active_client->sfd, NULL) < 0) {
		fprintf(stderr, "error deleting event readServerRes\n");
		exit(1);
	}

	struct epoll_event event;
	event.data.ptr = active_client;
	event.events = EPOLLOUT | EPOLLET;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, active_client->fd, &event) < 0) {
		fprintf(stderr, "error adding event readServerRes\n");
		exit(1);
	}

	active_client->state = 3;

	if (close(active_client->sfd) < 0) {
		printf(" close sfd %s\n", strerror(errno));
	}
	else {
		printf("closed sfd %d\n", active_client->sfd);
	}

	printf("finish reading server state %d \n", active_client->state);
}

void sendProxyRes(struct client_info* active_client) {

	printf("gonna write to server\n");

	printf("active_client fd %d\n", active_client->fd);

	int nwrote = 0;
	while (active_client->bytesReadServer != active_client->bytesWroteServer) {
		nwrote = write(active_client->fd, (active_client->response + active_client->bytesWroteServer), (active_client->bytesReadServer - active_client->bytesWroteServer));
		if (nwrote < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return;
			}
			else {
				printf("error write sendProxyRes %s\n", strerror(errno));
			}
		}
		else {
			active_client->bytesWroteServer += nwrote;
			printf("nwrote sendProxyRes %d\n", nwrote);
		}
	}


	if (epoll_ctl(efd, EPOLL_CTL_DEL, active_client->fd, NULL) < 0) {
		fprintf(stderr, "error deleting event sendProxyRes\n");
		exit(1);
	}

	if (close(active_client->fd) < 0) {
		printf("close active_client fd %s\n", strerror(errno));
	}
	else {
		printf("closed fd %d\n", active_client->fd);
	}

}


void test_parser() {
	int i;
	char method[16], hostname[64], port[8], path[64], headers[1024];

       	char *reqs[] = {
		"GET http://www.example.com/index.html HTTP/1.0\r\n"
		"Host: www.example.com\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://www.example.com:8080/index.html?foo=1&bar=2 HTTP/1.0\r\n"
		"Host: www.example.com:8080\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://localhost:1234/home.html HTTP/1.0\r\n"
		"Host: localhost:1234\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://www.example.com:8080/index.html HTTP/1.0\r\n",

		NULL
	};
	
	for (i = 0; reqs[i] != NULL; i++) {
		printf("Testing %s\n", reqs[i]);
		if (parse_request(reqs[i], method, hostname, port, path, headers)) {
			printf("METHOD: %s\n", method);
			printf("HOSTNAME: %s\n", hostname);
			printf("PORT: %s\n", port);
			printf("HEADERS: %s\n", headers);
		} else {
			printf("REQUEST INCOMPLETE\n");
		}
	}
}

void print_bytes(unsigned char *bytes, int byteslen) {
	int i, j, byteslen_adjusted;

	if (byteslen % 8) {
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	} else {
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++) {
		if (!(i % 8)) {
			if (i > 0) {
				for (j = i - 8; j < i; j++) {
					if (j >= byteslen_adjusted) {
						printf("  ");
					} else if (j >= byteslen) {
						printf("  ");
					} else if (bytes[j] >= '!' && bytes[j] <= '~') {
						printf(" %c", bytes[j]);
					} else {
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted) {
				printf("\n%02X: ", i);
			}
		} else if (!(i % 4)) {
			printf(" ");
		}
		if (i >= byteslen_adjusted) {
			continue;
		} else if (i >= byteslen) {
			printf("   ");
		} else {
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}
