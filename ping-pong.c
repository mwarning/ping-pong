#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <unistd.h> // close()
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>


// IPv6 address length including port, e.g. [::1]:12345
#define FULL_ADDSTRLEN (INET6_ADDRSTRLEN + 8)

static const char *send_message = "ping";
static const char *reply_message = "pong";

static bool is_running = true;

// Set a socket non-blocking
static int net_set_nonblocking(int fd)
{
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

static socklen_t addr_len(const struct sockaddr *address)
{
    switch (address->sa_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    default:
        return 0;
    }
}

const char *str_addr(const struct sockaddr *addr)
{
    static char addrbuf[FULL_ADDSTRLEN];
    char buf[INET6_ADDRSTRLEN];
    const char *fmt;
    int port;

    switch (addr->sa_family) {
    case AF_INET6:
        port = ((struct sockaddr_in6 *)addr)->sin6_port;
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr, buf, sizeof(buf));
        fmt = "[%s]:%d";
        break;
    case AF_INET:
        port = ((struct sockaddr_in *)addr)->sin_port;
        inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr, buf, sizeof(buf));
        fmt = "%s:%d";
        break;
    default:
        return "<invalid>";
    }

    sprintf(addrbuf, fmt, buf, ntohs(port));

    return addrbuf;
}

static bool parse_port(int *port_ret, const char *port_str)
{
    char *endptr = NULL;
    const char *end = port_str + strlen(port_str);
    ssize_t port = strtoul(port_str, &endptr, 10);
    if (endptr != port_str && endptr == end && port > 0 && port <= 65536) {
        *port_ret = port;
        return true;
    } else {
        return false;
    }
}

static bool parse_address(struct sockaddr *sockaddr_ret, const char *address_str, int port)
{
    struct sockaddr_in *sockaddr4 = (struct sockaddr_in *) sockaddr_ret;
    struct sockaddr_in6 *sockaddr6 = (struct sockaddr_in6 *) sockaddr_ret;

    if (1 == inet_pton(AF_INET, address_str, &sockaddr4->sin_addr)) {
        sockaddr4->sin_family = AF_INET;
        sockaddr4->sin_port = htons(port);
        return true;
    }

    if (1 == inet_pton(AF_INET6, address_str, &sockaddr6->sin6_addr)) {
        sockaddr6->sin6_family = AF_INET6;
        sockaddr6->sin6_port = htons(port);
        sockaddr6->sin6_flowinfo = 0;
        sockaddr6->sin6_scope_id = 0;
        return true;
    }

    return false;
}

static const char *af_to_str(int af)
{
    switch (af) {
        case AF_INET: return "IPv4";
        case AF_INET6: return "IPv6";
        default: return "<invalid>";
    }
}

static const char *protocol_to_str(int protocol)
{
    switch (protocol) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        default: return "<invalid>";
    }
}

static void send_packet(const struct sockaddr *address, int sock)
{
    int message_length = strlen(send_message);

    int nbytes_send = sendto(sock, send_message, message_length, 0, address, addr_len(address));

    if (nbytes_send != message_length) {
        fprintf(stderr, "failed to send to %s: %s\n", str_addr(address), strerror(errno));
    } else {
        fprintf(stdout, "send to %s: %.*s\n", str_addr(address), message_length, send_message);
    }
}

static void read_packet(int rc, int sock)
{
    struct sockaddr_storage _fromAddress;
    struct sockaddr *fromAddress = (struct sockaddr *) &_fromAddress;
    uint8_t receive_buf[32];

    if (rc == 0) {
        return;
    }

    // receive request
    socklen_t addrlen = sizeof(_fromAddress);
    ssize_t nbytes_received = recvfrom(sock, receive_buf, sizeof(receive_buf), 0, fromAddress, &addrlen);
    if (nbytes_received < 0) {
        return;
    }

    printf("received from %s: %.*s\n", str_addr(fromAddress), (int) nbytes_received, receive_buf);

    // send reply
    size_t message_length = strlen(reply_message);
    int nbytes_send = sendto(sock, reply_message, message_length, 0, fromAddress, addr_len(fromAddress));

    if (nbytes_send != message_length) {
        fprintf(stderr, "failed to send reply to %s: %s\n", str_addr(fromAddress), strerror(errno));
    } else {
        printf("send to %s: %.*s\n", str_addr(fromAddress), (int) message_length, reply_message);
    }
}

static void shutdown_handler(int signo)
{
    // hard exit on second stop request
    if (!is_running) {
        exit(1);
    }

    is_running = false;
}

static void unix_signals(void)
{
    struct sigaction sig_stop;
    struct sigaction sig_term;

    // STRG+C aka SIGINT => stop the program
    sig_stop.sa_handler = shutdown_handler;
    sig_stop.sa_flags = 0;
    if ((sigemptyset(&sig_stop.sa_mask) == -1) || (sigaction(SIGINT, &sig_stop, NULL) != 0)) {
        fprintf(stderr, "failed to set SIGINT handler: %s\n", strerror(errno));
        exit(1);
    }

    // SIGTERM => stop the program gracefully
    sig_term.sa_handler = shutdown_handler;
    sig_term.sa_flags = 0;
    if ((sigemptyset(&sig_term.sa_mask) == -1) || (sigaction(SIGTERM, &sig_term, NULL) != 0)) {
        fprintf(stderr, "failed to set SIGTERM handler: %s\n", strerror(errno));
        exit(1);
    }

    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
}

static const char *usage_str =
    "Usage: %s <listen|send> <tcp|udp> <address> [<port>]\n"
    "  Example:\n"
    "    On device A (IP address 192.168.1.2):\n"
    "      %s listen udp 0.0.0.0\n"
    "    On Device B:\n"
    "      %s send udp 192.168.1.2\n"
    "\n"; 

int main(int argc, char **argv)
{
    if (argc != 5 && argc != 4) {
        printf(usage_str, argv[0], argv[0], argv[0]);
        return EXIT_FAILURE;
    }

    const char *listen_str = argv[1];
    const char *protocol_str = argv[2];
    const char *address_str = argv[3];
    const char *port_str = "1234";

    if (argc == 5) {
        port_str = argv[4];
    }

    unix_signals();

    int protocol = IPPROTO_TCP;
    if (0 == strcmp(protocol_str, "tcp")) {
        protocol = IPPROTO_TCP;
    } else if (0 == strcmp(protocol_str, "udp")) {
        protocol = IPPROTO_UDP;
    } else {
        fprintf(stderr, "tcp or udp expected: %s\n", protocol_str);
        return EXIT_FAILURE;
    }

    bool do_listen = false;
    if (0 == strcmp(listen_str, "listen")) {
        do_listen = true;
    } else if (0 == strcmp(listen_str, "send")) {
        do_listen = false;
    } else {
        fprintf(stderr, "listen or send expected: %s\n", listen_str);
        return EXIT_FAILURE;
    }

    // this program is work in progress
    if (protocol == IPPROTO_TCP) {
        fprintf(stderr, "TCP/IP not supported yet.\n");
        return EXIT_FAILURE;
    }

    const int opt_on = 1;
    int sock = -1;
    int port = -1;

    struct sockaddr_storage _address = {0};
    struct sockaddr *address = (struct sockaddr *) &_address;

    if (!parse_port(&port, port_str)) {
        fprintf(stderr, "Failed to parse port: %s\n", port_str);
        return EXIT_FAILURE;
    }

    if (!parse_address(address, address_str, port)) {
        fprintf(stderr, "Failed to parse address: %s\n", address_str);
        return EXIT_FAILURE;
    }

    const int af = address->sa_family;

    printf("%s over %s via %s\n", protocol_to_str(protocol), af_to_str(af), str_addr(address));

    if ((sock = socket(af, (protocol == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM, protocol)) < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (net_set_nonblocking(sock) < 0) {
        fprintf(stderr, "Failed to make socket nonblocking: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_on, sizeof(opt_on)) < 0) {
        fprintf(stderr, "Unable to set SO_REUSEADDR: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (af == AF_INET6) {
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt_on, sizeof(opt_on)) < 0) {
            fprintf(stderr, "Failed to set IPV6_V6ONLY: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
    }

    if (do_listen) {
        socklen_t addrlen = addr_len(address);
        if (bind(sock, address, addrlen) < 0) {
            fprintf(stderr, "Failed to bind socket to %s: %s\n",
                str_addr(address), strerror(errno)
            );
            return EXIT_FAILURE;
        }

        if (protocol == IPPROTO_TCP) {
            if (listen(sock, 5) < 0) {
                fprintf(stderr, "Failed to listen on %s (%s)\n",
                    str_addr(address), strerror(errno)
                );

                return EXIT_FAILURE;
            }
        }
    }

    time_t start = time(NULL);

    struct pollfd fds[1];
    fds[0].fd = sock;
    fds[0].events = POLLIN;

    while (is_running) {
        int rc = poll(fds, 1, 1000);

        if (rc < 0) {
            fprintf(stderr, "poll() %s", strerror(errno));
            break;
        }

        if (do_listen) {
            int revents = fds[0].revents;
            if (revents) {
                // execute if a packet is received
                read_packet(rc, fds[0].fd);
            }
        } else {
            time_t now = time(NULL);
            if (start != now) {
                // execute every second
                send_packet(address, fds[0].fd);
                start = now;
            }
        }
    }

    printf("\nshutdown...\n");

    return EXIT_SUCCESS;
}
