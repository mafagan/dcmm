#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/un.h>
#include <assert.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <dcmm.h>

#define LEN 1024

#define CA_CERT "/home/ubuntu/Public/Test/ssl/tls/ca.crt"
#define CLIENT_CERT "/home/ubuntu/Public/Test/ssl/tls/client.crt"
#define CLIENT_KEY "/home/ubuntu/Public/Test/ssl/tls/client.key"

int main()
{
    dsocket_t sd = dcmm_socket(0);
    dcmm_addr_t addr;
    char buff[LEN];
    int n;
    int i;

    addr.port = 9734;
    strcpy(addr.ip, "127.0.0.1");

    printf("dcmm_tls_set: %d\n", dcmm_tls_set(sd, CA_CERT, NULL, CLIENT_CERT, CLIENT_KEY));
    printf("dcmm_connect: %d\n", dcmm_connect(sd, &addr, DCMM_OPT_BLOCKING, NULL));
    for (i = 0; i < 5; ++ i) {
        n = dcmm_send(sd, "yuanzhf", 7);
        printf("dcmm_send: %d\n", n);
        bzero(buff, LEN);
        n = dcmm_recv(sd, buff, LEN);
        printf("dcmm_recv: %d\n", n);
        buff[n] = '\0';
        printf("recv:%s\n", buff);
    }

    dcmm_close(sd);
    return 0;
}
