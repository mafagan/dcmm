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

int main() {
    struct timeval tv = {5, 0};
    char buff[LEN];
    int n;
    uint32_t i;
    dsocket_t fd;
    dcmm_addr_t addr;
    dcmm_status_t status;

    fd = dcmm_socket(0);
    if (fd == -1) {
        perror("dcmm_socket\n");
        exit(EXIT_FAILURE);
    }

    addr.port = 9000;
    strcpy(addr.ip, "127.0.0.1");

    printf("connection status: %d\n", dcmm_connect(fd, &addr, DCMM_OPT_NOWAIT, NULL));

    int t;
    for (t = 0; t < 10; ++ t) {
        for (i = 0; i < 10; ++ i) {
            snprintf(buff, LEN, "%d:%s", i + t * 10, "hello");
            dcmm_send(fd, buff, strlen(buff));
        }
        sleep(1);
    }

    dcmm_close(fd);

    return 0;
}
