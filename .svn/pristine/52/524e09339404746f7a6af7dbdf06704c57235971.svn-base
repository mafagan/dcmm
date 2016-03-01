#include <stdio.h>
#include <dcmm.h>

int main(int argc, char **argv)
{
    const char *url = argv[1];
    static char buf[500000];
    dcmm_http_https_get(url, buf, sizeof(buf));    
    
    char *status_code = buf;
    int *ser_repcode = (int *)(buf + 1);
    int *body_len = (int*)(buf + 5);
    
    printf("body: %s\n", buf+9);
    printf("status_code: %d\n", (int)*status_code);
    printf("response_code: %d\n", (int)*ser_repcode);
    printf("body_len: %d\n", *body_len);

    return 0;
}
