#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include <thread_pool.h>

#ifndef DEBUG
#define DEBUG
#endif

int main() {
    thread_pool_init();
    thread_pool_destroy();
    return 0;
}
