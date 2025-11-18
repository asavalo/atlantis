#include <unistd.h>
#include <memory.h>
#include <stdio.h>

int main(int argc, char **argv) {
    char buf[0x100];

    read(0, buf, 0x100);

    if(memcmp(buf, "PASSWORD!!!!", 12) == 0) {
        puts("EQ");
    }
    else {
        puts("NEQ");
    }

    if(memcmp(buf, "PASSWORD!!!!", 12) < 0) {
        puts("LT");
    }
    else {
        puts("GE");
    }

    if(memcmp(buf, "PASSWORD!!!!", 12) > 0) {
        puts("GT");
    }
    else {
        puts("LE");
    }

    return 0;
}
