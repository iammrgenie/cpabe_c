#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <pbc/pbc.h>
#include <time.h>

int main() {
    printf("An attempt to write CPABE in C\n");

    FILE *file = fopen("param/a.param", "rb");  // Open file in binary mode for reading
    if (file == NULL) {
        printf("Failed to open the file.\n");
        return 1;
    }

    pairing_t pairing;
    char param[1024];     // Buffer to store the read data
    
    size_t count = fread(param, 1, 1024, file);
    if (!count) {pbc_die("Input Error");}

    pairing_init_set_buf(pairing, param, count);

    return 0;
}