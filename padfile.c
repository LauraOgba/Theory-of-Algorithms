#include <stdio.h>
#include <stdint.h>

union point{
    uint_8 e[64];
    uint_32 t[16];
    uint_64 s[8];

};

int main(int argc, char *argv[]){

union msgblock M;

uint_64 nobytes;

FILE* f;
f = fopen(argv[1], 'r');

while (!feof(f)){
    nobytes = fread(M.e, 1, 64, f);
    printf("%llu\n", nobytes);
}

fclose(f);

return 0;
}