\
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void defuse(){
    char *f = getenv("FLAG");
    if(!f) f = "flag{local_testing_bomb}";
    puts(f);
}

int check(const char *in){
    // password is "HYPERION" but lightly obfuscated (XOR 0x13)
    char enc[] = { ']' , 'L', 'C', 'R', 'V', 'Z', 'V', ']', 0 }; // each char = real ^ 0x13
    char pass[9]; for(int i=0;i<8;i++) pass[i] = enc[i] ^ 0x13; pass[8]=0;
    return strcmp(in, pass)==0;
}

int main(){
    setvbuf(stdout, NULL, _IONBF, 0);
    char buf[64];
    puts("This program will self-destruct unless you enter the disarm code.");
    printf("Code: ");
    if(!fgets(buf, sizeof(buf), stdin)) return 0;
    buf[strcspn(buf, "\r\n")] = 0;
    if(check(buf)){ puts("Bomb disarmed."); defuse(); }
    else { puts("Boom! Wrong code."); }
    return 0;
}
