#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void func(int*p) {
    int **q = &p;
    free(p);
    **q = 1;
}
int main(){
    int *p = (int*)malloc(sizeof(int)*10);
    func(p);
}
