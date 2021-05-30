/*************************************************************************
	> File Name: einherjar.c
	> Author: 
	> Mail: 
	> Created Time: Wed 26 May 2021 07:42:30 AM CST
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void){
    char* s0 = malloc(0x200);
    char* s1 = malloc(0x18);
    char* s2 = malloc(0xf0);
    char* s3 = malloc(0x20); 
    printf("step 1: leak address where you want to edit.\n");
    printf("usually,the address contains gloable ptr,we can use this ptr to edit got table.\n");
    printf("Address of s0 :%p,where we can write fake chunk.\n", s0);
    printf("Edit fake chunk in s0\n");
    read(0, s0, 0x200);
    printf("Triger off by one in s1\n");
    read(0, s1, 0x19);
    printf("Now triger house of einherjar\n");
    free(s2);
    printf("After einherjar,we need to modify unstored bin's chunk head.\n");
    write(1,s0,0x200);

    printf("Now modify the fake chunk head.\n");
    read(0,s0,0x200);

    printf("Malloc chunk will at fake chunk,\n");
    char* d0 = malloc(0x68);
    printf("Now, we can edit fake chunk.\n");
    read(0,d0,0x70);
    read(0,d0,0x70);
    return 0;

}
