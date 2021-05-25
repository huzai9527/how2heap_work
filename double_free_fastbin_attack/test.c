#include "stdlib.h"
#include "stdio.h"
typedef struct{
	int a;
	int b;
}node;
int main(){
	node *list = malloc(sizeof(node)*100);
	for(int i=0;i<100;i++){
		list[i].a=1;list[i].b=2;
	}
	node* a = list[0];
	printf("*(list[0])==%ld\n",a);
	return 0;
}
