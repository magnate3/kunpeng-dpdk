#include<stdio.h>

void main()
{
	short s=0x1234;
	char * pTest=(char*)&s;
	printf("%p %0X %0X",&s,pTest[0],pTest[1]);
}
