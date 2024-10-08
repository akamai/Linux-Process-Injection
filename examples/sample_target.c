#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

int test()
{
	printf("Inside test! \n");
	
	// Stay inside a function call to enable stack return address overwrite injection methods
	getchar();
	printf("Returned from getchar! \n");
	
	return 0;
}



int main()
{
	// Map write + execute memory for injection methods that require it
        void *x = mmap(NULL, 5000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        
	test();
	printf("Returned to main! \n");
	
	return 0;
}
