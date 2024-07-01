#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PERF_DEF_OPTS (1 | 16)

static void
enable_cpu_counters(void* data)
{
	/* Enable user-mode access to counters. */
	puts("test0");
        asm volatile("mcr p15, 0, %0, c9, c14, 0" :: "r"(1));
        /* Program PMU and enable all counters */
        puts("test1");
        asm volatile("mcr p15, 0, %0, c9, c12, 0" :: "r"(PERF_DEF_OPTS));
        puts("test2");
        asm volatile("mcr p15, 0, %0, c9, c12, 1" :: "r"(0x8000000f));
        puts("test3");
}

int main(int argc, char *argv[])
{
        on_each_cpu(enable_cpu_counters, NULL, 1);
        puts("test4");
        
        uint32_t r = 0;
        asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(r) );
        puts("test5");
        
        return 0;
}
