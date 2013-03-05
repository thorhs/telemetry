telemetry: telemetry.c btree.c Makefile
	gcc -O2 -fprofile-arcs -Wall telemetry.c btree.c -o telemetry -lpcre -lpthread
