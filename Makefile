des: main.c des.c des.h
	gcc --std=c11 -Wall main.c des.c -o des

clean:
	rm des
