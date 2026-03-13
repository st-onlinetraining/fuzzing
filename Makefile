# Enable debugging and suppress pesky warnings
CFLAGS ?= -g -w 

all:	vulnerable-afl

clean:
	rm -f vulnerable
	rm -f vulnerable-arm

vulnerable: vulnerable.c
	${CC} ${CFLAGS} vulnerable.c -o vulnerable

vulnerable-afl: vulnerable.c
	afl-gcc-fast ${CFLAGS} vulnerable.c -o vulnerable 	

vulnerable-arm: vulnerable.c
	arm-linux-gnueabihf-gcc ${CFLAGS} -static vulnerable.c -o vulnerable-arm
