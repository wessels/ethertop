NAME=ethertop

${NAME}: ${NAME}.o
	${CC} -g -o $@ ${@}.o -lcurses -lpcap -lpthread

${NAME}.o:
	${CC} -g -Wall -c ${NAME}.c

clean:
	rm -fv ${NAME}
	rm -fv ${NAME}.o
	
