NAME=ethertop

all: ${NAME}

${NAME}: ${NAME}.o
	${CC} -o $@ ${NAME}.o -lcurses -lpcap
