# PHoss (Phenoelits own security sniffer)

LIBDIR=
INCDIR=
LIBS=-lpcap
OPTIMI=-O3 -Wall

RM=rm
OBJECTS=main.o MIME.o list.o
CC=gcc

PHoss: $(OBJECTS)
	$(CC) -o PHoss ${OPTIMI} $(INCDIR) $(LIBDIR) $(OBJECTS) $(LIBS) 

static: $(OBJECTS)
	$(CC) -o PHossS ${OPTIMI} $(INCDIR) $(LIBDIR) $(OBJECTS) $(LIBS) -static

debug: maind.o MIMEd.o
	$(CC) -o phoss_d -g -DDEBUG $(INCDIR) $(LIBDIR) ${OBJECTS} $(LIBS) 

main.o: main.c MIME.h subprotocols.h
	$(CC) ${OPTIMI} $(INCDIR) -c main.c

list.o: list.c list.h subprotocols.h
	$(CC) ${OPTIMI} $(INCDIR) -c list.c

MIME.o: MIME.c MIME.h
	$(CC) ${OPTIMI} $(INCDIR) -c MIME.c

MIMEd.o: MIME.c
	$(CC) -g  $(INCDIR) -c MIME.c

maind.o: main.c MIME.h
	$(CC) -g $(INCDIR) -c main.c

clean:
	${RM} -f $(OBJECTS) PHoss PHossS phoss_d
