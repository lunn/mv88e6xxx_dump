CFLAGS = -Wall -I . -g
CFLAGS += $(shell pkg-config libmnl --cflags)
LDFLAGS += $(shell pkg-config libmnl --libs)
OBJS = mv88e6xxx_dump.o mnlg.o libnetlink.o

all: mv88e6xxx_dump

mv88e6xxx_dump: $(OBJS)
	${CC} $^ -o $@ ${LDFLAGS}

clean:
	rm $(OBJS) mv88e6xxx_dump
