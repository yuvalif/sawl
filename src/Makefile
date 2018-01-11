CC?=gcc

ifeq ($(VERSION),)
VERSION = 0.1.0
endif

ifeq ($(DBG),on)
CFLAGS?=-O0 -g -Wall -I../inc/
else
CFLAGS?=-O2 -Wall -I../inc/
endif
LDFLAGS?=

ifeq ($(LOGS),on)
CFLAGS+=-DLOGS
endif

CFLAGS+=-DVERSION=\"$(VERSION)\"

TARGET=sawl

SOURCES=main.c http.c packet.c radius.c update_redis.c update_csv.c subscriber_db.c stats.c
OBJECTS=$(SOURCES:.c=.o)
LIBS = -lpcap -lssl -lcrypto -lhiredis -lpthread

.PHONY: all clean

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

-include $(OBJECTS:.o=.d)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
	$(CC) -MM $(CFLAGS) $< > $*.d

clean:
	$(RM) *.o *.d $(TARGET)

