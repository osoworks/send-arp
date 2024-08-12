CC = gcc
CFLAGS = -Wall -Wextra -std=c99

TARGET = send-arp
OBJS = send_arp.o main.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -lpcap

send_arp.o: send_arp.c send_arp.h
	$(CC) $(CFLAGS) -c send_arp.c

main.o: main.c send_arp.h
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f $(TARGET) $(OBJS)

