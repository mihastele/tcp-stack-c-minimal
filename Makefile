CC      := gcc
CFLAGS  := -O3 -Wall -Wextra -Werror -std=c99 -pedantic
TARGET  := ustack
SRCS    := net_base.c eth_arp.c ipv4_icmp.c tcp.c main.c
OBJS    := $(SRCS:.c=.o)

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TARGET)
	./$(TARGET) --selftest

clean:
	rm -f $(OBJS) $(TARGET)
