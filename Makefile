CC = gcc
CFLAGS = -g -Wall -fPIC -std=gnu99
LFLAGS = -lpthread

TARGET	     = csdo csdod

all:
	$(MAKE) $(TARGET)

csdo: csdo.o
	@$(CC) $(CFLAGS) $^ -o $@

csdod: csdod.o
	@$(CC) $(CFLAGS) $(LFLAGS) $^ -o $@

%.o: %.c
	@echo "  CC " $<
	@$(CC) -c $(CFLAGS) -o "$@" "$<"

clean:
	@rm -rf ./*.o $(TARGET)

distclean:
	make clean

.PHONY: all clean distclean
