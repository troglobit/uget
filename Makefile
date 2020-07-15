
EXEC  := uget
OBJS  := uget.o

all: $(EXEC)

clean:
	$(RM) $(OBJS) $(EXEC)

distclean: clean
	*.o *~

