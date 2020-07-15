
EXEC  := uget
OBJS  := uget.o
CPPFLAGS := -DPACKAGE_NAME=\"uget\" -DPACAKGE_VERSION=\"1.0\"

all: $(EXEC)

clean:
	$(RM) $(OBJS) $(EXEC)

distclean: clean
	*.o *~

