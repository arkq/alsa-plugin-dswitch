LIBNAME := libasound_module_pcm_dswitch.so
SOURCES := pcm_dswitch.c

.PHONE: all
all: $(LIBNAME)

.PHONE: clean
clean:
	rm -f $(LIBNAME)

$(LIBNAME): $(SOURCES)
	$(CC) $(CFLAGS) -shared -fPIC -DPIC -o $@ $^ -lasound
