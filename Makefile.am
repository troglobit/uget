EXTRA_DIST    = README.md LICENSE
doc_DATA      = README.md LICENSE
bin_PROGRAMS  = uget

uget_CFLAGS   = -W -Wall -Wextra
uget_CPPFLAGS = -DSTANDALONE
uget_SOURCES  = uget.c uget.h

if ENABLE_SSL
uget_SOURCES += ssl.c ssl.h
endif
