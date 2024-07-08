
MY_CFLAGS = $(shell pkg-config --cflags glib-2.0) -Werror -Wall -Wextra -g -ggdb
MY_LIBS = $(shell pkg-config --libs glib-2.0) -limaevm $(shell pkg-config --libs openssl)

all: check-ima-signature

install: all
	install -m 755 check-ima-signature /usr/bin/check-ima-signature

check-ima-signature: check-ima-signature.c
	gcc $< -o $@ $(MY_CFLAGS) $(MY_LIBS)

clean:
	rm -f check-ima-signature
