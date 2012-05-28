LIBS	= -lev `pkg-config --libs glib-2.0`
FLAGS	= -g -Wall -Werror -Wno-strict-aliasing -Wno-unused-variable -Wno-unused-function -std=c99 -Wno-missing-braces `pkg-config --cflags glib-2.0`
OBJS    = headers.o memory.o main.o ev_helpers.o outstream.o helpers.o easy_hashtable.o blacklist.o

inceptroxy: $(OBJS)
	$(CC) $(FLAGS) -o inceptroxy $(OBJS) $(LIBS) ../deps/http-parser/http_parser.o

-include $(OBJS:.o=.d)

%.o: %.c
	gcc $(FLAGS) -c $*.c -o $*.o
	gcc $(FLAGS) -MM $*.c > $*.d
