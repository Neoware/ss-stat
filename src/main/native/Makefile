CC = 		gcc

RM = 		rm -f

CFLAGS += 	-Wextra -Wall -Werror

CFLAGS += 	-pedantic

CFLAGS += 	-I.

CFLAGS +=	-fPIC

CFLAGS +=	-I${JAVA_HOME}/include

CFLAGS +=	-I${JAVA_HOME}/include/linux

LFLAGS =	-shared -O3

NAME = 		libsocketstat.so

SRCS =		socketstat.c

OBJS = 		$(SRCS:.c=.o)

all: 		$(NAME)

$(NAME): 	$(OBJS)
		$(CC) $(LFLAGS) $(OBJS) -o $(NAME)

clean:
		$(RM) $(OBJS)

fclean: 	clean
		$(RM) $(NAME)

re: 		fclean all

.PHONY:     	all clean fclean re
