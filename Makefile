BASE=../../../..
LOCAL_CFLAGS=-I/usr/include/mysql
LOCAL_LDFLAGS=-lmysqlclient -L/usr/lib/
include $(BASE)/build/modmake.rules
