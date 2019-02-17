echo off

set PATH=%PATH%;C:\MinGW\bin;

gcc -c -s -O2 clnt.c

gcc clnt.o -o clnt.exe -lpthread -lws2_32

del clnt.o

pause