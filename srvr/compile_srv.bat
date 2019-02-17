echo off

set PATH=%PATH%;C:\MinGW\bin;

gcc -c -s -O2 srvr.c

gcc srvr.o -o srvr.exe -lpthread -lws2_32

del srvr.o

pause