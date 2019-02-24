# TIBIB-server-client-chat

server and client written in C, with colors, alert sound, multi-tasking, encryption, domaine name converter and windows/linux compatibility.

## compile and run for linux


in clnt or srvr directory (clnt in this example) tape in terminal :


gcc -c -s -O2 clnt.c

gcc clnt.o -o clnt.exe -lpthread

./clnt.exe

## compile for windows

edit compile_srv.bat or compile_cln.bat, add the C compiler path.

e.g : set PATH=%PATH%;C:\CodeBlocks\MinGW\bin.


run compile_srv.bat or compile_cln.bat.
