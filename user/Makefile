######

objs = fsdev.o ftpparse.o ftpclient.o fscbk.o

cflags = 
links = 

fsdev:$(objs)
	g++ -o ./fsdev $(objs) -lpthread $(links)

ftpparse.o:
	gcc -c ftpparse.c $(cflags)

%.o:%.cpp
	g++ -c $< -o $@  $(cflags)

clean:
	-rm *.o
