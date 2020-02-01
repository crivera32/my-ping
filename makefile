myping: main.cpp packet.o
	g++ -o myping main.cpp packet.o

packet.o: packet.cpp packet.h
	g++ -c packet.cpp

clean:
	rm -f *.o myping
