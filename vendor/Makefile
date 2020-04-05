all: tinyxml2.o easylogging++.o

tinyxml2.o: github.com/leethomason/tinyxml2/tinyxml2.cpp
	$(CXX) $(CPPFLAGS) -c -o $@ $^

easylogging++.o: github.com/muflihun/easyloggingpp/src/easylogging++.cc
	$(CXX) $(CPPFLAGS) -c -o $@ $^

clean:
	$(RM) tinyxml2.o easylogging++.o
