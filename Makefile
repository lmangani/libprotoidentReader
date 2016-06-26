%: %.cc
	gcc -o $@ $^ -lprotoident -ltrace -lflowmanager -g -O0 -lstdc++

clean:
	rm ./reader_dpi

library:
	if [ ! -d "./libprotoident"]; then git clone "http://github.com/lmangani/libprotoident"; fi
	cd libprotoident && ./bootstrap.sh && ./configure && make && cd .. \

library-install:
	cd libprotoident && make install
