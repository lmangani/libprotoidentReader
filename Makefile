%: %.cc
	gcc -o $@ $^ -lprotoident -ltrace -lflowmanager -g -O0 -lstdc++

clean:
	if [ -a " ./reader_dpi" ]; then rm ./reader_dpi
	if [ ! -d "./libprotoident" ]; then rm ./libprotoident

deps:
	if [ -f "/etc/debian_version" ]; then apt-get -y install libtrace-dev autoconf libtool; fi
	if [ -f "/etc/redhat-release" ]; then yum -y install autoconf libtool libtrace-devel; fi
	wget http://research.wand.net.nz/software/libflowmanager/libflowmanager-2.0.4.tar.gz && \
	  tar zxvf libflowmanager-2.0.4.tar.gz && cd libflowmanager-2.0.4 && ./configure && \
	  make && make install && cd ..
	if [ ! -d "./libprotoident" ]; then git clone "http://github.com/lmangani/libprotoident"; fi
	  cd libprotoident && ./bootstrap.sh && ./configure && make && make install && cd ..
