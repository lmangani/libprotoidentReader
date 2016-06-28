%: %.cc
	gcc -o $@ $^ -lprotoident -ltrace -lflowmanager -g -O0 -lstdc++

clean:
	if [ -a " ./reader_dpi" ]; then rm ./reader_dpi && \
	if [ ! -d "./libprotoident" ]; then rm ./libprotoident && \
	if [ ! -d "./Libflowmanager" ]; then rm ./libprotoident


deps:
	if [ -f "/etc/debian_version" ]; then apt-get -y install libtrace-dev autoconf libtool; fi
	if [ -f "/etc/redhat-release" ]; then yum -y install autoconf libtool libtrace-devel; fi
	if [ ! -d "./Libflowmanager" ]; then git clone "http://github.com/ReaDPI/Libflowmanager"; fi
	  cd Libflowmanager && git pull && ./configure && make && make install && cd ..
	if [ ! -d "./libprotoident" ]; then git clone "http://github.com/ReaDPI/libprotoident"; fi
	  cd libprotoident && git pull && ./bootstrap.sh && ./configure && make && make install && cd ..
