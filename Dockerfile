# docker build --tag ebat:ubuntu20.04 .

# docker run -i -t --rm --name ebat -v $PWD:/EBAT:rw ebat:ubuntu20.04 /EBAT/tests/TYPE/script.sh
# docker run -i -t --rm --name ebat -v $PWD:/EBAT:rw ebat:ubuntu20.04 /EBAT/tests/Routers/runDSR-250.sh

# docker stop ebat
# docker rm ebat
# remove all
# docker system prune
# docker system prune -a

# docker images purge
# stop all running containers
# docker stop $(docker ps -a -q)
# remove all containers
# docker rm $(docker ps -a -q)

FROM ubuntu:20.04
#ENV GHIDRA_DOWNLOAD=https://ghidra-sre.org/ghidra_9.1.2_PUBLIC_20200212.zip
ENV GHIDRA_DOWNLOAD=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_9.1.2_build/ghidra_9.1.2_PUBLIC_20200212.zip
ENV GHIDRA_PATH=ghidra_9.1.2_PUBLIC
ENV GSON_JAVA_DOWNLOAD=https://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.6/gson-2.8.6.jar
ENV DROPBEAR_DOWNLOAD=https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/dropbear/2019.78-2build1/dropbear_2019.78.orig.tar.bz2
ENV YARA_DOWNLOAD=https://github.com/VirusTotal/yara/archive/v4.0.2.tar.gz
ENV LC_CTYPE C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive
ENV NVD_API_KEY="420261fc-d89b-4c58-9cdd-61af2940a9d9"

RUN apt-get update && \
apt-get install -y build-essential vim git make cmake g++ libgraphviz-dev wget curl unzip default-jdk \
python2-dev libboost-all-dev python3 python3-dev python3-pip python3-lzo libssl-dev python3-crypto python3-opengl python \
python3-numpy python3-scipy python3-pip libmagic-dev libarchive-dev unrar python-crypto python3-gpg lzma-dev liblzma-dev \
python-crypto p7zip-full squashfs-tools pgpdump lzma tar rpm2cpio cpio cabextract graphviz-dev python3-pygraphviz gcc \
mtd-utils gzip bzip2 tar arj lhasa p7zip p7zip-full cramfsswap squashfs-tools sleuthkit lzop srecord gpg \
python3-testresources devscripts libffi-dev libfuzzy-dev apt-transport-https ca-certificates gnupg-agent libgpgmepp-dev \
software-properties-common binutils-multiarch libjansson-dev automake libtool libprotobuf-c-dev pkg-config
# install pip2
RUN curl https://bootstrap.pypa.io/pip/3.5/get-pip.py --output get-pip.py && python2 get-pip.py && \
mkdir tools && cd tools && \
# install latest yara 4.0.2 with modules
wget $YARA_DOWNLOAD && tar -zxf v4.0.2.tar.gz && cd yara-4.0.2 && \
./bootstrap.sh && ./configure --enable-cuckoo --enable-magic --enable-dotnet && make && make install && \
sh -c 'echo "/usr/local/lib" >> /etc/ld.so.conf' && ldconfig
WORKDIR /tools
# Download Binwalk
RUN git clone --recursive https://github.com/ReFirmLabs/binwalk && cd binwalk &&  \
# add bionic apt packages
#echo "deb http://cz.archive.ubuntu.com/ubuntu bionic main universe" | tee --append /etc/apt/sources.list && \
# Install dependencies for binwalk
# Remove CramFS and python-lzo (replace with python3-lzo from APT requirements) and fix distro comparison
#1sed -r -e 's/cramfsprogs / /' -e 's/python-pip / /' -e 's/libqt4-opengl / /' -e 's/python-lzma / /' -e 's/python-lzo /python3-lzo/' deps.sh > deps_fixed.sh && \
# sed for ubi reader fix remove it will install manually later
sed -r -e 's/^install_ubireader/#install_ubireader/' deps.sh > deps_fixed.sh && \
chmod +x deps_fixed.sh && ./deps_fixed.sh --yes

# Other dependencies for EBAT
RUN pip3 install toposort networkx matplotlib nose coverage pyqtgraph capstone rarfile pygraphviz py7zr pygal jinja2 && \
pip3 install ssdeep plotly seaborn aiohttp bs4 rich
# Download CramFS and install it separately
#wget ftp://ftp.si.debian.org/debian/pool/main/c/cramfs/cramfsprogs_1.1-6_amd64.deb && \
RUN wget http://launchpadlibrarian.net/1248932/cramfsprogs_1.1-6_amd64.deb && \
dpkg -i cramfsprogs_1.1-6_amd64.deb

RUN cd /tools/binwalk && mkdir deps

WORKDIR /tools/binwalk/deps
# Install sasquatch to extract non-standard SquashFS images
RUN apt-get install -y zlib1g-dev liblzma-dev liblzo2-dev && \
git clone https://github.com/devttys0/sasquatch && \
cd sasquatch && ./build.sh
# mirror squashfs if failed
# sed -r -e 's/\$SUDO //' -e 's/https:\/\/downloads.sourceforge.net\/project\/squashfs\/squashfs\/squashfs4.3\/squashfs4.3.tar.gz/https:\/\/sourceforge.net\/projects\/squashfs\/files\/squashfs\/squashfs4.3\/squashfs4.3.tar.gz\/download\?use_mirror=netcologne -O squashfs4.3.tar.gz/' build.sh > build_fixed.sh && chmod a+x build_fixed.sh && \
#1sed -r -e 's/\$SUDO //' build.sh > build_fixed.sh && chmod a+x build_fixed.sh && \
#1./build_fixed.sh && cd .. && \

# Install jefferson to extract JFFS2 file systems
RUN pip3 install cstruct && pip2 install cstruct && \
git clone https://github.com/sviehb/jefferson && \
cd jefferson && pip3 install -r requirements.txt && python3 setup.py install
# Install ubi_reader to extract UBIFS file systems
RUN apt-get install -y liblzo2-dev python3-lzo && \
pip2 install python-lzo && pip3 install python-lzo poetry && \
git clone https://github.com/jrspruitt/ubi_reader && \
cd ubi_reader && poetry install
# Install yaffshiv to extract YAFFS file systems
RUN git clone https://github.com/devttys0/yaffshiv && \
cd yaffshiv && python3 setup.py install
# Install unstuff (closed source) to extract StuffIt archive files
# wget -O - https://www.dropbox.com/s/erkqvnzhb7vu88g/stuffit520.611linux-i386.tar.gz | tar -zxv && \
#RUN wget -O - http://downloads.tuxfamily.org/sdtraces/stuffit520.611linux-i386.tar.gz | tar -zxv && \
RUN wget -O - http://mirror.sobukus.de/files/grimoire/z-archive/stuffit520.611linux-i386.tar.gz | tar -zxv && \
cp bin/unstuff /usr/local/bin/

WORKDIR /tools/binwalk
# Install binwalk for python3
RUN python3 setup.py install
WORKDIR /tools
# install dropbear
RUN apt-get install -y dropbear-bin && \
wget $DROPBEAR_DOWNLOAD -O dropbear_src.tar.bz2 && tar -xf dropbear_src.tar.bz2 && cd dropbear-2019.78 && \
./configure && make PROGRAMS=dropbearconvert && make PROGRAMS=dropbearconvert install
# install CVE bin tool https://github.com/intel/cve-bin-tool
# latest
# pip3 install -U git+https://github.com/intel/cve-bin-tool && \
# stable
RUN pip3 install cve-bin-tool && \
# patch cve-bin-tool \
# issue https://github.com/intel/cve-bin-tool/issues/990 fixed
#cp /usr/local/lib/python3.8/dist-packages/cve_bin_tool/cve_scanner.py /usr/local/lib/python3.8/dist-packages/cve_bin_tool/cve_scanner.py.bak && \
#sed -e 's/            parsed_version = parse_version(product_info.version)/            parsed_version = parse_version(product_info.version)\n            if product_info.product == "openssl":\n                parsed_version = parse_version(self.openssl_convert(product_info.version))/' /usr/local/lib/python3.8/dist-packages/cve_bin_tool/cve_scanner.py.bak > /usr/local/lib/python3.8/dist-packages/cve_bin_tool/cve_scanner.py && \
# patch file
#wget https://www.dropbox.com/s/raikv31sowj8i09/cvedb.patch && \
#patch /usr/local/lib/python3.8/dist-packages/cve_bin_tool/cvedb.py cvedb.patch && \
# dummy run to update CVE database
cve-bin-tool -u now /tmp --nvd-api-key ${NVD_API_KEY}
#1cd .. && \
# download cve release db with publish dates
RUN git clone https://github.com/ppanagiotou/cvedbrelease && python3 /tools/cvedbrelease/cvedb.py -u --nvd-api-key ${NVD_API_KEY}
# Download Ghidra
RUN wget $GHIDRA_DOWNLOAD -O ghidra.zip && \
# unzip it
unzip ghidra.zip  && \
# Download and unzip gson
wget $GSON_JAVA_DOWNLOAD -O gson.jar && mv gson.jar $GHIDRA_PATH/support && \
# Patch Ghidra launch to include the external java library gson
cd $GHIDRA_PATH/support && cp launch.sh launch.sh.bak && \
sed -r -e 's/\$\{CPATH}/${CPATH}:${SUPPORT_DIR}\/gson.jar/' launch.sh.bak > launch.sh && \
# maximize heap memory to 3GB
cp analyzeHeadless analyzeHeadless.bak && \
sed -r -e 's/MAXMEM=2G/MAXMEM=4G/' analyzeHeadless.bak > analyzeHeadless

WORKDIR /EBAT