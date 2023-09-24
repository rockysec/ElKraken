#!/bin/bash
sudo apt update
sudo aptget install -y tmux
sudo apt-get install -y libcurl4-openssl-dev
sudo apt-get install -y libssl-dev
sudo apt-get install -y jq
sudo apt-get install -y ruby-full
sudo apt-get install -y libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev
sudo apt-get install -y build-essential libssl-dev libffi-dev python-dev
sudo apt-get install -y python-setuptools
sudo apt-get install -y libldns-dev
sudo apt-get install -y python3-pip
sudo apt-get install -y python-pip
sudo apt-get install -y python-dnspython
sudo apt-get install -y git
sudo apt-get install -y rename
sudo apt-get install -y xargs
sudo apt-get install -y chromium chromium-l10n
sudo apt-get install -y golang
apt install -y libpcap-dev
apt install -y whatweb
apt install -y awscli
apt install -y snap
apt install -y tmux
apt install -y dnsutils
apt install -y curl
apt-get install -y nmap
snap install chromium
pip3 install dirsearch

pip install colored
pip3 install colored
pip install shodan
pip3 install uro
pip3 install requests

cd
mkdir ~/tools

git clone https://github.com/projectdiscovery/nuclei-templates
nuclei -update-templates

cd ~/tools
git clone https://github.com/rockysec/ElKraken.git
chmod +x ~/tools/ElKraken/ElKrakenTool.sh

git clone https://github.com/nahamsec/JSParser.git
cd JSParser*
sudo python setup.py install

git clone https://github.com/udhos/update-golang
cd update-golang
sudo ./update-golang.sh

cd ~/tools/
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r*
pip install -r requirements.txt

cd ~/tools/
git clone https://github.com/m4ll0k/SecretFinder.git secretfinder
cd secretfinder
pip3 install -r requirements.txt
python3 SecretFinder.py

cd ~/tools/
git clone https://github.com/1ndianl33t/Gf-Patterns

cd ~/tools/
git clone https://github.com/maurosoria/dirsearch.git

cd ~/tools/
git clone https://github.com/jobertabma/virtual-host-discovery.git

cd ~/tools/
git clone https://github.com/guelfoweb/knock.git

cd ~/tools/
git clone https://github.com/rockysec/customscripts

cd ~/tools/
git clone https://github.com/blechschmidt/massdns.git
cd ~/tools/massdns
make

cd ~/tools/
git clone https://github.com/nahamsec/crtndstry.git

cd ~/tools/
git clone https://github.com/0xbharath/assets-from-spf

cd ~/tools/
git clone https://github.com/internetwache/GitTools

cd ~/tools/
git clone https://github.com/gwen001/github-search

cd ~/tools/
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git

cd ~/tools/
git clone https://github.com/s0md3v/Corsy

cd ~/tools/
git clone https://github.com/danielmiessler/SecLists.git

cd ~/tools/SecLists/Discovery/DNS/
cat dns-Jhaddix.txt | head -n -14 > clean-jhaddix-dns.txt

curl -L -O https://github.com/projectdiscovery/httpx/releases/download/v1.0.3/httpx_1.0.3_linux_amd64.tar.gz
tar -xzvf httpx_1.0.3_linux_amd64.tar.gz
mv httpx /usr/local/bin/
 
cd ~/tools/
curl -L -O https://github.com/lc/gau/releases/download/v1.1.0/gau_1.1.0_linux_amd64.tar.gz
tar xvf gau_1.1.0_linux_amd64.tar.gz
mv gau /usr/bin/gau

cd ~/tools/
curl -L -O https://github.com/projectdiscovery/nuclei/releases/download/v2.5.4/nuclei_2.5.4_linux_amd64.zip
unzip nuclei_2.5.4_linux_amd64.zip
mv nuclei /usr/bin/
git clone https://github.com/projectdiscovery/nuclei-templates
nuclei -update

cd ~/tools/
curl -L -O https://github.com/ffuf/ffuf/releases/download/v1.2.1/ffuf_1.2.1_linux_amd64.tar.gz
tar -xzvf ffuf_1.2.1_linux_amd64.tar.gz
mv ffuf /usr/bin/

GO111MODULE=on go get github.com/hahwul/dalfox/v2

cd ~/tools
git clone https://github.com/dwisiswant0/crlfuzz.git
cd crlfuzz
go build cmd/crlfuzz/main.go
mv main crlfuzz
mv crlfuzz /usr/local/bin/

cd ~/tools 
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
python setup.py install
pip3 install -r requirements.txt

curl -L -O https://github.com/projectdiscovery/subfinder/releases/download/v2.4.5/subfinder_2.4.5_linux_386.tar.gz
tar -xzvf subfinder_2.4.5_linux_386.tar.gz
cp subfinder /usr/local/bin/

curl -L -O https://github.com/projectdiscovery/chaos-client/releases/download/v0.1.7/chaos-client_0.1.7_linux_amd64.tar.gz
tar -xzvf chaos-client_0.1.7_linux_amd64.tar.gz 
mv chaos /usr/bin/
cd

git clone https://github.com/1ndianl33t/Gf-Patterns
mkdir .gf
mv ~/Gf-Patterns/*.json ~/.gf

go get -u github.com/ffuf/ffuf
go get github.com/michenriksen/aquatone
go get -u github.com/tomnomnom/unfurl 
go get -v github.com/projectdiscovery/naabu/cmd/naabu
go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns
go get -u -v github.com/projectdiscovery/dnsprobe
go get -u github.com/tomnomnom/anew
go get -u github.com/tomnomnom/gf
go get -u github.com/tomnomnom/qsreplace
go get -u github.com/jaeles-project/gospider
go get -v github.com/projectdiscovery/httpx/cmd/httpx
go get github.com/tomnomnom/waybackurls
go get -u github.com/tomnomnom/anew
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/detectify/page-fetch@latest
nuclei -update-templates
cd ~/go/bin
cp * /usr/bin/
