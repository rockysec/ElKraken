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
apt install -y tmux
apt install -y dnsutils
apt install -y curl
apt-get install -y nmap
pip3 install dirsearch

pip install colored
pip3 install colored
pip3 install uro
pip3 install requests

cd
mkdir ~/tools

git clone https://github.com/projectdiscovery/nuclei-templates
nuclei -update-templates

cd ~/tools
git clone https://github.com/udhos/update-golang
cd update-golang
sudo ./update-golang.sh

cd ~/tools/
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r*
pip install -r requirements.txt

cd ~/tools/
git clone https://github.com/maurosoria/dirsearch.git

cd ~/tools/
git clone https://github.com/rockysec/customscripts

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
curl -L -O https://github.com/projectdiscovery/nuclei/releases/download/v2.5.4/nuclei_2.5.4_linux_amd64.zip
unzip nuclei_2.5.4_linux_amd64.zip
mv nuclei /usr/bin/
git clone https://github.com/projectdiscovery/nuclei-templates
nuclei -update

cd ~/tools
git clone https://github.com/dwisiswant0/crlfuzz.git
cd crlfuzz
go build cmd/crlfuzz/main.go
mv main crlfuzz
mv crlfuzz /usr/local/bin/

curl -L -O https://github.com/projectdiscovery/subfinder/releases/download/v2.4.5/subfinder_2.4.5_linux_386.tar.gz
tar -xzvf subfinder_2.4.5_linux_386.tar.gz
cp subfinder /usr/local/bin/

git clone https://github.com/1ndianl33t/Gf-Patterns
mkdir .gf
mv ~/Gf-Patterns/*.json ~/.gf

go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/projectdiscovery/httpx@latest
go install github.com/tomnomnom/waybackurls@latest
nuclei -update-templates
cd ~/go/bin
cp * /usr/bin/
