#/usr/bin/bash

sudo apt install python3 python3-pip git curl libpcap-dev wget python3-dev python3-dnspython pv dnsutils build-essential libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap  python3-shodan apt-transport-https   -y 
# install go from site and configure path
# after this go to .bashrc or .zshrc file and add these lines at the end of the file.
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH

# Installing tools:
# findomain :
eval wget -N -c https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux
sudo mv findomain-linux /usr/local/bin/findomain
sudo chmod 755 /usr/local/bin/findomain
eval wget -nc -O ~/.config/amass/config.ini https://raw.githubusercontent.com/OWASP/Amass/master/examples/config.ini 

go get  -v github.com/tomnomnom/qsreplace
GO111MODULE=on go get -v  github.com/OWASP/Amass/v3/
go get  -v github.com/tomnomnom/assetfinder
go get -v github.com/tomnomnom/hacks/waybackurls
go get -v github.com/tomnomnom/anew
go get -v github.com/tomnomnom/unfurl
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
GO111MODULE=on go get -u -v github.com/bp0lr/gauplus
go get -v github.com/cgboal/sonarsearch/crobat
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
eval git clone https://github.com/projectdiscovery/nuclei-templates ~/nuclei-templates
eval nuclei -update-templates
eval sed -i 's/^miscellaneous/#miscellaneous/' ~/nuclei-templates/.nuclei-ignore 
eval sed -i 's/^#random-agent: false/random-agent: true/' ~/.config/nuclei/config.yaml
eval wget -O resolvers_trusted.txt https://gist.githubusercontent.com/six2dez/ae9ed7e5c786461868abd3f2344401b6/raw
eval strip -s $HOME/go/bin/*
eval pip3 install multithreading termcolor sys os colored subprocess readline art 
mkdir ~/Tools; eval git clone https://github.com/darkoperator/dnsrecon.git  ~/Tools/dnsrecon/ 
sudo python3 ~/Tools/dnsrecon/setup.py install
eval git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/Tools/testssl.sh 
eval git clone https://github.com/six2dez/degoogle_hunter.git ~/Tools/degoogle_hunter 
eval git clone  https://github.com/obheda12/GitDorker.git ~/Tools/GitDorker
eval pip3 install -r ~/Tools/GitDorker/requirements.txt
eval git clone https://github.com/s0md3v/Corsy.git ~/Tools/Corsy
eval pip3 install -r ~/Tools/Corsy/requirements.txt
eval git clone https://github.com/Tuhinshubhra/CMSeeK.git ~/Tools/CMSeeK 
sudo python3 ~/Tools/CMSeeK/setup.py install 