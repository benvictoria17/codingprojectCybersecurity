#!/bin/bash

# Update the package list and allow insecure repositories
sudo apt-get update --allow-insecure-repositories

# Install kali-linux-everything
sudo apt-get install kali-linux-everything

# Add kali linux sources
echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" | sudo tee /etc/apt/sources.list.d/kali.list

# Make the "penetrationtest" directory and move into it
mkdir -p penetrationtest
cd penetrationtest

# Clone the required repositories
git clone https://github.com/adarshkrdubay/AKDFI.git
git clone https://github.com/sundowndev/phoneinfoga.git
git clone https://github.com/MA24th/WiFiHunter.git
cd WiFiHunter
sudo python3 setup.py install
cd ..

git clone https://github.com/m3n0sd0n4ld/uDork.git
git clone https://github.com/JoyGhoshs/Airattackit.git
git clone https://github.com/s0md3v/Photon.git
sudo apt install dnstwist
git clone https://github.com/anouarbensaad/vulnx.git
git clone https://github.com/ankitdobhal/Ashok.git
git clone https://github.com/SxNade/Rudrastra.git
git clone https://github.com/SamJoan/droopescan.git
git clone https://github.com/webernetco/wifi-thief.git
git clone https://github.com/Moham3dRiahi/Th3inspector.git
git clone https://github.com/almandin/fuxploider.git
git clone https://github.com/phenotypic/WiFiCrack.git
git clone https://github.com/GONZOsint/gitrecon.git
cd gitrecon/
python3 -m pip install -r requirements.txt
cd ..

git clone https://github.com/BadKiko/Tsunami-Fi.git
git clone https://github.com/JohnRyk/wireless_stuff.git
git clone https://github.com/Dionach/CMSmap.git
git clone https://github.com/megadose/toutatis.git
cd toutatis/
python3 setup.py install
cd ..

git clone https://github.com/n4xh4ck5/CMSsc4n.git
git clone https://github.com/Invertebr4do/WiBreak.git
git clone https://github.com/0301yasiru/LionCub.git

# Print completion message
echo "All repositories have been cloned and installed successfully!"

sudo chmod +x penetrationtest_setup.sh

sudo ./penetrationtest_setup.sh
