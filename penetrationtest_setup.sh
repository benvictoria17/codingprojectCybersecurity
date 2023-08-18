# Add kali linux sourc
sudo add-apt-repository  deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware'
sudo add-apt-repository  deb https://deb.parrot.sh/parrot/ rolling main contrib non-free'
sudo add-apt-repository  deb-src https://deb.parrot.sh/parrot/ rolling main contrib non-free'
sudo add-apt-repository 'deb https://deb.parrot.sh/parrot/ rolling-security main contrib non-free'
sudo add-apt-repository 'deb-src https://deb.parrot.sh/parrot/ rolling-security main contrib non-free'
sudo add-apt-repository 'deb http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse'
sudo add-apt-repository 'deb-src http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse'
sudo add-apt-repository 'deb http://archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse'
sudo add-apt-repository 'deb-src http://archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse'
sudo add-apt-repository 'deb http://archive.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse'
sudo add-apt-repository 'deb-src http://archive.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse'
sudo add-apt-repository 'deb http://archive.ubuntu.com/ubuntu/ focal-backports main restricted universe multiverse'
sudo add-apt-repository 'deb-src http://archive.ubuntu.com/ubuntu/ focal-backports main restricted universe multiverse'
sudo add-apt-repository 'deb http://archive.canonical.com/ubuntu focal partner'
sudo add-apt-repository 'deb-src http://archive.canonical.com/ubuntu focal partner'
sudo add-apt-repository 'deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports focal main restricted universe multiverse'
sudo add-apt-repository 'deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports focal-updates main restricted universe multiverse'
sudo add-apt-repository 'deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports focal-security main restricted universe multiverse'
sudo add-apt-repository 'deb [arch=i386,amd64] http://us.archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse'
sudo add-apt-repository 'deb [arch=i386,amd64] http://us.archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse'
sudo add-apt-repository 'deb [arch=i386,amd64] http://security.ubuntu.com/ubuntu focal-security main restricted universe multiverse'


# Update the package list and allow insecure repositories
sudo apt-get update --allow-insecure-repositories

# Install kali-linux-everything
sudo apt-get install kali-linux-default


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
