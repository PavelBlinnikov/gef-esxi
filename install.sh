mkdir -p $HOME/gef-esxi
wget -q https://raw.githubusercontent.com/PavelBlinnikov/gef-esxi/main/esxi.py -o $HOME/gef-esxi/esxi.py

sed -i -E "s|python sys\.path\.insert\(0, \"/root/\.gef\"\); from gef import \*; Gef\.main\(\)|python sys.path.insert(0, \"/root/.gef\"); sys.path.insert(0, \"$HOME/gef-esxi\"); from gef import *; from esxi import *; Gef.main()|g" /root/.gdbinit
