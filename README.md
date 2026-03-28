# gef-esxi

This is the GDB extension that enables comfortable ESXi debugging. It is based on [bata24-gef](https://github.com/bata24/gef). 

## Installation

To install gef-esxi you need to install both bata24-gef and gef-esxi:

```bash
wget -q https://raw.githubusercontent.com/bata24/gef/dev/install-uv.sh -O- | sudo sh
wget -q https://raw.githubusercontent.com/PavelBlinnikov/gef-esxi/main/install.sh -O- | sudo sh
```

## Features

- `esx vmk-file filepath`: adds VMKernel symbols
    - ![](images/1.png)

- `esx mods`: adds basic modules' symbols (vmmblob and vmm)
    - ![](images/2.png)
    - on vm startup loads secondary modules' symbols
        - ![](images/3.png)
- `esx regs`: prints userspace registers on syscall entry
    - ![](images/4.png)
