## Required packages:
 - g++ (version >=8)
 - libboost-all-dev (version >=1.74)
 - libgmp-dev
 - libssl-dev
 - libntl-dev
 - pkg-config
 - libglib2.0-dev

**Install Dependencies**
```bash
sudo apt install gcc-9 g++-9 make cmake git libboost-thread-dev libboost-system-dev libboost-filesystem-dev libboost-program-options-dev libgmp-dev libssl-dev pkg-config libntl-dev libglib2.0-dev -y
```

## Compilation
```
mkdir build
cd build
cmake ..
make
## Execution Environment
The code was tested on Ubuntu Ubuntu 22.04

