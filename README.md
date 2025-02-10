# JANUS - FUD Reverse Shell

## I. Introduction

Janus is a simple reverse shell developed in C++ that can establish a reverse tcp connection
to the attacker from the victim's computer. The attacker can after that execute commands on the victim's computer.
This too has the objective to be fud (fully undetectable) in the future.

## II. Installation

At first clone the repo and navigate to the directory:
``` bash
git clone https://github.com/Omikrone/Janus.git
cd Janus
```

Once in the directory, you have to compile the project with CMake. But before that, you may want to change 
the host ip and the port used by the backdoor. To do that, simply edit the first lines of ``client.cpp`` and 
``server.cpp`` so it uses your preferences instead of ``localhost``. Once done, you can compile the project with: 
```
mkdir build
cd build
cmake ..
cmake --build .
```

And it is done!

## III. Usage and features

To execute it, you have to launch the server first, and then the malicious file. Here are the following features for the 
moment:
- Remote command execution
- Background launch
- Persistence : the backdoor start at every startup of the victims computer

## IV. AV detection

Here is the current detection rate on virustotal for Janus:
![virustotal](img/scan.png)
I will try to get it fud fo the next update.

## V. Disclaimer and further information
This program is for educational purposes only! I take no responsibility or liability for own personal use.