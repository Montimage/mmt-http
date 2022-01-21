![MMT-HTTP](mmt-http.png)

# MMT-HTTP #

- Simple version of MMT Tool
- Provide HTTP informations in your network such as: method, url, cookies, user-agent
- OS supported: Linux

## Install

Make sure you have installed [`MMT-DPI`](https;//bitbucket.org/montimage/mmt-dpi)

### Install some dependencies

To compile MMTReader, we need to install `libpcap-dev` and `libconfuse-dev`:

_On Debian machine_

```
sudo -s
apt-get update
# C/C++ environment
apt-get install -y build-essential gcc g++ make
apt-get update
apt-get install libpcap-dev libconfuse-dev
```

_On Redhat machine_

```
yum update
# C/C++ environment
yum group install "Development Tools"
yum install libpcap-devel
```

## Compile *MMT-HTTP*

To compile `MMTReader`:

```
gcc -g -o mmtHTTP mmtHTTP.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
```

## Running *MMT-HTTP*

 Usage:

```
./mmtHTTP -t [PATH_TO_PCAP_FILE] <OPTION>

sudo ./mmtHTTP -i [INTERFACE_NAME] <OPTION>
```
 
 Options:

     -b [value] : Set buffer for pcap handler in realtime monitoring

     -h         : Show help

## Issues

If you have any problem, please contact us at: [contact@montimage.com](contact@montimage.com)

## License 
Copyright [Montimage](http://montimage.com)