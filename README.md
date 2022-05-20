# LongDong SDK for Raspberry Pi(2,3,4)
[![Rust 1.62+](https://img.shields.io/badge/rust-1.62+-orange.svg)](https://www.rust-lang.org)

The goal of longdong project is to establish...
***TBD***

# Install

## From released binary
Just need download latest released tarball(.tar.gz) and untar to system path

    $ tar xvfz {LATEST-RELEASE-TARBALL} -C /
    # need sudo permission since default install path is /etc & /usr

## From Source

To compile SDK, you need a Rust toolchain.
See <https://rustup.rs/> for instructions.
(Note that Rust compilers shipped with Linux distributions
may be too outdated to compile SDK.)

The following command install related package binaries:

    $ make all

And then install configurations:

    $ sudo make install

(need sudo permission since default install path is /etc)

# Usage

## System requirement
Install [JQ](https://github.com/stedolan/jq) via package management - [apt](https://www.raspberrypi.com/documentation/computers/os.html#using-apt)

    $ sudo apt update
    $ sudo apt install jq iproute2 redis


## Activation

Configuation setup to match system.  
**Make sure wan connection is OK before this operation**

    $ sudo fika-manager activate

(need sudo permission to modify & add in /userdata)

Capture output and post to [community](https://discord.com/channels/975795016410755082/1030295373798985759).

```json
{
  "certificate": "....",
  "id": "....",
  "issue_time": "....",
  "name": "...."
}
```
  
Command will create related connecting certificate/private-key in /userdata automaticcally by default,
but **INACTIVE** until confirm from community.


## Start-services
    
    $ sudo fika-manager daemon
    $ sudo fika-easy-setup -a {RPI-LAN-IP}

## Pairing

Using PC/Laptop's web browser, goto *https://{RPI-LAN-IP}:8888*, it will show one QRcode,
scan this QRcode from IPhone's [KApp](https://www.apple.com/tw/search/kapp?src=globalnav) APP.
    
## License

See [LICENSE](LICENSE) file.
 
## Package Guidelines

See [CONTRIBUTING.md](CONTRIBUTING.md) file.

