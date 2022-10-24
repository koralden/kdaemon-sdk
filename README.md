# LongDong SDK for Raspberry Pi(2,3,4)
[![Rust 1.62+](https://img.shields.io/badge/rust-1.62+-orange.svg)](https://www.rust-lang.org)

The goal of longdong project is to establish...
***TBD***

# Install

## From Source

To compile SDK, you need a Rust toolchain.
See <https://rustup.rs/> for instructions.
(Note that Rust compilers shipped with Linux distributions
may be too outdated to compile SDK.)

The following command install related package binaries:

    $ make all

And then install configurations:

    $ make install
    # maybe need sudo permission since default install path is /etc

Reestablish daemon configuation to match system.  
**Make sure wan connection is OK before this operation**

    $ fika-manager activate

Capture output and post to [community](https://discord.com/channels/975795016410755082/1030295373798985759).
  
Command will create related connecting certificate/private-key in /userdata automaticcally by default,
but **INACTIVE** until confirm from community.

# Usage
## Start-services
    
    $ fika-manager daemon
    $ fika-easy-setup -a {RPI-LAN-IP} --certificate /etc/fika_easy_setup/certs/cert.pem --private-key /etc/fika_easy_setup/certs/key.pem

## Pairing

Using PC/Laptop's web browser, goto *https://{RPI-LAN-IP}:8888*, it will show one QRcode,
scan this QRcode from IPhone's [KApp](https://www.apple.com/tw/search/kapp?src=globalnav) APP.
    
## License

See [LICENSE](LICENSE) file.
 
## Package Guidelines

See [CONTRIBUTING.md](CONTRIBUTING.md) file.

