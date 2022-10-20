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

The following command install related packages:

    $ cd longdong/system/fika-manager/src
    $ cargo install --path .
    $ cd longdong/net/fika-easy-setup/src
    $ cargo install --path .

And then setup configurations:

    $ cp -a longdong/system/fika-manager/files /etc/fika_manager
    $ install -d /etc/fika_easy_setup
    $ cp -a longdong/net/fika-easy-setup/src/certs /etc/fika_easy_setup
    $ cp -a longdong/net/fika-easy-setup/src/templates /etc/fika_easy_setup
    $ install -d /userdata
    $ cp /etc/fika_manager/kdaemon.toml.sample kdaemon.toml

Reestablish daemon configuation to match system.  
**Make sure wan connection is OK before this operation**

    $ fika-manager recovery

# Usage
## Start-services
    
    $ fika-manager daemon
    $ fika-easy-setup -a {RPI-LAN-IP} --certificate /etc/fika_easy_setup/certs/cert.pem --private-key /etc/fika_easy_setup/certs/key.pem

After daemon start first time, it will create **INACTIVE** connection certificate/private-key /userdata automaticcally by default,
All IOT connection is broken until active key(#device-activation)

## Device-Activation

    $ fika-manager activation

Capture its output and feedback to [community](https://discord.com/channels/975795016410755082/1030295373798985759).
We will *ACTIVE* related certification in back-end.

## Pairing

Using PC/Laptop's web browser, goto *https://{RPI-LAN-IP}:8888*, it will show one QRcode,
scan this QRcode from IPhone's [KApp](https://www.apple.com/tw/search/kapp?src=globalnav) APP.
    
## License

See [LICENSE](LICENSE) file.
 
## Package Guidelines

See [CONTRIBUTING.md](CONTRIBUTING.md) file.

