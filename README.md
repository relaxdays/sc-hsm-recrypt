# sc-hsm-recrypt

[opensc](https://github.com/OpenSC/OpenSC) contains the `sc-hsm-tool` binary to manage [smart card hsms](https://github.com/OpenSC/OpenSC/wiki/SmartCardHSM). this tool allows creating dkek shares which are encrypted with an [n-of-m threshold scheme](https://github.com/OpenSC/OpenSC/wiki/SmartCardHSM#using-a-n-of-m-threshold-scheme), but sadly does not allow rotating the secrets.

this tool re-implements the necessary logic from `sc-hsm-tool` to allow for rotating the secrets.

## usage

`sc-hsm-recrypt --file path/to/dkek.bin --shares-total 6 --shares-required 3`

## notes

currently, `sc-hsm-recrypt` only recreates the secret split via the n-of-m threshold scheme, makes sure it is the correct one by decrypting the dkek share, and generates new shares for the existing dkek share. it does **NOT** change the actual key in use for the dkek share, which means all old secrets stay valid. it also does not allow changing the number of required shares.

## license

code in this repo is dual-licensed under either of

- Apache License, Version 2.0
- MIT License

at your option
