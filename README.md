# Library for interfacing NTAG 424 DNA

A small library for accessing [NTAG 424 DNA] proximity devices via NFC.

Only LRP encryption is supported and must be enabled permanently on the card prior to using this library.

Example code for using [`libnfc`] is provided, but any other NFC interface may be used by passing an appropriate callback function for transceiving.

See [`ntag424.h`] for an overview of provided functions.

[NTAG 424 DNA]: https://www.nxp.com/products/rfid-nfc/nfc-hf/NTAG424DNA
[`libnfc`]: https://github.com/nfc-tools/libnfc
[`ntag424.h`]: ntag424.h

## Contribution

This library is licensed under the terms of the MIT license (see [`LICENSE`]
file). By contributing (e.g. by submitting a pull request) you agree to the
publication of your work as part of this library under the MIT license.

[`LICENSE`]: LICENSE
