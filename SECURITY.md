# Security Policy

## Supported Versions

Versions prior to 1.0.0 which is considered the first official release are not supported

| Version | Supported          |
| ------- | ------------------ |
| 1.0.0   | :white_check_mark: |
| < 1.0.0 | :x:              |

## Reporting a Vulnerability

Typically the vulnerability will be a result of parsing bad input due to the nature of the library which must act
depending on lengths given by the data themselves. Some erroneous length checking leading to out of bounds access of the buffer is the most prominent.
Whatever the case, open a new bug issue and provide the steps to reproduce and whenever applicable provide the **binary data input** that caused the abnormal behavior.
The form of the input shall be in the form: `uint8_t pp_hdr_evil[] = { 0xXX, 0XX ...}` so that it can be easily unit tested.

