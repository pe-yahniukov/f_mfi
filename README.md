# f_mfi USB gadget function Linux kernel driver

## General

A simple two-endpoint interface that is aligned with Apple Accessory Interface Specification. It should be used by MFi (Made For iPhone/iPad/iPod) accessory devices when the Apple device is in USB host mode and the accessory itself is in USB device mode.

Please see the Accessory Interface Specification to obtain information on configuring the device descriptor that uses this interface.

This interface provides only transport that is acceptable for Apple devices. It doesn't implement the iAP2 protocol, the user-space application should do it.

The driver creates a character device (/dev/mfiX, e.g. /dev/mfi0) with the following file operations:
* read()  is for output endpoint non-blocked reading.
* write() is for input endpoint non-blocked writing.
* poll()  is for waiting when some data is available for reading in the output endpoint.
* ioctl() is for obtaining an amount of bytes available for reading, and not only.

Only one user-space process can open the device at the same time.

Only the user-space process that opened the device can use the file operations described above.

## Linux kernel build system

See patches/ folder for example(s) on how to incorporate the driver into the Linux kernel build system. Please pay attention to a Kconfig, don't forget to enable the function in your kernel configuration.

## Example of usage

* example/mfi_gadget_create.sh - example of creating the gadget
* example/example.c - C example of working with the character device that was created by the gadget

## What's next?

Please visit Apple MFi program and attend to it in order to obtain Accessory Interface Specification and many other useful documentation. This will allow you to implement the iAP2 session protocol in your application. This driver will be used as a transport to communicate with your target Apple devices. Good luck!

https://mfi.apple.com

## License

Dual MIT OR GPL-2.0. See LICENSE file.

Copyright (C) 2024 by Stanislav Yahniukov
