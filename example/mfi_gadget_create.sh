#!/bin/sh

GADGET_BASE_DIR="/sys/kernel/config/usb_gadget/g1"

modprobe libcomposite

mkdir "${GADGET_BASE_DIR}"
cd "${GADGET_BASE_DIR}" || (echo "ERROR: Failed to load libcomposite kernel module"; exit 1)

echo 0x1d6b > idVendor  # Linux Foundation
echo 0x0104 > idProduct # Multifunction Composite Gadget
echo 0x0200 > bcdUSB    # USB2
echo 0x0    > bDeviceClass
echo 0x0    > bDeviceSubClass
echo 0x0    > bDeviceProtocol
echo 0x0100 > bcdDevice # v1.0.0

mkdir -p strings/0x409
echo "0000000000000000"  > strings/0x409/serialnumber
echo "Test manufacturer" > strings/0x409/manufacturer
echo "Test product"      > strings/0x409/product

mkdir -p configs/c.1/strings/0x409
echo "Test configuration" > configs/c.1/strings/0x409/configuration
echo 250                  > configs/c.1/MaxPower
echo 0xC0                 > configs/c.1/bmAttributes # self powered device

mkdir functions/mfi.0
ln -s functions/mfi.0 configs/c.1/

udevadm settle -t 5 || true
ls /sys/class/udc > UDC

exit 0
