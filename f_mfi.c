// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * f_mfi.c - USB interface driver for MFi accessory
 *
 * Copyright (C) 2024 by Stanislav Yahniukov
 */

/* #define DEBUG         */
/* #define VERBOSE_DEBUG */

#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/usb/composite.h>

#define MAX_MFI_INTERFACES (CONFIG_USB_CONFIGFS_F_MFI_MAX)

/*
 * A simple two-endpoint interface that is aligned with
 * Apple Accessory Interface Specification. It should be used
 * by MFi (Made For iPhone/iPad/iPod) accessory devices when
 * the Apple device is in USB host mode and the accessory
 * itself is in USB device mode.
 *
 * Please see the Accessory Interface Specification to obtain
 * information on configuring the device descriptor that uses
 * this interface.
 *
 * This interface provides only transport that is acceptable
 * for Apple devices. It doesn't implement the iAP2 protocol,
 * the user-space application should do it.
 *
 * The driver creates a character device (/dev/mfiX, e.g. /dev/mfi0)
 * with the following file operations:
 * - read()  is for output endpoint non-blocked reading.
 * - write() is for input endpoint non-blocked writing.
 * - poll()  is for waiting when some data is available for reading
 *           in the output endpoint.
 * - ioctl() is for obtaining an amount of bytes available for reading,
 *           and not only.
 * Only one user-space process can open the device at the same time.
 * Only the user-space process that opened the device can use the
 * file operations described above.
 */

struct f_mfi {
	struct usb_function function;

	struct usb_ep *in_ep;
	struct usb_ep *out_ep;

	struct usb_request *read_req;
	struct usb_request *write_req;

	u8 *in_buf;
	int in_buf_cnt;
	wait_queue_head_t in_wait;

	u8 *out_buf;
	int out_buf_cnt;

	int minor;
	struct cdev cdev;
	struct task_struct *task;

	/* for in_buf, out_buf access control */
	spinlock_t lock;
	unsigned long flags;
	/* for file operations access control */
	struct mutex mutex;
};

struct f_mfi_opts {
	struct usb_function_instance func_inst;
};

static __always_inline struct f_mfi *func_to_mfi(struct usb_function *f)
{
	return container_of(f, struct f_mfi, function);
}

static __always_inline void mfi_spin_lock(struct f_mfi *mfi)
{
	spin_lock_irqsave(&mfi->lock, mfi->flags);
}

static __always_inline void mfi_spin_unlock(struct f_mfi *mfi)
{
	spin_unlock_irqrestore(&mfi->lock, mfi->flags);
}

/*-------------------------------------------------------------------------*/

static __always_inline struct device *get_mfi_dev(struct f_mfi *mfi)
{
	return &mfi->function.config->cdev->gadget->dev;
}

#define mfi_dev_err(mfi, fmt, ...) \
	dev_err(get_mfi_dev(mfi), "f_mfi: ERROR: " fmt, ##__VA_ARGS__)
#define mfi_dev_warn(mfi, fmt, ...) \
	dev_warn(get_mfi_dev(mfi), "f_mfi: WARNING: " fmt, ##__VA_ARGS__)
#define mfi_dev_info(mfi, fmt, ...) \
	dev_info(get_mfi_dev(mfi), "f_mfi: INFO: " fmt, ##__VA_ARGS__)
#define mfi_dev_dbg(mfi, fmt, ...) \
	dev_dbg(get_mfi_dev(mfi), "f_mfi: DEBUG: " fmt, ##__VA_ARGS__)
#define mfi_dev_vdbg(mfi, fmt, ...) \
	dev_vdbg(get_mfi_dev(mfi), "f_mfi: DEBUG: " fmt, ##__VA_ARGS__)

/*-------------------------------------------------------------------------*/

static struct usb_interface_descriptor mfi_intf = {
	.bLength = sizeof(mfi_intf),
	.bDescriptorType = USB_DT_INTERFACE,
	.bNumEndpoints = 2,
	.bInterfaceClass = USB_CLASS_VENDOR_SPEC,
	.bInterfaceSubClass = 0xF0, /* MFi accessory */
	.bInterfaceProtocol = 0x00,
};

/* full speed support: */

static struct usb_endpoint_descriptor fs_mfi_source_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes = USB_ENDPOINT_XFER_BULK,
};

static struct usb_endpoint_descriptor fs_mfi_sink_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes = USB_ENDPOINT_XFER_BULK,
};

static struct usb_descriptor_header *fs_mfi_descs[] = {
	(struct usb_descriptor_header *)&mfi_intf,
	(struct usb_descriptor_header *)&fs_mfi_sink_desc,
	(struct usb_descriptor_header *)&fs_mfi_source_desc,
	NULL,
};

/* high speed support: */

static struct usb_endpoint_descriptor hs_mfi_source_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bmAttributes = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize = cpu_to_le16(512),
};

static struct usb_endpoint_descriptor hs_mfi_sink_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bmAttributes = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize = cpu_to_le16(512),
};

static struct usb_descriptor_header *hs_mfi_descs[] = {
	(struct usb_descriptor_header *)&mfi_intf,
	(struct usb_descriptor_header *)&hs_mfi_source_desc,
	(struct usb_descriptor_header *)&hs_mfi_sink_desc,
	NULL,
};

/* super speed support: */

static struct usb_endpoint_descriptor ss_mfi_source_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bmAttributes = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize = cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor ss_mfi_source_comp_desc = {
	.bLength = USB_DT_SS_EP_COMP_SIZE,
	.bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
	.bMaxBurst = 0,
	.bmAttributes = 0,
	.wBytesPerInterval = 0,
};

static struct usb_endpoint_descriptor ss_mfi_sink_desc = {
	.bLength = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,
	.bmAttributes = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize = cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor ss_mfi_sink_comp_desc = {
	.bLength = USB_DT_SS_EP_COMP_SIZE,
	.bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
	.bMaxBurst = 0,
	.bmAttributes = 0,
	.wBytesPerInterval = 0,
};

static struct usb_descriptor_header *ss_mfi_descs[] = {
	(struct usb_descriptor_header *)&mfi_intf,
	(struct usb_descriptor_header *)&ss_mfi_source_desc,
	(struct usb_descriptor_header *)&ss_mfi_source_comp_desc,
	(struct usb_descriptor_header *)&ss_mfi_sink_desc,
	(struct usb_descriptor_header *)&ss_mfi_sink_comp_desc,
	NULL,
};

/* function-specific strings: */

static struct usb_string strings_mfi[] = {
	[0].s = "",
	[1].s = "iAP Interface",
	{} /* end of list */
};

static struct usb_gadget_strings stringtab_mfi = {
	.language = 0x0409, /* en-us */
	.strings = strings_mfi,
};

static struct usb_gadget_strings *mfi_strings[] = {
	&stringtab_mfi,
	NULL,
};

/*-------------------------------------------------------------------------*/

static void mfi_complete(struct usb_ep *ep, struct usb_request *req);

static inline struct usb_request *mfi_alloc_req(struct usb_ep *ep)
{
	struct usb_request *req = usb_ep_alloc_request(ep, GFP_ATOMIC);
	if (unlikely(NULL == req))
		return NULL;
	req->buf = kmalloc(ep->maxpacket, GFP_ATOMIC);
	if (unlikely(NULL == req->buf)) {
		usb_ep_free_request(ep, req);
		req = NULL;
	}
	return req;
}

static inline void mfi_free_req(struct usb_request *req, struct usb_ep *ep)
{
	if (likely(req)) {
		if (likely(req->buf))
			kfree(req->buf);
		usb_ep_free_request(ep, req);
	}
}

static inline int mfi_send_async(struct f_mfi *mfi)
{
	/* mfi->lock should be locked before calling this function */

	int ret = 0;

	if (mfi->write_req)
		return -EBUSY;

	mfi->write_req = mfi_alloc_req(mfi->in_ep);
	if (unlikely(NULL == mfi->write_req))
		return -ENOMEM;

	mfi->write_req->context = mfi;
	mfi->write_req->complete = mfi_complete;
	mfi->write_req->length = mfi->out_buf_cnt;
	memcpy(mfi->write_req->buf, mfi->out_buf, mfi->out_buf_cnt);

	/* temporary unlock to avoid deadlock in complete callback */
	mfi_spin_unlock(mfi);
	ret = usb_ep_queue(mfi->in_ep, mfi->write_req, GFP_ATOMIC);
	mfi_spin_lock(mfi);

	return ret;
}

static inline int mfi_recv_async(struct f_mfi *mfi)
{
	/* mfi->lock should be locked before calling this function */

	int ret = 0;

	if (mfi->read_req)
		return -EBUSY;

	mfi->read_req = mfi_alloc_req(mfi->out_ep);
	if (unlikely(NULL == mfi->read_req))
		return -ENOMEM;

	mfi->read_req->context = mfi;
	mfi->read_req->complete = mfi_complete;
	mfi->read_req->length = mfi->out_ep->maxpacket;

	/* temporary unlock to avoid deadlock in complete callback */
	mfi_spin_unlock(mfi);
	ret = usb_ep_queue(mfi->out_ep, mfi->read_req, GFP_ATOMIC);
	mfi_spin_lock(mfi);

	return ret;
}

/*-------------------------------------------------------------------------*/

#define IOCTL_GADGET_GET_MFI_IN_BUF_CNT _IOW('a', 0x10, int32_t)
#define IOCTL_GADGET_GET_MFI_MAX_PACKET_SIZE _IOW('a', 0x11, int32_t)

static __always_inline struct f_mfi *cdev_to_mfi(struct cdev *d)
{
	return container_of(d, struct f_mfi, cdev);
}

static __always_inline bool mfi_permission_denied(struct f_mfi *mfi)
{
	/* mfi->mutex should be locked before calling this function */

	return mfi->task != get_current();
}

static int mfi_open(struct inode *inode, struct file *file)
{
	struct f_mfi *mfi = cdev_to_mfi(inode->i_cdev);

	mutex_lock(&mfi->mutex);

	if (mfi->task) {
		mutex_unlock(&mfi->mutex);
		return -EBUSY;
	}
	mfi->task = get_current();

	mutex_unlock(&mfi->mutex);

	mfi_dev_dbg(mfi, "/dev/mfi%d opened\n", mfi->minor);

	return 0;
}

static int mfi_release(struct inode *inode, struct file *file)
{
	struct f_mfi *mfi = cdev_to_mfi(inode->i_cdev);

	mutex_lock(&mfi->mutex);

	if (mfi_permission_denied(mfi)) {
		mutex_unlock(&mfi->mutex);
		return -EPERM;
	}
	mfi->task = NULL;

	mutex_unlock(&mfi->mutex);

	mfi_dev_dbg(mfi, "/dev/mfi%d closed\n", mfi->minor);

	return 0;
}

static ssize_t mfi_read(struct file *file, char __user *buf, size_t len,
			loff_t *off)
{
	ssize_t ret = 0;
	struct f_mfi *mfi = cdev_to_mfi(file->f_inode->i_cdev);

	mutex_lock(&mfi->mutex);

	if (mfi_permission_denied(mfi)) {
		mutex_unlock(&mfi->mutex);
		return -EPERM;
	}
	if (!mfi->in_buf_cnt) {
		mutex_unlock(&mfi->mutex);
		return 0;
	}

	mfi_spin_lock(mfi);

	if (unlikely(copy_to_user(buf, mfi->in_buf, mfi->in_buf_cnt))) {
		mfi_dev_warn(mfi, "/dev/mfi%d: copy_to_user\n", mfi->minor);
		ret = 0;
	} else {
		ret = (ssize_t)mfi->in_buf_cnt;
	}

	mfi->in_buf_cnt = 0;
	mfi_recv_async(mfi);

	mfi_spin_unlock(mfi);
	mutex_unlock(&mfi->mutex);

	mfi_dev_dbg(mfi, "/dev/mfi%d: read %d bytes\n", mfi->minor, (int)ret);

	return ret;
}

static ssize_t mfi_write(struct file *file, const char *buf, size_t len,
			 loff_t *off)
{
	int ret = 0;
	struct f_mfi *mfi = cdev_to_mfi(file->f_inode->i_cdev);

	mutex_lock(&mfi->mutex);

	if (mfi_permission_denied(mfi)) {
		mutex_unlock(&mfi->mutex);
		return -EPERM;
	}
	if (!len) {
		mutex_unlock(&mfi->mutex);
		return 0;
	}

	mfi_spin_lock(mfi);

	ret = copy_from_user(mfi->out_buf, buf, len);
	if (unlikely(ret)) {
		mfi_dev_warn(mfi, "/dev/mfi%d: copy_from_user, err = %d\n",
			    mfi->minor, ret);
		ret = 0;
		goto mfi_write_exit;
	}
	mfi->out_buf_cnt = (int)len;

	ret = mfi_send_async(mfi);
	if (unlikely(ret)) {
		mfi_dev_err(mfi, "/dev/mfi%d: mfi_send, err = %d\n", mfi->minor, ret);
		ret = 0;
	} else {
		ret = (int)len;
	}

mfi_write_exit:
	mfi_spin_unlock(mfi);
	mutex_unlock(&mfi->mutex);

	mfi_dev_dbg(mfi, "/dev/mfi%d: wrote %d bytes\n", mfi->minor, (int)len);

	return ret;
}

static __poll_t mfi_poll(struct file *file, poll_table *wait)
{
	__poll_t status = 0;
	struct f_mfi *mfi = cdev_to_mfi(file->f_inode->i_cdev);

	mutex_lock(&mfi->mutex);

	if (mfi_permission_denied(mfi)) {
		status |= EPOLLERR;
		goto mfi_poll_exit;
	}

	mfi_spin_lock(mfi);
	if (mfi->in_buf_cnt) {
		status |= EPOLLIN;
		mfi_spin_unlock(mfi);
		goto mfi_poll_exit;
	}
	mfi_spin_unlock(mfi);

	mfi_dev_vdbg(mfi, "mfi_poll: Waiting for event\n");
	poll_wait(file, &mfi->in_wait, wait);

	mfi_spin_lock(mfi);
	if (likely(mfi->in_buf_cnt))
		status |= EPOLLIN;
	mfi_spin_unlock(mfi);

mfi_poll_exit:
	mutex_unlock(&mfi->mutex);

	mfi_dev_dbg(mfi, "/dev/mfi%d: poll status = %u\n", mfi->minor, status);

	return status;
}

static long mfi_ioctl(struct file *file, unsigned int code, unsigned long arg)
{
	long ret = -EINVAL;
	struct f_mfi *mfi = cdev_to_mfi(file->f_inode->i_cdev);

	mutex_lock(&mfi->mutex);

	if (mfi_permission_denied(mfi)) {
		mutex_unlock(&mfi->mutex);
		return -EPERM;
	}

	switch (code) {
	default:
		break;
	case IOCTL_GADGET_GET_MFI_IN_BUF_CNT:
		mfi_dev_vdbg(mfi,
			     "mfi_ioctl: IOCTL_GADGET_GET_MFI_IN_BUF_CNT\n");
		mfi_spin_lock(mfi);
		ret = mfi->in_buf_cnt;
		mfi_spin_unlock(mfi);
		break;
	case IOCTL_GADGET_GET_MFI_MAX_PACKET_SIZE:
		mfi_dev_vdbg(
			mfi,
			"mfi_ioctl: IOCTL_GADGET_GET_MFI_MAX_PACKET_SIZE\n");
		ret = mfi->out_ep->maxpacket;
		break;
	}

	mutex_unlock(&mfi->mutex);

	mfi_dev_dbg(mfi, "/dev/mfi%d: ioctl status = %ld\n", mfi->minor, ret);

	return ret;
}

static struct file_operations mfi_fops = {
	.owner = THIS_MODULE,
	.open = mfi_open,
	.release = mfi_release,
	.read = mfi_read,
	.write = mfi_write,
	.poll = mfi_poll,
	.unlocked_ioctl = mfi_ioctl,
};

/*-------------------------------------------------------------------------*/

#define MFI_CHRDEV_MINORS_NUM (MAX_MFI_INTERFACES)

static int mfi_major = 0;
static int mfi_interfaces_cnt = 0;
static struct class *mfi_class = NULL;
static bool region_registered = false;
static bool mfi_interfaces_minors[MAX_MFI_INTERFACES];

static inline int mfi_get_first_available_minor(void)
{
	int i;
	for (i = 0; i < MAX_MFI_INTERFACES; ++i) {
		if (!mfi_interfaces_minors[i])
			return i;
	}

	/*
	 * We never reach this point due to mfi_interfaces_limit_reached() check
	 * in mfi_alloc_instance()
	 */
	return -EBUSY;
}

static __always_inline void mfi_occupy_minor(int minor)
{
	mfi_interfaces_minors[minor] = true;
}

static __always_inline void mfi_release_minor(int minor)
{
	mfi_interfaces_minors[minor] = false;
}

static inline int mfi_chrdev_register_region(void)
{
	int err;
	dev_t dev = 0;

	if (region_registered)
		return 0;

	mfi_class = class_create(THIS_MODULE, "mfi");
	if (unlikely(IS_ERR(mfi_class))) {
		err = PTR_ERR(mfi_class);
		mfi_class = NULL;
		return err;
	}

	err = alloc_chrdev_region(&dev, 0, MFI_CHRDEV_MINORS_NUM, "mfi");
	if (unlikely(err)) {
		class_destroy(mfi_class);
		mfi_class = NULL;
		return err;
	}
	mfi_major = MAJOR(dev);

	memset(mfi_interfaces_minors, 0, sizeof(bool) * MAX_MFI_INTERFACES);

	region_registered = true;

	return 0;
}

static inline void mfi_chrdev_unregister_region(void)
{
	if (!region_registered)
		return;

	if (likely(mfi_major)) {
		unregister_chrdev_region(MKDEV(mfi_major, 0),
					 MFI_CHRDEV_MINORS_NUM);
		mfi_major = 0;
	}

	if (likely(mfi_class)) {
		class_destroy(mfi_class);
		mfi_class = NULL;
	}

	region_registered = false;
}

static inline int mfi_chrdev_register(struct f_mfi *mfi)
{
	/* mfi->mutex should be locked before calling this function */

	dev_t devt;
	struct device *pdev;

	int err = mfi_chrdev_register_region();
	if (err < 0) {
		mfi_dev_err(
			mfi,
			"mfi_chrdev_register: mfi_chrdev_register_region, err = %d\n",
			err);
		return err;
	}

	mfi->minor = mfi_get_first_available_minor();
	devt = MKDEV(mfi_major, mfi->minor);
	pdev = device_create(mfi_class, NULL, devt, NULL, "mfi%d",
			     mfi->minor);
	if (unlikely(IS_ERR(pdev))) {
		mfi_dev_err(mfi, "mfi_chrdev_register: device_create\n");
		return PTR_ERR(pdev);
	}

	mfi->minor = MINOR(devt);
	mfi_occupy_minor(mfi->minor);
	mfi_dev_vdbg(mfi, "mfi_chrdev_register: major=%d, minor=%d\n",
		     mfi_major, mfi->minor);

	cdev_init(&mfi->cdev, &mfi_fops);
	mfi->cdev.owner = THIS_MODULE;
	err = cdev_add(&mfi->cdev, devt, 1);
	if (unlikely(err)) {
		mfi_dev_err(mfi, "mfi_chrdev_register: cdev_add, err = %d\n",
			    err);
		device_destroy(mfi_class, devt);
		return err;
	}

	++mfi_interfaces_cnt;

	mfi_dev_info(mfi, "registered /dev/mfi%d character device\n",
		     mfi->minor);

	return 0;
}

static inline void mfi_chrdev_unregister(struct f_mfi *mfi)
{
	/* mfi->mutex should be locked before calling this function */

	device_destroy(mfi_class, MKDEV(mfi_major, mfi->minor));
	cdev_del(&mfi->cdev);

	mfi_release_minor(mfi->minor);
	mfi_dev_vdbg(mfi, "mfi_chrdev_unregister: major=%d, minor=%d\n",
		     mfi_major, mfi->minor);

	--mfi_interfaces_cnt;

	if (!mfi_interfaces_cnt)
		mfi_chrdev_unregister_region();
}

/*-------------------------------------------------------------------------*/

static int mfi_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev = c->cdev;
	struct f_mfi *mfi = func_to_mfi(f);
	struct usb_string *us;
	int id, ret;

	us = usb_gstrings_attach(cdev, mfi_strings, ARRAY_SIZE(strings_mfi));
	if (IS_ERR(us)) {
		mfi_dev_err(mfi, "mfi_bind: usb_gstrings_attach, err = %ld\n",
			    PTR_ERR(us));
		return PTR_ERR(us);
	}
	mfi_intf.iInterface = us[1].id;
	mfi_dev_vdbg(mfi, "mfi_intf.iInterface = %d\n", mfi_intf.iInterface);

	id = usb_interface_id(c, f);
	if (unlikely(id < 0)) {
		mfi_dev_err(mfi, "mfi_bind: usb_interface_id, err = %d\n", id);
		return id;
	}
	mfi_intf.bInterfaceNumber = id;
	mfi_dev_vdbg(mfi, "mfi_intf.bInterfaceNumber = %d\n",
		     mfi_intf.bInterfaceNumber);

	/* allocate endpoints */

	mfi->in_ep = usb_ep_autoconfig(cdev->gadget, &fs_mfi_source_desc);
	if (unlikely(!mfi->in_ep)) {
autoconf_fail:
		mfi_dev_err(mfi, "%s: can't autoconfigure on %s\n", f->name,
			    cdev->gadget->name);
		return -ENODEV;
	}

	mfi->out_ep = usb_ep_autoconfig(cdev->gadget, &fs_mfi_sink_desc);
	if (unlikely(!mfi->out_ep))
		goto autoconf_fail;

	/* support high speed hardware */
	hs_mfi_source_desc.bEndpointAddress =
		fs_mfi_source_desc.bEndpointAddress;
	hs_mfi_sink_desc.bEndpointAddress = fs_mfi_sink_desc.bEndpointAddress;

	/* support super speed hardware */
	ss_mfi_source_desc.bEndpointAddress =
		fs_mfi_source_desc.bEndpointAddress;
	ss_mfi_sink_desc.bEndpointAddress = fs_mfi_sink_desc.bEndpointAddress;

	ret = usb_assign_descriptors(f, fs_mfi_descs, hs_mfi_descs,
				     ss_mfi_descs, ss_mfi_descs);
	if (unlikely(ret))
		return ret;

	mutex_init(&mfi->mutex);
	spin_lock_init(&mfi->lock);

	mfi_spin_lock(mfi);
	mutex_lock(&mfi->mutex);
	ret = mfi_chrdev_register(mfi);
	if (unlikely(ret)) {
		mfi_spin_unlock(mfi);
		mutex_unlock(&mfi->mutex);
		return ret;
	}
	mutex_unlock(&mfi->mutex);

	mfi->in_buf = kzalloc(mfi->out_ep->maxpacket_limit, GFP_KERNEL);
	if (unlikely(NULL == mfi->in_buf))
		goto mfi_bind_chrdev;

	mfi->out_buf = kzalloc(mfi->in_ep->maxpacket_limit, GFP_KERNEL);
	if (unlikely(NULL == mfi->out_buf)) {
		kfree(mfi->in_buf);
		goto mfi_bind_chrdev;
	}

	init_waitqueue_head(&mfi->in_wait);

	mfi_spin_unlock(mfi);

	mfi_dev_dbg(mfi, "%s speed %s: IN/%s, OUT/%s\n",
		    (gadget_is_superspeed(c->cdev->gadget) ?
			     "super" :
			     (gadget_is_dualspeed(c->cdev->gadget) ? "dual" :
								     "full")),
		    f->name, mfi->in_ep->name, mfi->out_ep->name);

	return ret;

mfi_bind_chrdev:
	mutex_lock(&mfi->mutex);
	mfi_chrdev_unregister(mfi);
	mutex_unlock(&mfi->mutex);
	mfi_spin_unlock(mfi);
	return -ENOMEM;
}

static void mfi_free_func(struct usb_function *f)
{
	struct f_mfi *mfi = func_to_mfi(f);

	mfi_spin_lock(mfi);
	if (likely(mfi->in_buf))
		kfree(mfi->in_buf);
	if (likely(mfi->out_buf))
		kfree(mfi->out_buf);
	mutex_lock(&mfi->mutex);
	mfi_chrdev_unregister(mfi);
	mutex_unlock(&mfi->mutex);
	mutex_destroy(&mfi->mutex);
	mfi_spin_unlock(mfi);
	usb_free_all_descriptors(f);
	kfree(mfi);
}

static inline void disable_mfi(struct f_mfi *mfi)
{
	mfi_spin_lock(mfi);
	mfi_free_req(mfi->read_req, mfi->out_ep);
	mfi_free_req(mfi->write_req, mfi->in_ep);
	usb_ep_disable(mfi->in_ep);
	usb_ep_disable(mfi->out_ep);
	mfi_spin_unlock(mfi);
}

static void mfi_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct f_mfi *mfi = req->context;

	switch (req->status) {
	case 0:
		mfi_spin_lock(mfi);
		if (ep == mfi->out_ep) {
			mfi_dev_dbg(mfi, "mfi_complete: received %d bytes\n",
				    req->actual);
			mfi->in_buf_cnt = req->actual;
			memcpy(mfi->in_buf, req->buf, req->actual);
			mfi_free_req(mfi->read_req, ep);
			mfi->read_req = NULL;
			wake_up_interruptible(&mfi->in_wait);
		} else if (ep == mfi->in_ep) {
			mfi_dev_dbg(mfi, "mfi_complete: transmited %d bytes\n",
				    req->actual);
			mfi_free_req(mfi->write_req, ep);
			mfi->write_req = NULL;
		}
		mfi_spin_unlock(mfi);
		break;

	default:
		mfi_dev_err(mfi, "%s mfi_complete --> %d, %d/%d\n", ep->name,
			    req->status, req->actual, req->length);
		fallthrough;

	case -ECONNABORTED: /* hardware forced ep reset */
	case -ECONNRESET: /* request dequeued */
	case -ESHUTDOWN: /* disconnect from host */
		disable_mfi(mfi);
		break;
	}
}

static inline int enable_endpoint(struct usb_composite_dev *cdev,
				  struct f_mfi *mfi, struct usb_ep *ep)
{
	int ret = config_ep_by_speed(cdev->gadget, &(mfi->function), ep);
	if (ret)
		return ret;

	return usb_ep_enable(ep);
}

static inline int enable_mfi(struct usb_composite_dev *cdev, struct f_mfi *mfi)
{
	int ret = 0;

	mfi_spin_lock(mfi);

	ret = enable_endpoint(cdev, mfi, mfi->in_ep);
	if (unlikely(ret))
		goto enable_mfi_exit;

	ret = enable_endpoint(cdev, mfi, mfi->out_ep);
	if (unlikely(ret)) {
		usb_ep_disable(mfi->in_ep);
		goto enable_mfi_exit;
	}

	ret = mfi_recv_async(mfi);
	if (unlikely(ret))
		mfi_dev_warn(
			mfi,
			"enable_mfi: Failed to initiate data receiving, err = %d\n",
			ret);

enable_mfi_exit:
	mfi_spin_unlock(mfi);

	return ret;
}

static int mfi_set_alt(struct usb_function *f, unsigned intf, unsigned alt)
{
	struct usb_composite_dev *cdev = f->config->cdev;

	disable_mfi(func_to_mfi(f));
	return enable_mfi(cdev, func_to_mfi(f));
}

static void mfi_disable(struct usb_function *f)
{
	disable_mfi(func_to_mfi(f));
}

static __always_inline bool mfi_interfaces_limit_reached(void)
{
	return (mfi_interfaces_cnt + 1) > MAX_MFI_INTERFACES;
}

static struct usb_function *mfi_alloc(struct usb_function_instance *fi)
{
	struct f_mfi *mfi = kzalloc(sizeof *mfi, GFP_KERNEL);
	if (unlikely(!mfi))
		return ERR_PTR(-ENOMEM);

	mfi->function.name = "mfi";
	mfi->function.bind = mfi_bind;
	mfi->function.set_alt = mfi_set_alt;
	mfi->function.disable = mfi_disable;
	mfi->function.strings = mfi_strings;
	mfi->function.free_func = mfi_free_func;

	return &mfi->function;
}

static void mfi_attr_release(struct config_item *item)
{
	struct f_mfi_opts *mfi_opts = container_of(
		to_config_group(item), struct f_mfi_opts, func_inst.group);

	usb_put_function_instance(&mfi_opts->func_inst);
}

static struct configfs_attribute *mfi_attrs[] = {
	NULL,
};

static struct configfs_item_operations mfi_item_ops = {
	.release = mfi_attr_release,
};

static const struct config_item_type mfi_func_type = {
	.ct_item_ops = &mfi_item_ops,
	.ct_attrs = mfi_attrs,
	.ct_owner = THIS_MODULE,
};

static void mfi_free_instance(struct usb_function_instance *fi)
{
	struct f_mfi_opts *mfi_opts =
		container_of(fi, struct f_mfi_opts, func_inst);
	kfree(mfi_opts);
}

static struct usb_function_instance *mfi_alloc_instance(void)
{
	struct f_mfi_opts *mfi_opts = NULL;

	if (mfi_interfaces_limit_reached()) {
		pr_err("f_mfi: Limit of MFi interfaces count (=%d) was reached\n",
		       MAX_MFI_INTERFACES);
		return ERR_PTR(-ENOMEM);
	}

	mfi_opts = kzalloc(sizeof(*mfi_opts), GFP_KERNEL);
	if (unlikely(!mfi_opts))
		return ERR_PTR(-ENOMEM);

	mfi_opts->func_inst.free_func_inst = mfi_free_instance;

	config_group_init_type_name(&mfi_opts->func_inst.group, "",
				    &mfi_func_type);

	return &mfi_opts->func_inst;
}

DECLARE_USB_FUNCTION_INIT(mfi, mfi_alloc_instance, mfi_alloc);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Stanislav Yahniukov <pe@yahniukov.com>");
