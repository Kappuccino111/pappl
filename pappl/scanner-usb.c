//
// USB scanner class support for the Printer Application Framework
//
// Copyright © 2019-2021 by Michael R Sweet.
// Copyright © 2010-2019 by Apple Inc.
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//

//
// Include necessary headers...
//

#include "pappl-private.h"
#include <cups/dir.h>
#ifdef __linux
#  include <sys/ioctl.h>
#  include <sys/mount.h>
#  include <sys/syscall.h>
#  include <linux/usb/functionfs.h>
#  include <linux/usb/g_printer.h>
#  include "httpmon-private.h"
#endif // __linux

//
// Local constants...
//

#ifdef __linux
#  define NUM_IPP_USB		3
#  define LINUX_USB_CONTROLLER	"/sys/class/udc"
#  define LINUX_USB_GADGET	"/sys/kernel/config/usb_gadget/g1"
#  define LINUX_IPPUSB_FFSPATH	"/dev/ffs-ippusb%d"
#endif // __linux

//
// Local types...
//

#ifdef __linux
typedef struct _ipp_usb_descriptors_s	// IPP-USB descriptors
{
  struct usb_functionfs_descs_head_v2
		header;			// Descriptor header
  __le32	fs_count;		// Number of full-speed endpoints
  __le32	hs_count;		// Number of high-speed endpoints
  __le32	ss_count;		// Number of super-speed endpoints
  struct
  {
    struct usb_interface_descriptor
			intf;			// Interface descriptor
    struct usb_endpoint_descriptor_no_audio
			ipp_to_device,		// IPP/HTTP requests
			ipp_to_host;		// IPP/HTTP responses
  } __attribute__((packed))
		fs_descs,		// Full-speed endpoints
		hs_descs,		// High-speed endpoints
		ss_descs;		// Super-speed endpoints
} __attribute__((packed)) _ipp_usb_descriptors_t;

typedef struct _ipp_usb_iface_s		// IPP-USB interface data
{
  pthread_mutex_t mutex;		// Mutex for accessing socket
  pappl_scanner_t *scanner;		// Scanner
  _pappl_http_monitor_t monitor;	// HTTP state monitor
  int		number,			// Interface number (0-N)
		ipp_control,		// IPP-USB control file
		ipp_to_device,		// IPP/HTTP requests file
		ipp_to_host,		// IPP/HTTP responses file
		ipp_sock;		// Local IPP socket connection, if any
  http_addrlist_t *addrlist;		// Local socket address
  pthread_t	host_thread,		// Thread ID for "to host" comm
		device_thread;		// Thread ID for "to scanner" comm
} _ipp_usb_iface_t;
#endif // __linux

//
// Local functions...
//

#ifdef __linux
static bool	create_directory(pappl_scanner_t *scanner, const char *filename);
static bool	create_ipp_usb_iface(pappl_scanner_t *scanner, int number, _ipp_usb_iface_t *iface);
static bool	create_string_file(pappl_scanner_t *scanner, const char *filename, const char *data);
static bool	create_symlink(pappl_scannner_t *scanner, const char *filename, const char *destname);
static void	delete_ipp_usb_iface(_ipp_usb_iface_t *data);
static void	disable_usb_scanner(pappl_scanner_t *scanner, _ipp_usb_iface_t *ifaces);
static bool	enable_usb_scanner(pappl_scanner_t *scanner, _ipp_usb_iface_t *ifaces);
static void	*run_ipp_usb_iface(_ipp_usb_iface_t *iface);
#endif // __linux


//
// '_papplScannerRunUSB() ' - Run the USB scanner thread.
//

void *					// O - Thread exit status (not used)
_papplScannerRunUSB(
    pappl_scanner_t *scanner)		// I - Scanner
{
#ifdef __linux
  int		i;			// Looping var
  struct pollfd	data[NUM_IPP_USB + 1];	// USB scanner gadget listeners
  _ipp_usb_iface_t ifaces[NUM_IPP_USB];	// IPP-USB gadget interfaces
  int		count;			// Number of file descriptors from poll()
  pappl_device_t *device = NULL;	// Scanner port data
  char		buffer[8192];		// Scan data buffer
  ssize_t	bytes;			// Bytes in buffer
  time_t	status_time = 0;	// Last port status update
  time_t	device_time = 0;	// Last time moving data...


  scanner->usb_active = enable_usb_scanner(scanner, ifaces);

  if (!scanner->usb_active)
  {
    disable_usb_scanner(scanner, ifaces);
    return (NULL);
  }

  sleep(1);

  if ((data[0].fd = open("/dev/g_printer0", O_RDWR | O_EXCL)) < 0)
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to open USB scanner gadget: %s", strerror(errno));
    disable_usb_scanner(scanner, ifaces);
    return (NULL);
  }

  data[0].events = POLLIN | POLLRDNORM;

  for (i = 0; i < NUM_IPP_USB; i ++)
  {
    data[i + 1].fd     = ifaces[i].ipp_control;
    data[i + 1].events = POLLIN;
  }

  papplLogScanner(scanner, PAPPL_LOGLEVEL_INFO, "Monitoring USB for outgoing scans.");

  while (!scanner->is_deleted && scanner->system->is_running)
  {
    if ((count = poll(data, NUM_IPP_USB + 1, 1000)) < 0)
    {
      papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "USB poll failed: %s", strerror(errno));

      if (scanner->is_deleted || !scanner->system->is_running)
        break;

      sleep(1);
    }
    else if (scanner->is_deleted || !scanner->system->is_running)
    {
      break;
    }
    else if (count > 0)
    {
      papplLogScanner(scanner, PAPPL_LOGLEVEL_DEBUG, "USB poll returned %d, revents=[%d %d %d %d].", count, data[0].revents, data[1].revents, data[2].revents, data[3].revents);

      if (data[0].revents)
      {
        if (!device)
        {
          papplLogScanner(scanner, PAPPL_LOGLEVEL_INFO, "Starting USB scan job.");

          while (!scanner->is_deleted && (device = papplScannerOpenDevice(scanner)) == NULL)
          {
            papplLogScanner(scanner, PAPPL_LOGLEVEL_DEBUG, "Waiting for USB access.");
            sleep(1);
	  }

	  if (scanner->is_deleted || !scanner->system->is_running)
	  {
	    papplScannerCloseDevice(scanner);
	    break;
	  }

          // Start looking for back-channel data and port status
          status_time = 0;
          device_time = time(NULL);
          data[0].events = POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM;
        }

        if ((time(NULL) - status_time) >= 1)
        {
          // Update port status once a second...
          pappl_preason_t reasons = papplDeviceGetStatus(device);
					// Current USB status bits
          unsigned char	port_status = SCANNER_NOT_ERROR | SCANNER_SELECTED;
					// Current port status bits

          if (reasons & PAPPL_PREASON_OTHER)
            port_status &= ~SCANNER_NOT_ERROR;
	  if (reasons & PAPPL_PREASON_MEDIA_JAM)
	    port_status |= 0x40;	// Extension
	  if (reasons & PAPPL_PREASON_COVER_OPEN)
	    port_status |= 0x80;	// Extension

          ioctl(data[0].fd, GADGET_SET_SCANNER_STATUS, (unsigned char)port_status);

          status_time = time(NULL);
        }

        if (data[0].revents & POLLRDNORM)
        {
	  if ((bytes = read(data[0].fd, buffer, sizeof(buffer))) > 0)
	  {
	    device_time = time(NULL);

	    papplLogScanner(scanner, PAPPL_LOGLEVEL_DEBUG, "Read %d bytes from USB port.", (int)bytes);
	    if (scanner->usb_cb)
	    {
	      if ((bytes = (scanner->usb_cb)(scanner, device, buffer, sizeof(buffer), (size_t)bytes, scanner->usb_cbdata)) > 0)
	      {
	        data[0].revents = 0;	// Don't try reading back from scanner

	        if (write(data[0].fd, buffer, (size_t)bytes) < 0)
	          papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to write %d bytes to host: %s", (int)bytes, strerror(errno));
	      }
	    }
	    else
	    {
	      papplDeviceWrite(device, buffer, (size_t)bytes);
	      papplDeviceFlush(device);
	    }
	  }
	  else
	  {
	    if (bytes < 0)
	      papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Read error from USB host: %s", strerror(errno));

	    papplLogScanner(scanner, PAPPL_LOGLEVEL_INFO, "Finishing USB print job.");
	    papplScannerCloseDevice(scanner);
	    device = NULL;
	  }
        }
        else if (data[0].revents & POLLWRNORM)
        {
	  if ((bytes = papplDeviceRead(device, buffer, sizeof(buffer))) > 0)
	  {
	    device_time = time(NULL);
	    papplLogScanner(scanner, PAPPL_LOGLEVEL_DEBUG, "Read %d bytes from scanner.", (int)bytes);
	    if (write(data[0].fd, buffer, (size_t)bytes) < 0)
	      papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to write %d bytes to host: %s", (int)bytes, strerror(errno));
	  }
        }
      }

      // Check for IPP-USB control messages...
      for (i = 0; i < NUM_IPP_USB; i ++)
      {
        if (data[i + 1].revents)
        {
          struct usb_functionfs_event *event;
					// IPP-USB control event

	  if (read(ifaces[i].ipp_control, buffer, sizeof(buffer)) < 0)
	  {
	    papplLogScanner(scanner, PAPPL_LOGLEVEL_WARN, "IPP-USB event read error: %s", strerror(errno));
            continue;
	  }

          event = (struct usb_functionfs_event *)buffer;

	  switch (event->type)
	  {
	    case FUNCTIONFS_BIND :
		papplLogScanner(scanner, PAPPL_LOGLEVEL_DEBUG, "BIND%d", i);
		break;
	    case FUNCTIONFS_UNBIND :
		papplLogScanner(scanner, PAPPL_LOGLEVEL_DEBUG, "UNBIND%d", i);
		break;
	    case FUNCTIONFS_ENABLE :
		papplLogScanner(scanner, PAPPL_LOGLEVEL_DEBUG, "ENABLE%d", i);
		break;
	    case FUNCTIONFS_DISABLE :
		papplLogScanner(scanner, PAPPL_LOGLEVEL_DEBUG, "DISABLE%d", i);
		break;
	    case FUNCTIONFS_SETUP :
		papplLogScanner(scanner, PAPPL_LOGLEVEL_DEBUG, "SETUP%d bRequestType=%d, bRequest=%d, wValue=%d, wIndex=%d, wLength=%d", i, event->u.setup.bRequestType, event->u.setup.bRequest, le16toh(event->u.setup.wValue), le16toh(event->u.setup.wIndex), le16toh(event->u.setup.wLength));
		break;
	    case FUNCTIONFS_SUSPEND :
		papplLogScanner(scanner, PAPPL_LOGLEVEL_DEBUG, "SUSPEND%d", i);
		break;
	    case FUNCTIONFS_RESUME :
		papplLogScanner(scanner, PAPPL_LOGLEVEL_DEBUG, "RESUME%d", i);
		break;
	    default :
		papplLogScanner(scanner, PAPPL_LOGLEVEL_DEBUG, "UNKNOWN%d type=%d", i, event->type);
		break;
	  }
        }
      }
    }
    else
    {
      // No new data, sleep 1ms to prevent excessive CPU usage...
      usleep(1000);
    }

    if (device && (time(NULL) - device_time) > 5)
    {
      // Finish talking to the scanner...
      papplLogScanner(scanner, PAPPL_LOGLEVEL_INFO, "Finishing USB scan job.");
      papplScannerCloseDevice(scanner);
      device = NULL;

      // Stop doing back-channel data
      data[0].events = POLLIN | POLLRDNORM;
    }
  }

  if (device)
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_INFO, "Finishing USB scan job.");
    papplScannerCloseDevice(scanner);
  }

  papplLogScanner(scanner, PAPPL_LOGLEVEL_INFO, "Disabling USB for outgoing scab jobs.");

  disable_usb_scanner(scanner, ifaces);

#else
  (void)scanner;
#endif // __linux

  return (NULL);
}

//
// 'papplScannerSetUSB()' - Set the USB vendor and product IDs for a scanner.
//
// This function sets the USB vendor and product IDs for a scanner as well as
// specifying USB gadget options when the scanner is registered with the USB
// device controller.
//
// The `usb_cb` argument specifies a processing callback that is called for
// every byte of data sent from the USB host and which is responsible for
// interpreting the data, writing data to the device, and handling back-channel
// data.
//
// > Note: USB gadget functionality is currently only available when running
// > on Linux with compatible hardware such as the Raspberry Pi Zero and 4B.
//

void
papplScannerSetUSB(
    pappl_scanner_t   *scanner,		// I - Scanner
    unsigned          vendor_id,	// I - USB vendor ID
    unsigned          product_id,	// I - USB product ID
    pappl_uoptions_t  options,		// I - USB gadget options
    const char        *storagefile,	// I - USB storage file, if any
    pappl_sc_usb_cb_t usb_cb,		// I - USB processing callback, if any
    void              *usb_cbdata)	// I - USB processing callback data, if any
{
  if (scanner)
  {
    // Don't allow changes once the gadget is running...
    if (scanner->usb_active)
    {
      papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "USB gadget options already set, unable to change.");
      return;
    }

    // Update the USB gadget settings...
    pthread_rwlock_wrlock(&scanner->rwlock);

    scanner->usb_vendor_id  = (unsigned short)vendor_id;
    scanner->usb_product_id = (unsigned short)product_id;
    scanner->usb_options    = options;
    scanner->usb_cb         = usb_cb;
    scanner->usb_cbdata     = usb_cbdata;

    free(scanner->usb_storage);

    if (storagefile)
      scanner->usb_storage = strdup(storagefile);
    else
      scanner->usb_storage = NULL;

    pthread_rwlock_unlock(&scanner->rwlock);

    // Start USB gadget if needed...
    if (scanner->system->is_running && scanner->system->default_scanner_id == scanner->scanner_id && (scanner->system->options & PAPPL_SOPTIONS_USB_SCANNER))
    {
      pthread_t	tid;			// Thread ID

      if (pthread_create(&tid, NULL, (void *(*)(void *))_papplScannerRunUSB, scanner))
      {
	// Unable to create USB thread...
	papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to create USB gadget thread: %s", strerror(errno));
      }
      else
      {
	// Detach the main thread from the raw thread to prevent hangs...
	pthread_detach(tid);
      }
    }
  }
}

#ifdef __linux
//
// 'create_directory()' - Create a directory.
//

static bool				// O - `true` on success, `false` otherwise
create_directory(
    pappl_scanner_t *scanner,		// I - Scanner
    const char      *filename)		// I - Directory path
{
  if (mkdir(filename, 0777) && errno != EEXIST)
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to create USB gadget directory '%s': %s", filename, strerror(errno));
    return (false);
  }
  else
    return (true);
}


//
// 'create_ipp_usb()' - Create an IPP-USB gadget instance.
//
// Each instance provides a single socket pair.
//

static bool				// O - `true` on success, `false` otherwise
create_ipp_usb_iface(
    pappl_scanner_t  *scanner,		// I - Scanner
    int              number,		// I - Interface number (0-N)
    _ipp_usb_iface_t *iface)		// O - IPP-USB interface data
{
  char		filename[1024],		// Filename
		destname[1024],		// Destination filename for symlink
		devpath[256];		// Device directory
  _ipp_usb_descriptors_t descriptors;	// IPP-USB descriptors
  struct usb_functionfs_strings_head strings;
					// IPP-USB strings (none)


  // Initialize IPP-USB data...
  pthread_mutex_init(&iface->mutex, NULL);

  _papplHTTPMonitorInit(&iface->monitor);

  iface->scanner        = scanner;
  iface->host_thread    = 0;
  iface->device_thread = 0;
  iface->number         = number;
  iface->ipp_control    = -1;
  iface->ipp_to_device = -1;
  iface->ipp_to_host    = -1;
  iface->ipp_sock       = -1;
  iface->addrlist       = NULL;

  // Start by creating the function in the configfs directory...
  snprintf(filename, sizeof(filename), LINUX_USB_GADGET "/functions/ffs.ippusb%d", number);
  if (!create_directory(scanner, filename))
    return (false);			// Failed

  snprintf(destname, sizeof(destname), LINUX_USB_GADGET "/configs/c.1/ffs.ippusb%d", number);
  if (!create_symlink(scanner, filename, destname))
    return (false);			// Failed

  // Then mount the filesystem...
  snprintf(filename, sizeof(filename), "ippusb%d", number);
  snprintf(devpath, sizeof(devpath), LINUX_IPPUSB_FFSPATH, number);
  if (!create_directory(scanner, devpath))
    return (false);			// Failed

  if (mount(filename, devpath, "functionfs", 0, NULL) && errno != EBUSY)
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to mount USB gadget filesystem '%s': %s", devpath, strerror(errno));
    return (false);
  }

  // Try opening the control file...
  snprintf(filename, sizeof(filename), "%s/ep0", devpath);
  if ((iface->ipp_control = open(filename, O_RDWR)) < 0)
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to open USB gadget control file '%s': %s", filename, strerror(errno));
    return (false);
  }

  // Now fill out the USB descriptors...
  memset(&descriptors, 0, sizeof(descriptors));

  descriptors.header.magic  = htole32(FUNCTIONFS_DESCRIPTORS_MAGIC_V2);
  descriptors.header.flags  = htole32(FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC | FUNCTIONFS_HAS_SS_DESC);
  descriptors.header.length = htole32(sizeof(descriptors));
  descriptors.fs_count      = htole32(3);
  descriptors.hs_count      = htole32(3);
  descriptors.ss_count      = htole32(3);

  descriptors.fs_descs.intf.bLength            = sizeof(descriptors.fs_descs.intf);
  descriptors.fs_descs.intf.bDescriptorType    = USB_DT_INTERFACE;
  descriptors.fs_descs.intf.bNumEndpoints      = 2;
  descriptors.fs_descs.intf.bInterfaceClass    = USB_CLASS_SCANNER;
  descriptors.fs_descs.intf.bInterfaceSubClass = 1;
  descriptors.fs_descs.intf.bInterfaceProtocol = 4; // IPP-USB

  descriptors.fs_descs.ipp_to_device.bLength          = sizeof(descriptors.fs_descs.ipp_to_device);
  descriptors.fs_descs.ipp_to_device.bDescriptorType  = USB_DT_ENDPOINT;
  descriptors.fs_descs.ipp_to_device.bEndpointAddress = 1 | USB_DIR_OUT;
  descriptors.fs_descs.ipp_to_device.bmAttributes     = USB_ENDPOINT_XFER_BULK;

  descriptors.fs_descs.ipp_to_host.bLength          = sizeof(descriptors.fs_descs.ipp_to_host);
  descriptors.fs_descs.ipp_to_host.bDescriptorType  = USB_DT_ENDPOINT;
  descriptors.fs_descs.ipp_to_host.bEndpointAddress = 2 | USB_DIR_IN;
  descriptors.fs_descs.ipp_to_host.bmAttributes     = USB_ENDPOINT_XFER_BULK;

  descriptors.hs_descs.intf.bLength            = sizeof(descriptors.hs_descs.intf);
  descriptors.hs_descs.intf.bDescriptorType    = USB_DT_INTERFACE;
  descriptors.hs_descs.intf.bNumEndpoints      = 2;
  descriptors.hs_descs.intf.bInterfaceClass    = USB_CLASS_SCANNER;
  descriptors.hs_descs.intf.bInterfaceSubClass = 1;
  descriptors.hs_descs.intf.bInterfaceProtocol = 4; // IPP-USB

  descriptors.hs_descs.ipp_to_device.bLength          = sizeof(descriptors.hs_descs.ipp_to_device);
  descriptors.hs_descs.ipp_to_device.bDescriptorType  = USB_DT_ENDPOINT;
  descriptors.hs_descs.ipp_to_device.bEndpointAddress = 1 | USB_DIR_OUT;
  descriptors.hs_descs.ipp_to_device.bmAttributes     = USB_ENDPOINT_XFER_BULK;
  descriptors.hs_descs.ipp_to_device.wMaxPacketSize   = htole16(512);

  descriptors.hs_descs.ipp_to_host.bLength          = sizeof(descriptors.hs_descs.ipp_to_host);
  descriptors.hs_descs.ipp_to_host.bDescriptorType  = USB_DT_ENDPOINT;
  descriptors.hs_descs.ipp_to_host.bEndpointAddress = 2 | USB_DIR_IN;
  descriptors.hs_descs.ipp_to_host.bmAttributes     = USB_ENDPOINT_XFER_BULK;
  descriptors.hs_descs.ipp_to_host.wMaxPacketSize   = htole16(512);

  descriptors.ss_descs.intf.bLength            = sizeof(descriptors.ss_descs.intf);
  descriptors.ss_descs.intf.bDescriptorType    = USB_DT_INTERFACE;
  descriptors.ss_descs.intf.bNumEndpoints      = 2;
  descriptors.ss_descs.intf.bInterfaceClass    = USB_CLASS_SCANNER;
  descriptors.ss_descs.intf.bInterfaceSubClass = 1;
  descriptors.ss_descs.intf.bInterfaceProtocol = 4; // IPP-USB

  descriptors.ss_descs.ipp_to_device.bLength          = sizeof(descriptors.ss_descs.ipp_to_device);
  descriptors.ss_descs.ipp_to_device.bDescriptorType  = USB_DT_ENDPOINT;
  descriptors.ss_descs.ipp_to_device.bEndpointAddress = 1 | USB_DIR_OUT;
  descriptors.ss_descs.ipp_to_device.bmAttributes     = USB_ENDPOINT_XFER_BULK;
  descriptors.ss_descs.ipp_to_device.wMaxPacketSize   = htole16(1024);

  descriptors.ss_descs.ipp_to_host.bLength          = sizeof(descriptors.ss_descs.ipp_to_host);
  descriptors.ss_descs.ipp_to_host.bDescriptorType  = USB_DT_ENDPOINT;
  descriptors.ss_descs.ipp_to_host.bEndpointAddress = 2 | USB_DIR_IN;
  descriptors.ss_descs.ipp_to_host.bmAttributes     = USB_ENDPOINT_XFER_BULK;
  descriptors.ss_descs.ipp_to_host.wMaxPacketSize   = htole16(1024);

  // and the strings (none)...
  memset(&strings, 0, sizeof(strings));
  strings.magic  = htole32(FUNCTIONFS_STRINGS_MAGIC);
  strings.length = htole32(sizeof(strings));

  // Now write the descriptors and strings values...
  if (write(iface->ipp_control, &descriptors, sizeof(descriptors)) < 0)
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to write IPP-USB descriptors to gadget control file '%s': %s", filename, strerror(errno));
    return (false);
  }

  if (write(iface->ipp_control, &strings, sizeof(strings)) < 0)
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to write IPP-USB strings to gadget control file '%s': %s", filename, strerror(errno));
    return (false);
  }

  // At this point the endpoints should be accessible...
  snprintf(filename, sizeof(filename), "%s/ep1", devpath);
  if ((iface->ipp_to_device = open(filename, O_RDONLY)) < 0)
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to open IPP-USB gadget scanner endpoint file '%s': %s", filename, strerror(errno));
    return (false);
  }

  snprintf(filename, sizeof(filename), "%s/ep2", devpath);
  if ((iface->ipp_to_host = open(filename, O_WRONLY)) < 0)
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to open IPP-USB gadget host endpoint file '%s': %s", filename, strerror(errno));
    return (false);
  }

  // Find the address for the local TCP/IP socket...
  if (scanner->system->domain_path)
  {
    // Use UNIX domain socket...
    if ((iface->addrlist = httpAddrGetList(scanner->system->domain_path, AF_LOCAL, "0")) == NULL)
    {
      papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to lookup '%s' for IPP USB gadget: %s", scanner->system->domain_path, cupsLastErrorString());
      return (false);
    }
  }
  else
  {
    // Use localhost TCP/IP port...
    snprintf(filename, sizeof(filename), "%d", scanner->system->port);
    if ((iface->addrlist = httpAddrGetList("localhost", AF_UNSPEC, filename)) == NULL)
    {
      papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to lookup 'localhost:%d' for IPP USB gadget: %s", scanner->system->port, cupsLastErrorString());
      return (false);
    }
  }

  // Start a thread to relay IPP/HTTP messages between USB and TCP/IP...
  if (pthread_create(&iface->device_thread, NULL, (void *(*)(void *))run_ipp_usb_iface, iface))
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to start IPP-USB gadget thread for endpoint %d: %s", number, strerror(errno));
    return (false);
  }

  // If we got this far, everything is setup!
  return (true);
}

//
// 'create_string_file()' - Create a file containing the specified string.
//
// A newline is automatically added as needed.
//

static bool				// O - `true` on success, `false` otherwise
create_string_file(
    pappl_scanner_t *scanner,		// I - Scanner
    const char      *filename,		// I - File path
    const char      *data)		// I - Contents of file
{
  cups_file_t	*fp;			// File pointer


  if ((fp = cupsFileOpen(filename, "w")) == NULL)
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to create USB gadget file '%s': %s", filename, strerror(errno));
    return (false);
  }

  if (!*data || data[strlen(data) - 1] != '\n')
    cupsFilePrintf(fp, "%s\n", data);
  else
    cupsFilePuts(fp, data);

  if (cupsFileClose(fp))
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to create USB gadget file '%s': %s", filename, strerror(errno));
    return (false);
  }

  return (true);
}

//
// 'create_symlink()' - Create a symbolic link.
//

static bool				// O - `true` on success, `false` otherwise
create_symlink(
    pappl_printer_t *scanner,		// I - Scanner
    const char      *filename,		// I - Source filename
    const char      *destname)		// I - Destination filename
{
  if (symlink(filename, destname) && errno != EEXIST)
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to create USB gadget symlink '%s': %s", filename, strerror(errno));
    return (false);
  }
  else
    return (true);
}


//
// 'delete_ipp_usb_iface()' - Delete an IPP-USB gadget interface.
//

static void
delete_ipp_usb_iface(
    _ipp_usb_iface_t *iface)		// I - IPP-USB data
{
  char	devpath[256];			// IPP-USB device path


  if (iface->ipp_control >= 0)
  {
    close(iface->ipp_control);
    iface->ipp_control = -1;
  }

  if (iface->host_thread)
  {
    pthread_cancel(iface->host_thread);
    iface->host_thread = 0;
  }

  if (iface->device_thread)
  {
    pthread_cancel(iface->device_thread);
    iface->device_thread = 0;
  }

  pthread_mutex_destroy(&iface->mutex);

  if (iface->ipp_to_device >= 0)
  {
    close(iface->ipp_to_device);
    iface->ipp_to_device = -1;
  }

  if (iface->ipp_to_host >= 0)
  {
    close(iface->ipp_to_host);
    iface->ipp_to_host = -1;
  }

  if (iface->ipp_sock >= 0)
  {
    close(iface->ipp_sock);
    iface->ipp_sock = -1;
  }

  httpAddrFreeList(iface->addrlist);
  iface->addrlist = NULL;

  snprintf(devpath, sizeof(devpath), LINUX_IPPUSB_FFSPATH, iface->number);
  if (umount(devpath))
    papplLogScanner(iface->scanner, PAPPL_LOGLEVEL_ERROR, "Unable to unmount '%s': %s", devpath, strerror(errno));
}

/
// 'disable_usb_scanner()' - Disable the USB scanner gadget module.
//

static void
disable_usb_scanner(
    pappl_scanner_t  *scanner,		// I - Scanner
    _ipp_usb_iface_t *ifaces)		// I - IPP-USB interfaces
{
  int			i;		// Looping var
  const char		*gadget_dir = LINUX_USB_GADGET;
					// Gadget directory
  char			filename[1024];	// Filename


  snprintf(filename, sizeof(filename), "%s/UDC", gadget_dir);
  if (!create_string_file(scanner, filename, "\n"))
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to create USB gadget file '%s': %s", filename, strerror(errno));
  }

  for (i = 0; i < NUM_IPP_USB; i ++)
    delete_ipp_usb_iface(ifaces + i);

  scanner->usb_active = false;
}




//
// 'enable_usb_scanner()' - Configure and enable the USB scanner gadget module.
//

static bool				// O - `true` on success, `false` otherwise
enable_usb_scanner(
    pappl_scanner_t  *scanner,		// I - Scanner
    _ipp_usb_iface_t *ifaces)		// I - IPP-USB interfaces
{
  int			i;		// Looping var
  const char		*gadget_dir = LINUX_USB_GADGET;
					// Gadget directory
  char			filename[1024],	// Filename
			destname[1024];	// Destination filename for symlinks
  cups_dir_t		*dir;		// Controller directory
  cups_dentry_t		*dent;		// Directory entry
  int			num_devid;	// Number of device ID values
  cups_option_t		*devid;		// Device ID values
  const char		*val;		// Value
  char			temp[1024],	// Temporary string
 			mfg[256],	// Manufacturer
			mdl[256],	// Model name
			sn[256];	// Serial number


  // Get the information for this scanner - vendor ID, product ID, etc.
  num_devid = papplDeviceParseID(scanner->device_id, &devid);

  if (scanner->driver_data.make_and_model[0])
  {
    // Get the make and model from the driver info...
    char	*ptr;			// Pointer into make-and-model

    papplCopyString(mfg, scanner->driver_data.make_and_model, sizeof(mfg));
    if ((ptr = strstr(mfg, "Hewlett Packard")) != NULL)
      ptr += 15;
    else
      ptr = strchr(mfg, ' ');

    if (ptr && *ptr)
    {
      // Split make from model...
      while (*ptr && isspace(*ptr & 255))
        *ptr++ = '\0';

      if (*ptr)
        papplCopyString(mdl, ptr, sizeof(mdl));
      else
        papplCopyString(mdl, "Scanner", sizeof(mdl));
    }
    else
    {
      // No whitespace so assume the make-and-model is just the make and use
      // the device ID for the model (with a default of "Scanner")...
      val = cupsGetOption("MODEL", num_devid, devid);
      if (!val)
        val = cupsGetOption("MDL", num_devid, devid);

      if (val)
        papplCopyString(mdl, val, sizeof(mdl));
      else
        papplCopyString(mdl, "Scanner", sizeof(mdl));
    }
  }
  else
  {
    // Get the make and model from the device ID fields.
    val = cupsGetOption("MANUFACTURER", num_devid, devid);
    if (!val)
      val = cupsGetOption("MFG", num_devid, devid);
    if (!val)
      val = cupsGetOption("MFR", num_devid, devid);

    if (val)
      papplCopyString(mfg, val, sizeof(mfg));
    else
      papplCopyString(mfg, "Unknown", sizeof(mfg));

    val = cupsGetOption("MODEL", num_devid, devid);
    if (!val)
      val = cupsGetOption("MDL", num_devid, devid);

    if (val)
      papplCopyString(mdl, val, sizeof(mdl));
    else
      papplCopyString(mdl, "Scanner", sizeof(mdl));
  }

  val = cupsGetOption("SERIALNUMBER", num_devid, devid);
  if (!val)
    val = cupsGetOption("SN", num_devid, devid);
  if (!val)
    val = cupsGetOption("SER", num_devid, devid);
  if (!val)
    val = cupsGetOption("SERN", num_devid, devid);
  if (!val && (val = strstr(scanner->device_uri, "?serial=")) != NULL)
    val += 8;
  if (!val && (val = strstr(scanner->device_uri, "?uuid=")) != NULL)
    val += 6;

  if (val)
    papplCopyString(sn, val, sizeof(sn));
  else
    papplCopyString(sn, "0", sizeof(sn));

  cupsFreeOptions(num_devid, devid);

  // Modern Linux kernels support USB gadgets through the configfs interface.
  // PAPPL takes control of this interface, so if you need (for example) a
  // serial gadget in addition to the printer gadget you need to specify that
  // with a call to papplPrinterSetUSB.
  //
  // The configfs interface lives under "/sys/kernel/config/usb_gadget/".  The
  // available USB Device Controllers can be found under "/sys/class/udc".  We
  // currently assume there will only be one of those and will expand the USB
  // gadget interface later as needed.
  //
  // The typical directory structure looks like this:
  //
  //   g1/
  //     idVendor (usb_vendor ID as a hex number, e.g. "0x12CD")
  //     idProduct (usb product ID as a hex number, e.g. "0x34AB")
  //     strings/0x409/
  //       manufacturer (manufacturer name string)
  //       product (model name string)
  //       serialnumber (serial number string)
  //     configs/c.1/
  //       symlink to functions/printer.g_printer0
  //     functions/printer.g_printer0
  //       pnp_string (IEEE-1284 device ID string)
  //     UDC (first entry from /sys/class/udc)

  // Create the gadget configuration files and directories...
  if (!create_directory(scanner, gadget_dir))
    return (false);

  snprintf(filename, sizeof(filename), "%s/idVendor", gadget_dir);
  snprintf(temp, sizeof(temp), "0x%04x\n", scanner->usb_vendor_id);
  if (!create_string_file(scanner, filename, temp))
    return (false);

  snprintf(filename, sizeof(filename), "%s/idProduct", gadget_dir);
  snprintf(temp, sizeof(temp), "0x%04x\n", scanner->usb_product_id);
  if (!create_string_file(scanner, filename, temp))
    return (false);

  snprintf(filename, sizeof(filename), "%s/strings/0x409", gadget_dir);
  if (!create_directory(scanner, filename))
    return (false);

  snprintf(filename, sizeof(filename), "%s/strings/0x409/manufacturer", gadget_dir);
  if (!create_string_file(scanner, filename, mfg))
    return (false);

  snprintf(filename, sizeof(filename), "%s/strings/0x409/product", gadget_dir);
  if (!create_string_file(scanner, filename, mdl))
    return (false);

  snprintf(filename, sizeof(filename), "%s/strings/0x409/serialnumber", gadget_dir);
  if (!create_string_file(scanner, filename, sn))
    return (false);

  snprintf(filename, sizeof(filename), "%s/configs/c.1", gadget_dir);
  if (!create_directory(scanner, filename))
    return (false);

  // Create the legacy USB printer gadget...
  snprintf(filename, sizeof(filename), "%s/functions/printer.g_printer0", gadget_dir);
  if (!create_directory(scanner, filename))
    return (false);

  snprintf(filename, sizeof(filename), "%s/functions/printer.g_printer0/pnp_string", gadget_dir);
  if (!create_string_file(scanner, filename, scanner->device_id))
    return (false);

  snprintf(filename, sizeof(filename), "%s/functions/printer.g_printer0/q_len", gadget_dir);
  // Note: Cannot error out on this since q_len cannot be changed once the
  // f_printer module is instantiated - see EMBEDDED.md for details and a patch
#ifdef __COVERITY__
  if (!create_string_file(scanner, filename, "10\n"))
  {
    papplLogPrinter(scanner, PAPPL_LOGLEVEL_DEBUG, "Ignoring q_len error - known Linux bug.");
  }

#else
  create_string_file(printer, filename, "10\n");
#endif // __COVERITY__

  snprintf(filename, sizeof(filename), "%s/functions/printer.g_printer0", gadget_dir);
  snprintf(destname, sizeof(destname), "%s/configs/c.1/printer.g_printer0", gadget_dir);
  if (!create_symlink(scanner, filename, destname))
    return (false);

  // Create the IPP-USB printer gadget...
  for (i = 0; i < NUM_IPP_USB; i ++)
  {
    if (!create_ipp_usb_iface(scanner, i, ifaces + i))
    {
      while (i > 0)
      {
        i --;
        delete_ipp_usb_iface(ifaces + i);
      }

      return (false);
    }
  }

  // Add optional gadgets...
  if (scanner->usb_options & PAPPL_UOPTIONS_ETHERNET)
  {
    // Standard USB-Ethernet interface...
    snprintf(filename, sizeof(filename), "%s/functions/ncm.usb0", gadget_dir);
    if (!create_directory(scanner, filename))
      goto error;

    snprintf(destname, sizeof(destname), "%s/configs/c.1/ncm.usb0", gadget_dir);
    if (!create_symlink(scanner, filename, destname))
      goto error;
  }

  if (printer->usb_options & PAPPL_UOPTIONS_SERIAL)
  {
    // Standard serial port...
    snprintf(filename, sizeof(filename), "%s/functions/acm.ttyGS0", gadget_dir);
    if (!create_directory(scanner, filename))
      goto error;

    snprintf(destname, sizeof(destname), "%s/configs/c.1/acm.ttyGS0", gadget_dir);
    if (!create_symlink(scanner, filename, destname))
      goto error;
  }

  if ((scanner->usb_options & PAPPL_UOPTIONS_STORAGE) && scanner->usb_storage)
  {
    // Standard USB mass storage device...
    snprintf(filename, sizeof(filename), "%s/functions/mass_storage.0", gadget_dir);
    if (!create_directory(scanner, filename))
      goto error;

    snprintf(filename, sizeof(filename), "%s/functions/mass_storage.0/lun.0/file", gadget_dir);
    if (!create_string_file(scanner, filename, scanner->usb_storage))
      goto error;

    if (scanner->usb_options & PAPPL_UOPTIONS_STORAGE_READONLY)
    {
      snprintf(filename, sizeof(filename), "%s/functions/mass_storage.0/lun.0/ro", gadget_dir);
      if (!create_string_file(scanner, filename, "1\n"))
        goto error;
    }

    if (scanner->usb_options & PAPPL_UOPTIONS_STORAGE_REMOVABLE)
    {
      snprintf(filename, sizeof(filename), "%s/functions/mass_storage.0/lun.0/removable", gadget_dir);
      if (!create_string_file(scanner, filename, "1\n"))
        goto error;
    }

    snprintf(filename, sizeof(filename), "%s/functions/mass_storage.0", gadget_dir);
    snprintf(destname, sizeof(destname), "%s/configs/c.1/mass_storage.0", gadget_dir);
    if (!create_symlink(scanner, filename, destname))
      goto error;
  }

  // Then assign this configuration to the first USB device controller
  if ((dir = cupsDirOpen(LINUX_USB_CONTROLLER)) == NULL)
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "Unable to find USB device controller in '%s': %s", LINUX_USB_CONTROLLER, strerror(errno));
    goto error;
  }

  while ((dent = cupsDirRead(dir)) != NULL)
  {
    if (dent->filename[0] != '.' && dent->filename[0])
      break;
  }

  if (!dent)
  {
    papplLogScanner(scanner, PAPPL_LOGLEVEL_ERROR, "No USB device controller in '%s': %s", LINUX_USB_CONTROLLER, strerror(errno));
    cupsDirClose(dir);
    goto error;
  }

  papplLogScanner(scanner, PAPPL_LOGLEVEL_DEBUG, "Using UDC '%s' for USB gadgets.", dent->filename);

  snprintf(filename, sizeof(filename), "%s/UDC", gadget_dir);
  if (!create_string_file(printer, filename, dent->filename))
  {
    cupsDirClose(dir);
    goto error;
  }

  cupsDirClose(dir);

  papplLogScanner(scanner, PAPPL_LOGLEVEL_INFO, "USB printer gadget configured.");

  return (true);

  // If we get here we need to tear down the IPP-USB interfaces...
  error:

  for (i = 0; i < NUM_IPP_USB; i ++)
    delete_ipp_usb_iface(ifaces + i);

  return (false);
}


//
// 'run_ipp_usb_iface()' - Run an I/O thread for IPP-USB.
//
// This function serializes IPP/HTTP requests from the host, relays them to a
// local socket, and then relays the IPP/HTTP response.
//

static void *				// O - Thread exit status
run_ipp_usb_iface(
    _ipp_usb_iface_t *iface)		// I - Thread data
{
  char		devbuf[8192],		// Device buffer
		hostbuf[8192];		// Host buffer
  const char	*hostptr;		// Pointer into buffer
  size_t	hostlen;		// Number of bytes in host buffer
  ssize_t	bytes;			// Bytes read


  papplLogScanner(iface->scanner, PAPPL_LOGLEVEL_INFO, "IPP-USB%d: Starting.", iface->number);

  while (!iface->scanner->is_deleted && iface->scanner->system->is_running)
  {
    // Wait for data from the host...
    if ((bytes = read(iface->ipp_to_device, hostbuf, sizeof(hostbuf))) > 0)
    {
      // Got data from the host, send it to the local socket...
      if (iface->ipp_sock < 0)
      {
        // (Re)connect to the local service...
	if (!httpAddrConnect2(iface->addrlist, &iface->ipp_sock, 10000, NULL))
	{
	  papplLogScanner(iface->scanner, PAPPL_LOGLEVEL_ERROR, "IPP-USB%d: Unable to connect to local socket: %s", iface->number, strerror(errno));
	  goto error;
	}

	papplLogScanner(iface->scanner, PAPPL_LOGLEVEL_INFO, "IPP-USB%d: Opened socket %d.", iface->number, iface->ipp_sock);

        // Initialize the HTTP state monitor...
	_papplHTTPMonitorInit(&iface->monitor);
      }

      // Scan the incoming IPP/HTTP request and relay it to the socket...
      hostptr = hostbuf;
      hostlen = (size_t)bytes;

      while (hostlen > 0)
      {
        if (_papplHTTPMonitorProcessHostData(&iface->monitor, &hostptr, &hostlen) == HTTP_STATUS_ERROR)
        {
	  papplLogScanner(iface->scanner, PAPPL_LOGLEVEL_ERROR, "IPP-USB%d: %s", iface->number, _papplHTTPMonitorGetError(&iface->monitor));
	  close(iface->ipp_sock);
	  iface->ipp_sock = -1;
	  break;
        }
      }

      if (iface->ipp_sock < 0)
        continue;

      // Send the request data to the local service...
      papplLogScanner(iface->scanner, PAPPL_LOGLEVEL_DEBUG, "IPP-USB%d: Sending %d bytes to socket %d.", iface->number, (int)bytes, iface->ipp_sock);

      if (write(iface->ipp_sock, hostbuf, (size_t)bytes) < 0)
      {
	papplLogScanner(iface->scanner, PAPPL_LOGLEVEL_ERROR, "IPP-USB%d: Unable to send data to socket: %s", iface->number, strerror(errno));
	close(iface->ipp_sock);
	iface->ipp_sock = -1;
	continue;
      }

      // If we are ready for a response, read it back...
      if (iface->monitor.state != HTTP_STATE_WAITING && iface->monitor.phase == _PAPPL_HTTP_PHASE_SERVER_HEADERS)
      {
        while (iface->monitor.state != HTTP_STATE_WAITING)
        {
	  do
	  {
	    bytes = read(iface->ipp_sock, devbuf, sizeof(devbuf));
	  }
	  while (bytes < 0 && (errno == EAGAIN || errno == EINTR));

	  if (bytes > 0)
	  {
	    papplLogScanner(iface->scanner, PAPPL_LOGLEVEL_DEBUG, "IPP-USB%d: Returning %d bytes.", iface->number, (int)bytes);

	    if (_papplHTTPMonitorProcessDeviceData(&iface->monitor, devbuf, bytes) == HTTP_STATUS_ERROR)
	    {
	      papplLogScanner(iface->scanner, PAPPL_LOGLEVEL_ERROR, "IPP-USB%d: %s", iface->number, _papplHTTPMonitorGetError(&iface->monitor));
	      goto error;
	    }

	    if (write(iface->ipp_to_host, devbuf, (size_t)bytes) < 0)
	    {
	      papplLogScanner(iface->scanner, PAPPL_LOGLEVEL_ERROR, "IPP-USB%d: Error returning data to host: %s", iface->number, strerror(errno));
	      goto error;
	    }
	  }
	  else if (bytes < 0)
	  {
	    // Close socket...
	    if (errno == EPIPE || errno == ECONNRESET)
	      papplLogScanner(iface->scanner, PAPPL_LOGLEVEL_INFO, "IPP-USB%d: Socket %d closed prematurely.", iface->number, iface->ipp_sock);
	    else
	      papplLogScanner(iface->scanner, PAPPL_LOGLEVEL_ERROR, "IPP-USB%d: Unable to read data from socket: %s", iface->number, strerror(errno));

	    goto error;
	  }
	  else if (bytes == 0)
	  {
	    // Closed connection
	    papplLogScanner(iface->scanner, PAPPL_LOGLEVEL_INFO, "IPP-USB%d: Socket %d closed.", iface->number, iface->ipp_sock);
	    break;
	  }
	}

        // For now, always close socket after a completed request...
        close(iface->ipp_sock);
        iface->ipp_sock = -1;
      }
    }
  }

  error:

  papplLogScanner(iface->scanner, PAPPL_LOGLEVEL_INFO, "IPP-USB%d: Shutting down.", iface->number);

  // Shut down any socket and host thread...
  if (iface->ipp_sock >= 0)
  {
    close(iface->ipp_sock);
    iface->ipp_sock = -1;
  }

  iface->device_thread = 0;

  return (NULL);
}
#endif // __linux

