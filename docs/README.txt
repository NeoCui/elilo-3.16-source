	--------------------------------------------------------------------
	ELILO.EFI: Linux boot loader for
			EFI/IA-64,EFI/IA-32 and EFI/x86_64 based systems
	--------------------------------------------------------------------
	               Stephane Eranian <eranian@hpl.hp.com>

		                 August 2003

	           Copyright (C) 2000-2012 Hewlett-Packard Co.
	           Copyright (C) 2006-2010 Intel Co.


I/ Introduction
   ------------

This document describes how to use ELILO on for IA-64, IA-32 and x86_64 EFI-based platforms.
This document describes ELILO version 3.7 - 3.14. 

II/ Command line options
    --------------------

	elilo [-hDpPVvaE] [-d nsec] [-C config] [-i initrd] [-c chooser] [kernel [kernel options...]]

	-h	Display a list of all possible command line options.

	-V	Print the version number and exit.

	-d nsec Specify the number of 10th of seconds before loading the
		kernel.

	-C file Specify the config file to use. The default is elilo.conf in the directory
		that elilo.efi was loaded from.

	-P	Verify config file syntax only. this option causes ELILO to 
		parse the config file and generate a report on the console.
		No kernel is loaded.

	-v	Turn on verbose mode. ELILO prints more message about what it 
		is doing. For each occurrence of this option the verbosity level
		is increased by one. The maximum level is 5.

	-a	Always check for alternate kernel image. The default behavior
		of ELILO is to NOT look for an alternate image. This 
		option overrides this behavior and ELILO is checking for 
		alternate images no matter what. Alternate images are
		specified using the EliloAlt EFI variable.

	-p      force interactive prompt mode. Valid when no kernel image is 
		specified on the command line.

	-D	print debug output.

	-E	don't force EDD30 variable to TRUE when FALSE.

	-i file Use file as the initial ramdisk (initrd).

	-c name	Specify which kernel chooser to use.  Default is 'simple', and
		the only other choice at present is 'textmenu'.

	In addition, elilo supports platform specific options:

	For IA-64:
	----------
		-r	the kernel image can be relocated if initial load address is not
			available. This options requires a special version of the kernel.

		-F file will try to load the FPSWA driver indicated by 'file'. Only this file
		        will be attempted. When no specific file is given, elilo will try
			loading \efi\intel firmware\fpswa.efi from all accessible EFI system
			partitions.
	For IA-32:
	----------
		no option defined.

	All file names (including the kernel file) can include a device name using the 
	following syntax:

		dev_name:/path/to/my/kernel

	The 'dev_name' component depends on the naming scheme selected and the detected
	devices for your system.  Some choosers may print the information automatically
	or on demand, see chooser specific documentation for more on this. See README.devschemes 
	for more information on device naming schemes. The slash character '/' can be used as 
	a directory separator on any file systems including the EFI file system (FAT32).

	For x86_64:
	----------
		none

III/ Configuration File
     ------------------

     ELILO supports a config file with options similar to the LILO/x86 boot loader.

     Elilo will use the following sequence (shown in order) when looking for its config 
     file when none is specified on the command line:

	1/ AABBCCDD.conf (netbooting with regular DHCP)
	   where AABBCCDD is the hexadecimal representation
	   of the IP address assigned during the DHCP phase.

	2/ elilo-ia64.conf or elilo-ia32.conf or elilo-x86_64.conf
	   The choice depends on the client platform. This step allows
	   the same DHCP/PXE server to provide files for both types of clients.

	3/ elilo.conf

     Unless explicitly specified on the command line, elilo looks for its config file
     in the filesystem and directory it was loaded from. For instance, if elilo.efi
     is invoked as:

     fs0:\> \efi\debian\elilo.efi

     Then elilo will look for its configuration file in fs0:\efi\debian and not
     in the root directory of fs0:. The prefix fs0:\efi\debian will be used for
     all other files that elilo needs to download when their paths are specified 
     as being relative.

     IMPORTANT:
     This rule also applies when a specific config file is passed via the -C 
     option. For example:

     fs0:\> \efi\debian\elilo.efi -C elilo.conf

     This will look for elilo.conf in fs0:\efi\debian and not in fs0:\.
     To get to the elilo.conf in fs0:\, you need to specify the absolute
     path:

     fs0:\> \efi\debian\elilo.efi -C \elilo.conf


     The configuration file is an ASCII file and not a UNICODE file.

     The config file contains additional options to change the behavior of the loader. 
     If the same option is specified in the config file AND on the command line, the
     latter takes precedence. Not all options available in the config file have an 
     equivalent on command line.

     When elilo is invoked with the -h option, it prints the list of support command line
     options but also the list of config file options. For each option it also prints
     the type of data expected.

     The config file options are divided in 2 groups:


	- image options which are specific to a particular kernel image. Each kernel image
   	  must be identified with a logical name called a label. 

     	- global options which affect the behavior of ELILO and apply to all images.

     The ELILO config file follows the LILO/x86 syntax. First come the global
     options, then the list of images and options for each of them, if
     necessary. At least one image MUST be defined and it is possible to have
     an empty list of global options.

     Options have types. Three types are defined:
     	- boolean: set or not set
	- string : a string of characters which can be quoted if necessary
	- number (in decimal) 
	- filename: a string interpreted as a file name

    
    The config file supports the following options:

    Global Options:
    ---------------
    default=value	Name the default image to boot. If not defined ELILO
    		 	will boot the first defined image.

    timeout=number	The number of 10th of seconds to wait while in
    			interactive mode before auto booting default kernel.
			Default is infinity.

    delay=number	The number of 10th of seconds to wait before
    			auto booting when not in interactive mode. 
			Default is 0.
   
    prompt		Force interactive mode

    verbose=number	Set level of verbosity [0-5]. Default 0 (no verbose)

    root=filename	Set global root filesystem for Linux/ia64

    read-only		Force root filesystem to be mounted read-only

    append=string	Append a string of options to kernel command line

    initrd=filename	Name of initrd file

    image=filename	Define a new image

    chooser=name	Specify kernel chooser to use: 'simple' or 'textmenu'.

    message=filename	a message that is printed on the main screen if supported by 
    			the chooser.

    fX=filename		Some choosers may take advantage of this option to
    			display the content of a file when a certain function
			key X is pressed. X can vary from 1-12 to cover 
			function keys F1 to F12.

    noedd30		do not force the EDD30 EFI variable to TRUE when FALSE. In other
    			words, don't force the EDD30 mode if not set.

    Image options:
    --------------
    root=filename	Set root filesystem for kernel

    read-only		Force root filesystem to be mounted read-only

    append=string	Append a string of options to kernel command line

    initrd=filename	Name of initrd file

    label=string	Logical name of image (used in interactive mode)

    description=string	One line text description of the image.

    IA-64 specific options:
    -----------------------

    Global options:
    ---------------
    fpswa=file          Specify the filename for a specific FPSWA to load. 
			If this option is used then no other file will be tried.

    relocatable		In case of memory allocation error at initial load point of
    			kernel, allow attempt to relocate (assume kernels is relocatable)

    Image options:
    --------------
    relocatable		In case of memory allocation error at initial load point of
    			kernel, allow attempt to relocate (assume this kernel is relocatable)

    IA-32 specific options:
    -----------------------
    legacy-free		Indicate that the host machine does not have a legacy BIOS at all.


    The user can specify a kernel and related kernel options using the image label. Alternatively,
    the user can also specify a kernel file that is not specified in the config file. In any case,
    some of the global options (such as append) are always concatenated to whatever the user type.

    x86_64 specific options:
    -----------------------
    text-mode		elilo>=3.14 boolean, image config option to force text console mode.

IV/ Booting from the local system
    -----------------------------

    The elilo.efi binary must be in an EFI system partition (FAT32). The config
    file, kernel image, and optional initrd ramdisk can be on the same partition
    or even another EFI partition. In the following discussion we assume that all 
    files are on the same EFI partition which is recognized by the EFI shell (nshell) 
    as fs0. The kernel and initrd can be copied from the any linux filesystems to the 
    EFI partition using either the mtools (mcopy) or by mounting the EFI partition as 
    a vfat partition. However you do not really need this because most linux 
    distributions install both files in the EFI partition and mount this partition in /boot/efi.

    To boot a kernel, simply power cycle the machine. Once you get to the EFI
    shell prompt, change to the filesystem that maps to the partition where elilo is.

	Shell> fs0:
	fs0:\>

	You might need to make sure that the Shell Path is set such that it will load
	ELILO from fs0:. You can verify this by typing:
	fs0:\> set
   	path : fs0:\
	
	At this point you can invoke ELILO:

	fs0:\> elilo

	If there is no config file, then it will: 
		- pick up the kernel image named vmlinux if it exists, otherwise it will abort.
		- pass no argument to the kernel.
	
	You can specify the kernel image and its options on the command line.
	For instance you can do:

	fs0:\> elilo vmlinux root=/dev/sda5

	You can specify as many parameters as you want. The syntax follows the kernel
	rule, i.e., list of value pairs (or even single values) separated by space.
	A more complicated example would be:

	fs0:\> elilo -i initrd-2.4.9 vmlinuz-2.4.9 root=/dev/sda2 console=tty0 console="ttyS0,115200n8"

	In this example, notice the double quotes. They are required because the comma is a control
	character for nshell.

    In the case a config file is found, then elilo will behave according to
    the options in that file. However if elilo is invoked with command line options, they
    will be combined or they will override (if conflicting) what is defined in the config file.

    As of version 3.3, elilo is fully compliant with the EFI specification (1.10) with regards
    to where the bootloader (elilo.efi) must be located in the EFI system partition. In 
    section 11.2.1.3 of the EFI1.10 specification, it is said that in order to avoid conflicts
    between various loaders for various OSes or distributions of the same OS, every vendor MUST
    use a dedicated directory: \EFI\vendor\. The bootloader must be placed in this directory.
    This has always been possible as this is a matter of creating the directory and copying
    the elilo.efi file in it. However up until version 3.3, elilo would look for its config file
    and kernel/initrd in the root (/) of the partition it was loaded from. As of version 3.3,
    elilo will now ONLY look for its configuration file FROM THE DIRECTORY IT WAS LOADED FROM. 
    The same applies to the kernel and initrd files unless absolute paths are specified. Let us 
    look at a simple example:

    	- suppose elilo.efi is in \EFI\DIST if fs0:  (for the EFI Shell)

	- if you invoke elilo as follows:

		fs0:\> \efi\dist\elilo -v -p
		default file path: \efi\dist\
		config file      : \efi\dist\elilo.conf
		ELILO boot: 


	  Note that this is the same if you invoke elilo directly from \efi or \efi\dist.
 
    File references in the configuration file are treated as relative to the directory
    elilo was loaded from except if they use an absolute path. 

   As of version 3.4 a similar rule applies to the network boot sequence, see netbooting.txt
   for details.

V/ Interactive mode
   ----------------

   Elilo can be forced into interactive mode using the "prompt" option in the config
   file or with the -p option. In this mode, the user can select a kernel to load.

   The interface depends on the chooser, it may be a simple command line prompt as provided
   by the simple chooser or a more sophisticated screen with scroll menus as provided by
   textmenu. Most choosers depends on the elilo config file to get the information they
   display. The simple chooser can operated without the elilo config file. However it
   is always better to have this file, to create handy logical names for each possible
   boot choices. The logical names are specified with the "label" option in the config
   file. They represent a specific kernel "image" and its specific options.

   In elilo, the user can select a particular kernel image using the corresponding label
   name. A simple example is as follows:

      If we suppose that the following is defined in elilo.conf:

      	image=vmlinuz-2.4.9
	label=linux-up
	initrd=initrd-2.4.9
	root=/dev/sda2
	append="console=tty0 console=ttyS0,115200n8"

      then the user can specify linux-up at the prompt and elilo will load the 
      vmlinuz-2.4.9 kernel file and the initrd-2.4.9 ramdisk and will pass 

         "root=/dev/sda2 console=tty0 console=ttyS0,115200n8"

      as command line arguments to the kernel.

      This behavior is identical to Lilo/x86. However, elilo further allows the user
      to specify actual kernel files names as well, i.e., kernels that are not defined
      in the configuration file. If we reuse the above example and the simple chooser, 
      the user can type:

      ELILO boot: vmlinux-2.4.18 root=/dev/sda2

      and elilo will boot the vmlinuz-2.4.18 kernel if it exists.

VI/ The alternate kernel image
    --------------------------

    Oftentimes when debugging kernels you want to reboot the machine once with
    your test kernel and, if something goes wrong, you want to fall back to a more
    stable kernel. In addition you want to be able to do this from a remote machine. 
    Many things can go wrong when doing kernel debugging. It could be that you don't
    even reach user-mode. In this case however, you still want to fall back to
    a stable kernel. The feature you'd like from a boot loader is 'boot once and
    then fall back to safe kernel'.

    Elilo offers this feature and it's called 'alternate kernel image'.  
    You can configure elilo to load a kernel only once and then whatever 
    happens the next reboot falls back to a different kernel hopefully more stable.

    To do this, elilo relies on an EFI variable called 'EliloAlt' with a NULL GUID.
    The content of this variable is a UNICODE string containing the kernel file name
    and its command line options.

    When the -a option is specified on the command line or if the "checkalt" option
    is present in the config file, elilo will check for the presence of this variable.
    If found and the content is a valid UNICODE string, elilo will use it as the kernel
    to boot. There is no verification made on the validity of the kernel name or options.
    Then the variable is deleted. If the variable is rejected because it does not look
    sane, it is also deleted.

    The variable can be set from a running Linux system using the /proc/efi/vars
    interface. In the tools directory of this package, there is a Linux tool called
    elilovar which can be used to create, modify, print, and delete the EliloAlt
    variable. Refer to eliloalt.txt for more information on this tool.

VII/ Auto booting the machine
     -----------------------

    Once you're satisfied with your machine setup, it is good to install an 
    auto boot procedure.  You have two options to do this:
    	- from the EFI boot manager menu
	- from the EFI shell

    The first option is preferred and is used by most Linux distributions.
    Elilo can be invoked directly from the boot manager. You need to get into
    the 'boot maintenance' menu and use load file a file. This can be tedious
    so instead it is recommended that you use a Linux tool called efibootmgr
    which is also shipped in most distributions. With this tool, you can
    create your own boot option and change the boot order.

    
    
    The second approach use the EFI shell and a shell script with a special name: 'startup.nsh'.

    When the system boots, it looks for EFI partitions and if it finds
    a 'startup.nsh' file in ANY of these it will jumpstart execution from it.

    So the typical way of auto booting your Linux/ia64 system is to simply create
    such a file with the following content:

	# cat /boot/startup.nsh
	elilo vmlinuz root=/dev/sda2

    Of course, this can be simplified if there is a configuration file.


VII/ Netbooting 
     ----------

     Please refer to netbooting.txt for a complete description of how to boot
     from the network.


XII/ Booting on EFI/ia32 platforms
     -----------------------------

	Until PC comes with the EFI firmware built in, you need to boot from a
	floppy that has the EFI firmware on it. Such floppy can be
	constructed from the EFI sample implementation and toolkit that is
	available from the Intel Developer Web site at:

		http://developer.intel.com/technology/efi/

	To use elilo on IA-32, you can put it on a floppy and
	on a FAT32 partition (msdos partition). You can also
	netbooting if you network adapter has support for UNDI/PXE.

	Elilo/ia32 is capable of booting unmodified 2.2.x. and 2.4.x kernels
	as they are shipped by distributors today (such as Redhat7.2). You don't need 
	to recompile the kernel with special options. Elilo ONLY takes compressed kernel
	image which are typically obtained via a 'make bzImage'. Plain elf/32 kernel can't 
	be booted (plain vmlinux will not work). Similarly, existing initial ramdisks can 
	be used without modifications. 

XIII/ Booting on EFI/x86_64 platforms
     -----------------------------

	To use elilo on x86_64, you can put it on a floppy and
	on a FAT32 partition (msdos partition). You can also
	netboot if your network adapter has support for UNDI/PXE.

	Elilo/x86_64 requires efi64 enabled linux kernel (> 2.6.21).
	You need to compile the kernel with CONFIG_EFI option.
	x86_64 platforms with UEFI 2.0 firmware deprecate UGA protocol
	and therefore only the Graphics Output Protocol (GOP) is supported. For
	such platforms, the kernel must be configured with EFI_FB option. This
	will enable early boot messages on the console. The elilo for x86_64
	attempts to query the firmware for GOP and if it fails it defaults to
	text mode. Elilo ONLY takes compressed kernel image which are
	typically obtained via a 'make bzImage'. Plain elf/x86_64 kernel can't 
	be booted (plain vmlinux will not work). Similarly, existing initial
	ramdisks can be used without modifications. 

	The x86_64 implementation converts the EFI memory map into E820 map and
	passes it in the bootparameter supplied to the OS. For details on
	bootparameter, see x86_64/sysdeps.h.

IX/ Credits
    -------

	Contributors:
	Intel Corp.
	Stephane Eranian <eranian@hpl.hp.com>
	David Mosberger  <davidm@hpl.hp.com>
	Johannes Erdfelt <jerdfelt@valinux.com>
	Richard Hirst    <rhirst@linuxcare.com>
	Chris Ahna	 <christopher.j.ahna@intel.com>
	Mike Johnston	 <michael.johnston@intel.com>
	Fenghua Yu	 <fenghua.yu@intel.com>
	Bibo Mao	 <bibo.mao@intel.com>
	Brett Johnson	 <brett@hp.com>
	Jason Fleischli	 <Jason.Fleischli@hp.com>
	Chandramouli Narayanan <mouli@linux.intel.com>
	
	Maintainers:
	Jason Fleischli	 <Jason.Fleischli@hp.com>

X/ Bug reports
   -----------

	Use the sourceforge bug submission system on the elilo sourceforge
	project page for reporting including errors or descrepancies in this
	document.

XIII/ Reference
      ---------

	UEFI 2.0 specifications are available from the following web site:

		http://www.uefi.org/home

	EFI v1.02 specifications are available from the following web site:

	http://developer.intel.com/technology/efi/

	The latest sources of ELILO can be downloaded at:

	https://sourceforge.net/projects/elilo/files/

