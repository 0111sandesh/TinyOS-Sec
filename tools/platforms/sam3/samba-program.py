#!/usr/bin/python2

# Script to program the Atmel SAM3U using the sam-ba tool.

import os
import re
import sys
import time
import signal
import optparse
import tempfile
import subprocess

parser = optparse.OptionParser()

parser.add_option("-p", "--port",
        action="store",
        type="string",
        dest="port",
        default="/dev/ttyUSB0",
        help="Port where the SAM3U can be found.")
parser.add_option("-b", "--binfile",
        action="store",
        type="string",
        dest="binfile",
        default="build/sam3u_ek/main.bin.out",
        help="Binary file that should be programmed into the flash.")
parser.add_option("-t", "--target",
        action="store",
        type="string",
        dest="target",
        default="AT91SAM3U4-EK",
        help="Target board type.")
parser.add_option("-c", "--check",
        action="store_true",
        dest="check",
        default=False,
        help="Checks and verifies the programmed flash")
parser.add_option("-r", "--run",
        action="store_true",
        dest="run",
        default=False,
        help="Starts executing the binary after flashing it")
parser.add_option("-s", "--start-addr",
        action="store",
        type="string",
        dest="start_addr",
        default="0x80000",
        help="Determines the start address where the binary is loaded")
parser.add_option("-d", "--debug",
        action="store_true",
        dest="DEBUG",
        default=False,
        help="Set the debug mode.")

(cmdOptions, args) = parser.parse_args()
class samba:
    def __init__(self):
        self.expect_timeout = False

        # check to make sure binary file exists
        if not os.path.isfile(cmdOptions.binfile):
            print '"%s" does not exist. Exiting.' % cmdOptions.binfile
            sys.exit(1)
        # once we switch to python 2.6, we should do this
        #self.f = tempfile.NamedTemporaryFile(delete=False)

        #if sam3s, use different TCL script
        r = re.compile("sam3s")
        matches = r.findall(cmdOptions.target)
        if(len(matches) != 0):
            print "Found SAM3S"

            self.f = file('/tmp/samba.tcl', 'w+')
            self.f.write("""FLASH::Init
        send_file {Flash} "%s" %s 0
        FLASH::ScriptGPNMV 2
        """%(cmdOptions.binfile,cmdOptions.start_addr))
            if cmdOptions.check:
                # verify flash
                print "Verify image"
                self.f.write('compare_file {Flash} "%s" %s 0\n'%(cmdOptions.binfile,cmdOptions.start_addr))
            if cmdOptions.run:
                # automatically run the code after writing
                self.f.write("TCL_Go $target(handle) 0 0\n")
        else:

            if( int(cmdOptions.start_addr, 16) >= 0x80000 and int(cmdOptions.start_addr, 16) < 0x100000):
                flash_id = 0
            else:
                flash_id = 1
            self.f = file('/tmp/samba.tcl', 'w+')
            self.f.write("""FLASH::Init %d
        send_file {Flash %d} "%s" %s 0
        FLASH::ScriptGPNMV 2
        """%(flash_id,flash_id,cmdOptions.binfile,cmdOptions.start_addr))
            if cmdOptions.check:
                # verify flash
                print "Verify image"
                self.f.write('compare_file {Flash %d} "%s" %s 0\n'%(flash_id, cmdOptions.binfile,cmdOptions.start_addr))
            if cmdOptions.run:
                # automatically run the code after writing
                self.f.write("TCL_Go $target(handle) 0 0\n")
        self.f.flush()

        try:
            error = False

            # check if SAMBA bootloader is here
            foundBootloader = False
            while not foundBootloader:
                print "Checking for programmer"
                lsusb_proc = subprocess.Popen('lsusb -d 03eb:6124', shell=True,
                        stdout=subprocess.PIPE)
                r = re.compile("SAMBA bootloader")
                lsusb_proc.wait()
                matches = r.findall(lsusb_proc.stdout.readline())
                if len(matches) == 0:
                    print """\n Couldn't find SAM-BA bootloader device on the USB bus.
     Please close the ERASE jumper on the development kit and reboot the system (hit NRSTB button)!\n"""
                    time.sleep(2)
                else:
                    foundBootloader = True

            print "Programmer Found!"

            print "Programming..."
            #print "Remove ERASE and hit [Enter]"
            #a = raw_input()

            samba_cmd = "DISPLAY=:0 sam-ba %s %s %s"%(cmdOptions.port, cmdOptions.target,
                    self.f.name)
            if(cmdOptions.DEBUG):
                print "DEBUG: ", samba_cmd
            samba_proc = subprocess.Popen(samba_cmd, shell=True, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
            r = re.compile("sam-ba: not found")
            e = samba_proc.stderr.readline()

            if len(r.findall(samba_proc.stderr.readline())) != 0:
                print "Couldn't find 'sam-ba'. Please make sure it is in your PATH!"
                self.cleanup()
                sys.exit(1)
            try:
                self.expect(samba_proc.stdout, "-I- Found processor : at91sam3")
            except RuntimeError:
                print "Couldn't find processor! Make sure the port '%s' is correct."%(cmdOptions.port)
                self.cleanup()
                sys.exit(1)
            try:
                self.expect(samba_proc.stdout, "-I- Command line mode : Execute script file")
            except:
                print "Couldn't execute script!"
                self.cleanup()
                sys.exit(1)
            try:
                self.expect(samba_proc.stdout, "-I- GPNVM1 set")
            except:
                print "Couldn't program the device!"
                self.cleanup()
                sys.exit(1)

            if cmdOptions.check:
                try:
                    self.expect(samba_proc.stdout, "match exactly")
                except:
                    print "Verification failed!"
                    self.cleanup()
                    sys.exit(1)

            if cmdOptions.run:
                print "Done! Your code should be running now."
            else:
                print "Done! Reboot your system (hit NRSTB button)."

        finally:
            pass

    def cleanup(self):
        self.f.close()
        os.unlink(self.f.name)


    def alarmHandler(self, signum, frame):
        self.expect_timeout = True

    # Wait until expected pattern is received on the given filehandle.
    def expect(self, fh, pat, timeout=3):
        r = re.compile(pat)

        expect_found = False

        if (timeout != -1):
            signal.signal(signal.SIGALRM, self.alarmHandler)
            signal.alarm(timeout)

        while (not expect_found and not self.expect_timeout):
            line = fh.readline().strip()
            if cmdOptions.DEBUG:
                print line
                time.sleep(0.1)
            matches = r.findall(line)
            if (len(matches) != 0):
                expect_found = True
                break

        signal.alarm(0)
        if (not expect_found):
            raise RuntimeError, "Did not receive expected pattern '%s'" % pat


if __name__ == "__main__":
    s = samba()

