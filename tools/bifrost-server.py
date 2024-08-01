#!/usr/bin/python
#
# BIFROST Server
# (c) Florian Roth - BSK Consulting GmbH
#
#
# This is bifrost server v1 that can be used on your own servers
# ASGARD uses v2

serverVersion = "v1.0 June 2016"

import os
import socket
import sys
import traceback
import zipfile
import zlib
import argparse
import hashlib
import datetime
import time
import signal


class BifrostServer(object):
    def __init__(self, ip, port, qdir):

        # New socket
        s = socket.socket()
        # Prepare Values
        if ip == "auto":
            local_ip = getIPaddress()
        else:
            local_ip = ip
        self.qdir = qdir
        # Bind to address
        print "Binging socket to %s %s" % (local_ip, port)
        s.bind((local_ip, int(port)))
        s.listen(2000)  # Accept up to x concurrent connections
        maxbytes = 10000000

        # Main loop
        while True:

            # Open Socket --------------------------------------------------------------
            sc, address = s.accept()
            print "".ljust(80, "-")
            print "New socket connection from: ", address

            # Disable the security block feature
            securityBlock = False

            try:
                # Receive header -------------------------------------------------------
                header = sc.recv(1024)
                print header
                try:
                    # Reading header values and normalizing them
                    (system, system_time, filename, path, ctime, mtime, atime, padding) = header.split(";")

                    print "SYSTEM: %s SYSTIME: %s FILE: %s PATH: %s CTIME: %s MTIME: %s ATIME: %s" % (
                        removeNonAsciiDrop(system), removeNonAsciiDrop(system_time), removeNonAsciiDrop(filename),
                        removeNonAsciiDrop(path), removeNonAsciiDrop(str(ctime)), removeNonAsciiDrop(str(mtime)),
                        removeNonAsciiDrop(str(atime)))

                    system = removeNonAsciiDrop(system)
                    system_time = removeNonAsciiDrop(system_time)
                    filename = removeNonAsciiDrop(os.path.basename(filename))
                    path = removeNonAsciiDrop(path)
                    ctime = removeNonAsciiDrop(str(ctime))
                    mtime = removeNonAsciiDrop(str(mtime))
                    atime = removeNonAsciiDrop(str(atime))

                    content_comp = ""
                    bytes = header  # first input

                except Exception, e:
                    traceback.print_exc()
                    self.securityDisconnect(sc, "Header error - security block")
                    continue

                # Receive the rest of the file -----------------------------------------
                while bytes:
                    # Receive file
                    bytes = sc.recv(1024)
                    # Write file
                    sys.stdout.write(".")
                    content_comp += bytes
                    if len(content_comp) > maxbytes:
                        securityBlock = True
                        break

                # If a security error occurred - kill socket and start over
                if securityBlock:
                    sc.close()
                    continue

                # Decompress file data -------------------------------------------------
                try:
                    # decompress received data to compress it again
                    content = zlib.decompress(content_comp)
                except Exception, e:
                    self.securityDisconnect(sc, "Content error - is not compressed or malformed - security block")
                    continue

                # Write the file -------------------------------------------------------
                try:
                    # Creating values from raw data
                    md5_h = hashlib.md5()
                    sha_h = hashlib.sha1()
                    md5_h.update(content)
                    sha_h.update(content)
                    md5 = md5_h.hexdigest().lower()
                    sha1 = sha_h.hexdigest().lower()

                    # Output file preparation
                    output_file = '%s_%s_%s' % (
                        removeNonAsciiDrop(system), removeNonAsciiDrop(filename).replace(".", "_"), md5)
                    print "\nOutput File: %s.zip" % output_file

                    # Creating zip file
                    f = zipfile.ZipFile(r'%s.zip' % (os.path.join(self.qdir, output_file)), mode='w',
                                        compression=zipfile.ZIP_DEFLATED)  # open in binary

                    # Prepare meta data text file with all information
                    metaData = "=== BIFROST Meta Data on File\n"
                    metaData += "Bifrost Server Version       : %s\n" % serverVersion
                    metaData += "Bifrost Server running on    : %s %s\n" % (local_ip, port)
                    metaData += "Bifrost Client sent from     : %s %s\n" % (str(address[0]), str(address[1]))
                    metaData += "Bifrost Server received time : %s\n\n" % getTimeStamp()
                    metaData += "=== Server Information\n"
                    metaData += "Server Time           : %s\n\n" % system_time
                    metaData += "=== File Information\n"
                    metaData += "File Name             : %s\n" % filename
                    metaData += "File Size             : %s\n" % len(content)
                    metaData += "MD5                   : %s\n" % md5
                    metaData += "SHA1                  : %s\n" % sha1
                    metaData += "Output File Name      : %s\n" % output_file
                    metaData += "Source System         : %s\n" % system
                    metaData += "Path on Source System : %s\n" % path
                    metaData += "Creation Date         : %s\n" % epoch2date(ctime)
                    metaData += "Modification Date     : %s\n" % epoch2date(mtime)
                    metaData += "Access Date           : %s\n" % epoch2date(atime)
                    metaData += "First Bytes (hex)     : %s\n" % content[:28].encode('hex')
                    metaData += "First Bytes (ascii)   : %s\n" % removeNonAsciiDrop(content[:56])

                    # Write ZIP file
                    # Suspicious Content
                    f.writestr(output_file, content)
                    # Information sent via bifrost
                    f.writestr("info.txt", metaData)
                    f.close()
                    print "File written: %s bytes" % len(content_comp)

                except Exception, e:
                    traceback.print_exc()
                    self.securityDisconnect(sc, "Error while writing the file")
                    continue

                # Socket Connection Close
                sc.close()

            except Exception, e:
                traceback.print_exc()
            finally:
                if sc:
                    sc.close()

        # Socket Close
        s.close()

    def securityDisconnect(self, rSocket, message):
        print message
        rSocket.close()


def removeNonAsciiDrop(string):
    nonascii = "error"
    # print "CON: ", string
    try:
        # Generate a new string without disturbing characters
        nonascii = "".join(i for i in string if ord(i) < 127 and ord(i) > 31)

    except Exception, e:
        traceback.print_exc()
        pass
    # print "NON: ", nonascii
    return nonascii


def getIPaddress():
    ip = "localhost"
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception, e:
        traceback.print_exc()
        pass
    return ip


def getTimeStamp(date_obj=None):
    if not date_obj:
        date_obj = datetime.datetime.now()
    date_str = date_obj.strftime("%Y-%m-%d %H:%M:%S")
    return date_str


def epoch2date(epoch):
    try:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(epoch)))
    except Exception, e:
        traceback.print_exc()
        print "Error converting epoch %s to a date"
        return "1999-01-01 00:00:00"


# CTRL+C Handler --------------------------------------------------------------
def signal_handler(signal, frame):
    print "------------------------------------------------------------------------------\n"
    print "The BIFROST has been closed."
    sys.exit(0)


if __name__ == '__main__':
    # Signal handler for CTRL+C
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='Bifrost')
    parser.add_argument('-d', help='Quarantine directory', metavar='out-dir', default=".")
    parser.add_argument('-i', help='IP address to bind to', metavar='ip', default="auto")
    parser.add_argument('-p', help='Port to bind to (tcp, default 1400)', metavar='port', default="1400")
    args = parser.parse_args()

    bfServer = BifrostServer(args.i, args.p, args.d)
