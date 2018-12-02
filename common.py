#!/usr/bin/python3
# -*- coding: utf-8 -*-

import struct
import enum
import zlib
import socket
import configparser
import functools
import platform
import os
import psutil
import json
import fcntl
import subprocess
from datetime import datetime
from collections import namedtuple

if platform.uname().system == 'Linux':
    import netifaces

# Equivalent of the _IO('U', 20) constant in the linux kernel.
USBDEVFS_RESET = ord('U') << (4 * 2) | 20

snetio = namedtuple('snetio', ['iface',
                               'bytes_sent', 'bytes_recv',
                               'packets_sent', 'packets_recv',
                               'errin', 'errout',
                               'dropin', 'dropout'])

snetiodiff = namedtuple('snetiodiff', ['iface',
                                       'bytes_sent_start', 'bytes_recv_start',
                                       'packets_sent_start', 'packets_recv_start',
                                       'errin_start', 'errout_start',
                                       'dropin_start', 'dropout_start',
                                       'bytes_sent_last', 'bytes_recv_last',
                                       'packets_sent_last', 'packets_recv_last',
                                       'errin_last', 'errout_last',
                                       'dropin_last', 'dropout_last'
                                       ])


# =============================================================================#
# test_bit() returns a nonzero result, 2 power(offset), if the bit at 'offset' is one.
def test_bit(int_type, offset):
    mask = 1 << offset
    return (int_type & mask)


# =============================================================================#
# is_bit() returns True if bit is set, or False if cleared.
def is_bit(int_type, offset):
    return test_bit(int_type, offset) != 0


# =============================================================================#
# set_bit() returns an integer with the bit at 'offset' set to 1.
def set_bit(int_type, offset):
    mask = 1 << offset
    return (int_type | mask)


# =============================================================================#
# clear_bit() returns an integer with the bit at 'offset' cleared.
def clear_bit(int_type, offset):
    mask = ~(1 << offset)
    return (int_type & mask)


# =============================================================================#
# toggle_bit() returns an integer with the bit at 'offset' inverted, 0 -> 1 and 1 -> 0.
def toggle_bit(int_type, offset):
    mask = 1 << offset
    return (int_type ^ mask)


# =============================================================================#
def __zlib_csum(fd, func):
    csum = None
    chunk = fd.read(1024)
    if len(chunk) > 0:
        csum = func(chunk)
        while True:
            chunk = fd.read(1024)
            if len(chunk) > 0:
                csum = func(chunk, csum)
            else:
                break
    if csum is not None:
        csum = csum & 0xffffffff
    return csum


# =============================================================================#
# generate crc32 from file descriptor (zlib)
def crc32f(fd):
    pos = fd.tell()
    crc = __zlib_csum(fd, zlib.crc32)
    fd.seek(pos)
    return crc


# =============================================================================#
# generate crc32 from filename (zlib)
def crc32(filename: str):
    with open(filename, 'rb') as fd:
        return __zlib_csum(fd, zlib.crc32)


# =============================================================================#
# generate adler32 from file descriptor (zlib)
def adler32f(fd):
    pos = fd.tell()
    crc = __zlib_csum(fd, zlib.adler32)
    fd.seek(pos)
    return crc


# =============================================================================#
# generate adler32 from filename (zlib)
def adler32(filename: str):
    with open(filename, 'wb') as fd:
        return __zlib_csum(fd, zlib.adler32)


# =============================================================================#
# test address IPV4
def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
        return address.count('.') == 3
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
            return address.count('.') == 3
        except socket.error:
            return False
    except socket.error:  # not a valid address
        return False


# =============================================================================#
# test address IPV6
def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


# =============================================================================#
# get IPV4 ip from iface
def get_ip_from_iface(iface: str, num=0):
    try:
        return netifaces.ifaddresses(iface)[netifaces.AF_INET][num]['addr']
    except:
        return None


# =============================================================================#
# get IPV4 default gw -> return (IP,iface)
def get_ip_gw(gw='default') -> (str, str):
    try:
        return netifaces.gateways()[gw][netifaces.AF_INET][0], netifaces.gateways()[gw][netifaces.AF_INET][1]
    except:
        return None


# =============================================================================#
# get IPV4 peer from iface
def get_ip_peer_from_iface(iface: str, num=0):
    try:
        return netifaces.ifaddresses(iface)[netifaces.AF_INET][num]['peer']
    except:
        return None


# =============================================================================#
# convert string to boolean
def string2bool(s: str):
    return s.lower() in ['true', '1', 'yes']


# =============================================================================#
# convert DNP3 date to date
def dnp3_2_datetime(octets):
    milliseconds = 0
    for i, value in enumerate(octets):
        milliseconds = milliseconds | (ord(value) << (i * 8))

    date = datetime.utcfromtimestamp(milliseconds / 1000.)
    return date.strftime('%b %d, %Y %H:%M:%S.%f UTC')


# =============================================================================#
# convert date to DNP3 date
def datetime_2_dnp3(date=None):
    if date is None:
        date = datetime.utcnow()
    seconds = (date - datetime(1970, 1, 1)).total_seconds()
    milliseconds = int(seconds * 1000)
    return ''.join(chr((milliseconds >> (i * 8)) & 0xff) for i in range(6))


# =============================================================================#
# convert decimal to BCD
def dec2BCD(inputValue):
    x = str(inputValue)
    BCDOut = 0
    for char in x:
        BCDOut = (BCDOut << 4) + int(char)
    return BCDOut


# =============================================================================#
# get device path by ID
def get_device_path_by_id(id):
    """
        Gets the devfs path to a Teensy microcontroller by scraping the output
        of the lsusb command

        The lsusb command outputs a list of USB devices attached to a computer
        in the format:
            Bus 002 Device 009: ID 16c0:0483 Van Ooijen Technische Informatica Teensyduino Serial
        where ID is:
            16c0:0483
        The devfs path to these devices is:
            /dev/bus/usb/<busnum>/<devnum>
        So for the above device, it would be:
            /dev/bus/usb/002/009
        This function generates that path.
    """
    proc = subprocess.Popen(['lsusb'], stdout=subprocess.PIPE)
    out = proc.communicate()[0]
    lines = out.split(b'\n')
    for line in lines:
        if id in line.decode():
            parts = line.split()
            bus = parts[1].decode()
            dev = parts[3][:3].decode()
            return '/dev/bus/usb/%s/%s' % (bus, dev)
    return None


# =============================================================================#
# reset usb device by device path
def send_usb_reset(dev_path):
    """
        Sends the USBDEVFS_RESET IOCTL to a USB device.

        dev_path - The devfs path to the USB device (under /dev/bus/usb/)
                   See get_teensy for example of how to obtain this.
    """
    fd = os.open(dev_path, os.O_WRONLY)
    try:
        fcntl.ioctl(fd, USBDEVFS_RESET, 0)
    finally:
        os.close(fd)


# =============================================================================#
def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


# =============================================================================#
def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


# =============================================================================#
class RByteType(enum.Enum):
    BYTE8 = 8
    BYTE16 = 16
    BYTE32 = 32
    BYTE64 = 64
    FLOAT = 33
    DOUBLE = 65


# =============================================================================#
class RNetStats(object):
    def __init__(self, filename: str, iface='all', start: bool = False,
                 ramdisk='/dev/shm'):
        self._filename = filename
        self._iface = iface
        self._ramdisk = os.path.join(ramdisk, os.path.basename(filename))
        if start and os.path.isfile(filename):
            with open(filename, 'r') as f:
                a = snetio(*json.load(f))
                self._start_counter(a)
        else:
            self._start_counter(snetio('all', 0, 0, 0, 0, 0, 0, 0, 0))

    @property
    def netstats(self) -> snetio:
        with open(self._ramdisk, 'r') as f:
            r = snetiodiff(*json.load(f))
            a = snetio(
                iface=self._iface,
                bytes_sent=r.bytes_sent_last - r.bytes_sent_start,
                bytes_recv=r.bytes_recv_last - r.bytes_recv_start,
                packets_sent=r.packets_sent_last - r.packets_sent_start,
                packets_recv=r.packets_recv_last - r.packets_recv_start,
                errin=r.errin_last - r.errin_start,
                errout=r.errout_last - r.errout_start,
                dropin=r.dropin_last - r.dropin_start,
                dropout=r.dropout_last - r.dropout_start
            )
            return a

    def update_counter(self):
        with open(self._ramdisk, 'r') as f:
            l = snetiodiff(*json.load(f))
            a = psutil.net_io_counters(pernic=self._iface != 'all', nowrap=True)
            if self._iface != 'all':
                if self._iface in a:
                    a = a[self._iface]
                else:
                    return
            r = snetiodiff(
                iface=self._iface,
                bytes_sent_start=l.bytes_sent_start,
                bytes_recv_start=l.bytes_recv_start,
                packets_sent_start=l.packets_sent_start,
                packets_recv_start=l.packets_recv_start,
                errin_start=l.errin_start,
                errout_start=l.errout_start,
                dropin_start=l.dropin_start,
                dropout_start=l.dropout_start,
                bytes_sent_last=a.bytes_sent,
                bytes_recv_last=a.bytes_recv,
                packets_sent_last=a.packets_sent,
                packets_recv_last=a.packets_recv,
                errin_last=a.errin,
                errout_last=a.errout,
                dropin_last=a.dropin,
                dropout_last=a.dropout
            )
            with open(self._ramdisk, 'w') as f:
                json.dump(r, f)

    def save_counter(self):
        a = self.netstats
        with open(self._filename, 'w') as f:
            json.dump(a, f)

    def load_counter(self) -> snetio:
        if os.path.isfile(self._filename):
            with open(self._filename, 'r') as f:
                return snetio(*json.load(f))
        else:
            return snetio(self._iface, 0, 0, 0, 0, 0, 0, 0, 0)

    def reset_counter(self):
        self._start_counter(snetio(self._iface, 0, 0, 0, 0, 0, 0, 0, 0))

    def _start_counter(self, start: snetio):
        a = psutil.net_io_counters(pernic=self._iface != 'all', nowrap=True)
        if self._iface != 'all':
            if self._iface in a:
                a = a[self._iface]
            else:
                a = snetio('all', 0, 0, 0, 0, 0, 0, 0, 0)
        r = snetiodiff(
            iface=self._iface,
            bytes_sent_start=a.bytes_sent - start.bytes_sent,
            bytes_recv_start=a.bytes_recv - start.bytes_recv,
            packets_sent_start=a.packets_sent - start.packets_sent,
            packets_recv_start=a.packets_recv - start.packets_recv,
            errin_start=a.errin - start.errin,
            errout_start=a.errout - start.errout,
            dropin_start=a.dropin - start.dropin,
            dropout_start=a.dropout - start.dropout,
            bytes_sent_last=a.bytes_sent,
            bytes_recv_last=a.bytes_recv,
            packets_sent_last=a.packets_sent,
            packets_recv_last=a.packets_recv,
            errin_last=a.errin,
            errout_last=a.errout,
            dropin_last=a.dropin,
            dropout_last=a.dropout
        )
        with open(self._ramdisk, 'w') as f:
            json.dump(r, f)


# =============================================================================#
class RPair:
    def __init__(self, value, key):
        self.value = value
        self.key = key

    @classmethod
    def create(cls):
        return cls(0, 0)

    def get_key(self):
        return self.key

    def set_key(self, key):
        self.key = key

    def get_value(self):
        return self.value

    def set_value(self, value):
        self.value = value


# =============================================================================#
class RData(bytearray):
    def dump(self) -> str:
        a = ""
        b = ""
        c = ""
        i = 0
        for d in self:
            if i == 16:
                c += a + " " + b
                c += '\n'
                a = ""
                b = ""
                i = 0
            a += '{:02X} '.format(d)
            if d < 32 or d > 126:
                b += '.'
            else:
                b += chr(d)
            i += 1
        if i != 0:
            a += '   ' * (16 - i)
            b += ' ' * (16 - i)
        c += a + " " + b
        return c

    def __genpackfmt(self, byte: RByteType, signed, bigendian) -> str:
        if byte == RByteType.BYTE8:
            s = 'B'
        elif byte == RByteType.BYTE16:
            if bigendian:
                s = '>'
            else:
                s = '<'
            if signed:
                s += 'h'
            else:
                s += 'H'
        elif byte == RByteType.BYTE32:
            if bigendian:
                s = '>'
            else:
                s = '<'
            if signed:
                s += 'i'
            else:
                s += 'I'
        elif byte == RByteType.BYTE64:
            if bigendian:
                s = '>'
            else:
                s = '<'
            if signed:
                s += 'q'
            else:
                s += 'Q'
        elif byte == RByteType.FLOAT:
            if bigendian:
                s = '>'
            else:
                s = '<'
            s += 'f'
        elif byte == RByteType.DOUBLE:
            if bigendian:
                s = '>'
            else:
                s = '<'
            s += 'd'
        else:
            return None
        return s

    def add_byte(self, bytetype: RByteType, data, signed=False, bigendian=False) -> None:
        s = self.__genpackfmt(bytetype, signed, bigendian)
        self += struct.pack(s, data)

    def get_byte(self, bytetype: RByteType, item, signed=False, bigendian=False):
        s = self.__genpackfmt(bytetype, signed, bigendian)
        return struct.unpack_from(s, self, item)[0]

    def set_byte(self, bytetype: RByteType, item, data, signed=False, bigendian=False) -> None:
        s = self.__genpackfmt(bytetype, signed, bigendian)
        v = struct.pack(s, data)
        if bytetype == RByteType.FLOAT:
            c = RByteType.BYTE32.value
        elif bytetype == RByteType.DOUBLE:
            c = RByteType.BYTE64.value
        else:
            c = bytetype.value
        self[item:item + int(c / 8)] = v[0:int(c / 8)]

    def is_bit(self, bit_index, offset=0) -> bool:
        addr = RPair.create()
        self.__calcule_bit_addr(bit_index, addr, offset)
        n = self[addr.key]
        return is_bit(n, addr.value)

    def set_bit(self, bit_index, offset=0):
        addr = RPair.create()
        self.__calcule_bit_addr(bit_index, addr, offset)
        actual = self[addr.key]
        self[addr.key] = set_bit(actual, addr.value)

    def clear_bit(self, bit_index, offset=0):
        addr = RPair.create()
        self.__calcule_bit_addr(bit_index, addr, offset)
        actual = self[addr.key]
        self[addr.key] = clear_bit(actual, addr.value)

    def toggle_bit(self, bit_index, offset=0):
        addr = RPair.create()
        self.__calcule_bit_addr(bit_index, addr, offset)
        actual = self[addr.key]
        self[addr.key] = toggle_bit(actual, addr.value)

    def put_bit(self, bit_index, bit: bool, offset=0):
        if bit:
            self.set_bit(bit_index, offset)
        else:
            self.clear_bit(bit_index, offset)

    def count_bit(self):
        return len(self) * 8

    def crc32(self):
        return zlib.crc32(self)

    def extract_crc32(self) -> bool:
        b = struct.unpack('<I', bytes(self[-4:]))
        del (self[-4:])
        return b[0] == self.crc32()

    def save_to_file(self, filename):
        with open(filename, 'wb') as f:
            f.write(self)
            f.flush()

    @classmethod
    def read_from_file(cls, filename, sizeblock=1024):
        with open(filename, 'rb') as f:
            x = 0
            b = bytearray()
            for chunk in iter(functools.partial(f.read, sizeblock), ''):
                if not chunk:
                    break
                b[x:] = chunk
                x = x + sizeblock
        return cls(b)

    def __calcule_bit_addr(self, bit_index, addr: RPair, offset=0):
        rev = False
        if (bit_index < 0):
            rev = True
            bit_index = abs(bit_index) - 1
        b = int(bit_index / 8)
        if len(self) <= b:
            raise IndexError
        addr.value = bit_index % 8  # value -> bit
        if rev:
            addr.key = len(self) - b - 1  # key -> byte
        else:
            addr.key = b + offset  # key -> byte


# =============================================================================#
class RConfigError(Exception):
    def __init__(self, setting):
        self.setting = setting


# =============================================================================#
class RConfig:
    def __init__(self, config: configparser.ConfigParser):
        self._config = config

    def get(self, section, option, fallback=None) -> str:
        try:
            r = self._config.get(section, option, fallback=fallback)
        except:
            r = fallback
        return r

    def set(self, section, option, value: str):
        self._config.set(section, option, value)

    def getbool(self, section, option, fallback=None) -> bool:
        try:
            r = self._config.getboolean(section, option, fallback=fallback)
        except:
            r = fallback
        return r

    def setbool(self, section, option, value: bool):
        v = str(value)
        self._config.set(section, option, v)

    def getint(self, section, option, fallback=None) -> int:
        try:
            r = self._config.getint(section, option, fallback=fallback)
        except:
            r = fallback
        return r

    def setint(self, section, option, value: int):
        v = str(value)
        self._config.set(section, option, v)

    def getfloat(self, section, option, fallback=None) -> float:
        try:
            r = self._config.getfloat(section, option, fallback=fallback)
        except:
            r = fallback
        return r

    def setfloat(self, section, option, value: float):
        v = str(value)
        self._config.set(section, option, v)

    def has_section(self, section) -> bool:
        return self._config.has_section(section)

    def has_option(self, section, option) -> bool:
        return self._config.has_option(section, option)


# =============================================================================#
def teste_rdata():
    r = RData()
    for i in range(30):
        r.append(255)
        r.append(3)
        r.append(4)
        r.append(6)
        r.append(65)
        r.append(67)
        r.append(45)
        r.append(20)
        r.append(32)
        r.append(78)
        r.append(100)
        r.append(120)
    print(r.dump())

    r.add_byte(RByteType.BYTE8, 67)
    r.add_byte(RByteType.BYTE16, -32456, True)
    r.add_byte(RByteType.BYTE32, 340992)
    r.add_byte(RByteType.BYTE64, 340992)

    print(r.get_byte(RByteType.BYTE8, 0))
    print(r.get_byte(RByteType.BYTE16, 1))
    print(r.get_byte(RByteType.BYTE32, 3))
    print(r.get_byte(RByteType.BYTE64, 7))

    r.set_byte(RByteType.BYTE8, 1, 129)
    r.set_byte(RByteType.BYTE16, 2, 65533)
    r.set_byte(RByteType.BYTE32, 4, 3998472)
    r.set_byte(RByteType.BYTE64, 8, 1450245273446974212)
    r.set_byte(RByteType.FLOAT, 16, 341.23423)
    r.set_byte(RByteType.DOUBLE, 24, 12123134.235123234)
    print(r.dump())
    print(r.get_byte(RByteType.FLOAT, 16))
    print(r.get_byte(RByteType.DOUBLE, 24))

    d = r.get_byte(RByteType.BYTE8, 0)
    print(d)
    print(r.is_bit(-5))
    r.toggle_bit(-5)
    print(r.is_bit(-5))
    r.toggle_bit(5)
    print(r.dump())

    t = RData([1, 2, 3, 4, 5, 6])
    print(t.dump())


# =============================================================================#
import unittest


class TestCommon(unittest.TestCase):
    def test_rdata(self):
        teste_rdata()


# =============================================================================#
if __name__ == '__main__':
    unittest.main()
