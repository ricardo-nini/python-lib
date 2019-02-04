#!/usr/bin/python3
# -*- coding: utf-8 -*-

import struct
import enum
import zlib
import socket
import functools
import platform
import threading
import os
import sys
import configparser
import fcntl
import subprocess
import logging
from pathlib import Path, PosixPath
from datetime import datetime

if platform.uname().system == 'Linux':
    import netifaces

_UNSET = object()


# =============================================================================#
class _const:
    class ConstError(TypeError):
        pass

    def __setattr__(self, name, value):
        if name in self.__dict__ and value != self.__dict__[name]:
            raise self.ConstError("Can't rebind const(%s)" % name)
        self.__dict__[name] = value


CONST = _const()

# Equivalent of the _IO('U', 20) constant in the linux kernel.
CONST.USBDEVFS_RESET = ord('U') << (4 * 2) | 20


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
# internal use by crc32f(), crc32(), adler32f() and adler32
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
        Sends the CONST.USBDEVFS_RESET IOCTL to a USB device.

        dev_path - The devfs path to the USB device (under /dev/bus/usb/)
                   See get_teensy for example of how to obtain this.
    """
    fd = os.open(dev_path, os.O_WRONLY)
    try:
        fcntl.ioctl(fd, CONST.USBDEVFS_RESET, 0)
    finally:
        os.close(fd)


# =============================================================================#
def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


# =============================================================================#
def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


# =============================================================================#
class RLogFilter(logging.Filter):
    def __init__(self, names: tuple):
        super().__init__(names)

    def filter(self, record):
        if self.nlen == 0:
            return True
        else:
            for name in self.name:
                if name == record.name:
                    return True
            return False


# =============================================================================#
class RLogHandler(logging.StreamHandler):
    def __init__(self, *args, **kwargs):
        if isinstance(args, tuple) and len(args) > 0:
            a = (args[0],)
            logging.StreamHandler.__init__(self, *a, **kwargs)
            if len(args) > 1 and isinstance(args[1], tuple) and len(args[1]) > 0:
                self.addFilter(RLogFilter(args[1]))
        else:
            logging.StreamHandler.__init__(self, *args, **kwargs)


# =============================================================================#
class RByteType(enum.Enum):
    BYTE8 = 8
    BYTE16 = 16
    BYTE32 = 32
    BYTE64 = 64
    FLOAT = 33
    DOUBLE = 65


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
            raise ValueError('Invalid value of byte!')
        return s

    def add_byte(self, bytetype: RByteType, data, signed=False, bigendian=False):
        s = self.__genpackfmt(bytetype, signed, bigendian)
        self.extend(struct.pack(s, data))

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
        addr = {}
        self.__calcule_bit_addr(bit_index, addr, offset)
        n = self[addr['key']]
        return is_bit(n, addr['value'])

    def set_bit(self, bit_index, offset=0):
        addr = {}
        self.__calcule_bit_addr(bit_index, addr, offset)
        actual = self[addr['key']]
        self[addr['key']] = set_bit(actual, addr['value'])

    def clear_bit(self, bit_index, offset=0):
        addr = {}
        self.__calcule_bit_addr(bit_index, addr, offset)
        actual = self[addr['key']]
        self[addr['key']] = clear_bit(actual, addr['value'])

    def toggle_bit(self, bit_index, offset=0):
        addr = {}
        self.__calcule_bit_addr(bit_index, addr, offset)
        actual = self[addr['key']]
        self[addr['key']] = toggle_bit(actual, addr['value'])

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

    def __calcule_bit_addr(self, bit_index, addr: dict, offset=0):
        rev = False
        if (bit_index < 0):
            rev = True
            bit_index = abs(bit_index) - 1
        b = int(bit_index / 8)
        if len(self) <= b:
            raise IndexError
        addr['value'] = bit_index % 8  # value -> bit
        if rev:
            addr['key'] = len(self) - b - 1  # key -> byte
        else:
            addr['key'] = b + offset  # key -> byte


# =============================================================================#
class RConfigError(Exception):
    def __init__(self, setting):
        self.setting = setting


# =============================================================================#
class RConfig(object):
    lock = threading.Lock()

    def __init__(self, defaults=None, dict_type=configparser._default_dict,
                 allow_no_value=False, *, delimiters=('=', ':'),
                 comment_prefixes=('#', ';'), inline_comment_prefixes=None,
                 strict=True, empty_lines_in_values=True,
                 default_section=configparser.DEFAULTSECT,
                 interpolation=configparser._UNSET, converters=configparser._UNSET):
        self._config = configparser.ConfigParser(defaults=defaults, dict_type=dict_type,
                                                 allow_no_value=allow_no_value, delimiters=delimiters,
                                                 comment_prefixes=comment_prefixes,
                                                 inline_comment_prefixes=inline_comment_prefixes,
                                                 strict=strict, empty_lines_in_values=empty_lines_in_values,
                                                 default_section=default_section,
                                                 interpolation=interpolation, converters=converters)
        self._filename = str()
        self._p0 = PosixPath()
        self._p1 = PosixPath()
        self._names = []

    @property
    def config(self):
        return self._config

    @property
    def path_config(self) -> PosixPath:
        return self._p0

    @property
    def path_config_def(self) -> PosixPath:
        return self._p1

    # raise FileNotFoundError when filename joined with paths not exist
    def read(self, filename: str, paths=None):
        RConfig.lock.acquire()
        try:
            self._filename = filename
            # build paths
            if isinstance(paths, tuple):
                self._paths = paths
            else:
                if paths and isinstance(paths, str):
                    self._paths = (paths,)
                else:
                    self._paths = (os.path.dirname(os.path.abspath(sys.argv[0])),)
            # look for paths to file and file default in order ...
            for path in self._paths:
                p0 = Path(path, self._filename)
                p1 = Path(path, self._add_defatlt_prefix(self._filename))
                if p0.is_file() and p1.is_file():
                    self._load((str(p0), str(p1)))
                    self._p0 = p0
                    self._p1 = p1
                    return
            # look for paths to file in order ...
            for path in self._paths:
                p0 = Path(path, self._filename)
                if p0.is_file():
                    self._load((str(p0),))
                    self._p0 = p0
                    self._p1 = PosixPath()
                    return
            raise FileNotFoundError('file:{} paths:{}'.format(filename, paths))
        finally:
            RConfig.lock.release()

    def write(self):
        RConfig.lock.acquire()
        try:
            if len(self._p0.parents) > 0:
                with open(str(self._p0), 'w') as f:
                    self._config.write(f)
            else:
                raise ValueError('No loaded config.')
        finally:
            RConfig.lock.release()

    def write2default(self):
        RConfig.lock.acquire()
        try:
            if len(self._p1.parents) > 0:
                with open(str(self._p1), 'w') as f:
                    self._config.write(f)
            else:
                raise ValueError('No default loaded config.')
        finally:
            RConfig.lock.release()

    def get_items(self, section) -> dict:
        return dict(self._config.items(section))

    def _load(self, paths: tuple, encoding=None):
        if len(paths) == 2:
            p = [paths[1], paths[0]]
        else:
            p = paths[0]
        self._config.read(p, encoding)

    def _add_defatlt_prefix(self, filename) -> str:
        p = os.path.splitext(filename)
        return p[0] + '.def' + p[1]


# =============================================================================#
class RConfigParms(object):
    def __init__(self, section, rconfig: RConfig, main_section=''):
        self._section = section
        self._rconfig = rconfig
        self._main_section = main_section

    @property
    def section(self):
        return self._section

    @property
    def config(self):
        return self._rconfig.config

    @property
    def rconfig(self):
        return self._rconfig

    @property
    def main_section(self):
        return self._main_section

    def str(self):
        ret = str()
        for c in self._rconfig.config.options(self._section):
            ret = ret + c + '=' + self._rconfig.config.get(self._section, c) + ';'
        return ret
