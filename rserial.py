#!/usr/bin/python3
# -*- coding: utf-8 -*-

import serial
import threading
import configparser
import rlib.common as common
import rlib._rserial as CONST


# =============================================================================#
class RSerialParms(object):
    def __init__(self, device, baudrate=9600, databits=8, parity='N', stopbits=1, timeout=300):
        self.device = device
        self.baudrate = baudrate
        self.databits = databits
        self.parity = parity
        self.stopbits = stopbits
        self.timeout = timeout

    def __str__(self) -> str:
        return 'Device:{} Baudrate:{} Databits:{} Parity:{} Stopbits:{} Timeout:{}'.format(self.device,
                                                                                           self.baudrate,
                                                                                           self.databits,
                                                                                           self.parity,
                                                                                           self.stopbits,
                                                                                           self.timeout)


# =============================================================================#
class RSerialConfig(object):
    def __init__(self, section, config: configparser.ConfigParser):
        self._conf = common.RConfig(config)
        self.section = section

    def read(self) -> RSerialParms:
        device = self._conf.get(self.section, CONST.RSERIAL.DEVICE, None)
        if not device:
            raise common.RConfigError(CONST.RSERIAL.DEVICE)
        baudrate = self._conf.getint(self.section, CONST.RSERIAL.BAUDRATE, CONST.RSERIAL.DEF_BAUDRATE)
        databits = self._conf.getint(self.section, CONST.RSERIAL.DATABITS, CONST.RSERIAL.DEF_DATABITS)
        parity = self._conf.get(self.section, CONST.RSERIAL.PARITY, CONST.RSERIAL.DEF_PARITY)
        stopbits = self._conf.getint(self.section, CONST.RSERIAL.STOPBITS, CONST.RSERIAL.DEF_STOPBITS)
        timeout = self._conf.getint(self.section, CONST.RSERIAL.TIMEOUT, CONST.RSERIAL.DEF_TIMEOUT)
        return RSerialParms(device, baudrate, databits, parity, stopbits, timeout)

    def write(self, parms: RSerialParms):
        self._conf.set(self.section, CONST.RSERIAL.DEVICE, parms.device)
        self._conf.setint(self.section, CONST.RSERIAL.BAUDRATE, parms.baudrate)
        self._conf.setint(self.section, CONST.RSERIAL.DATABITS, parms.databits)
        self._conf.set(self.section, CONST.RSERIAL.PARITY, parms.parity)
        self._conf.setint(self.section, CONST.RSERIAL.STOPBITS, parms.stopbits)
        self._conf.setint(self.section, CONST.RSERIAL.TIMEOUT, parms.timeout)


# # =============================================================================#
# class RSerialComm:
#     def __init__(self):
#         self._serial.port = '/dev/ttyAMA0'
#         self._serial.baudrate = 9600
#         self._serial.bytesize = 8
#         self._serial.parity = self.parms.parity
#         self._serial.stopbits = self.parms.stopbits
#         self._serial.timeout = self.parms.timeout / 1000
#
#     @property
#     def port(self):
#         return self._port
#
#     @port.setter
#     def port(self, port):
#         self._port = port
#
#     @property
#     def baudrate(self):
#         return self._baudrate
#
#     @baudrate.setter
#     def baudrate(self, baudrate):
#         self._baudrate = baudrate
#
#     @property
#     def bytesize(self):
#         return self._bytesize
#
#     @bytesize.setter
#     def bytesize(self, bytesize):
#         self._bytesize = bytesize
#
#     @property
#     def parity(self):
#         return self._parity
#
#     @parity.setter
#     def parity(self, parity):
#         self._parity = parity
#
#     @property
#     def stopbits(self):
#         return self._stopbits
#
#     @stopbits.setter
#     def stopbits(self, stopbits):
#         self._stopbits = stopbits
#
#     @property
#     def timeout(self):
#         return self._timeout
#
#     @timeout.setter
#     def timeout(self, timeout):
#         self._timeout = timeout
#
#     def open(self):
#         pass
#
#     def isOpen(self):
#         pass
#
#     def close(self):
#         pass
#
#     def flush(self):
#         pass
#
#     def read(self, size):
#         pass
#
#     def write(self, data):
#         pass
#
#
# =============================================================================#
class RSerialComm:
    threadLock = threading.Lock()

    def __init__(self, parms: RSerialParms):
        self.parms = parms
        self._serial = None
        # self._serial = serial.Serial()

    def open(self):
        RSerialComm.threadLock.acquire()
        try:
            if self._serial:
                self._serial.close()

            # if self._serial.isOpen():
            #     self._serial.close()

            self._serial = serial.Serial(port=self.parms.device,
                                         baudrate=self.parms.baudrate,
                                         bytesize=self.parms.databits,
                                         parity=self.parms.parity,
                                         timeout=self.parms.timeout / 1000)

            # self._serial.port = self.parms.device
            # self._serial.baudrate = self.parms.baudrate
            # self._serial.bytesize = self.parms.databits
            # self._serial.parity = self.parms.parity
            # self._serial.stopbits = self.parms.stopbits
            # self._serial.timeout = self.parms.timeout / 1000
            # self._serial.open()
            RSerialComm.threadLock.release()
        except Exception:
            RSerialComm.threadLock.release()
            raise

    def close(self):
        RSerialComm.threadLock.acquire()
        if self.is_open():
            self._serial.close()
        RSerialComm.threadLock.release()

    def is_open(self):
        if self._serial:
            return self._serial.isOpen()
        else:
            return False

    def flush(self):
        self._serial.flush()

    def flushInput(self):
        self._serial.reset_input_buffer()

    def flushOutput(self):
        self._serial.reset_output_buffer()

    def read(self, size=1):
        return self._serial.read(size)

    def write(self, data):
        return self._serial.write(data)

    def in_waiting(self):
        return self._serial.in_waiting

    def out_waiting(self):
        return self._serial.out_waiting

    def send_break(self, duration=0.25):
        self._serial.sendBreak(duration)


# =============================================================================#
def teste_serial():
    modbus = serial.Serial()
    modbus.port = '/dev/ttyMODBUS'
    modbus.baudrate = 9600
    modbus.bytesize = serial.EIGHTBITS
    modbus.parity = serial.PARITY_NONE
    modbus.stopbits = serial.STOPBITS_ONE
    modbus.timeout = .400

    modbus.open()
    values = bytearray([1, 1, 1, 0, 81, 136])
    modbus.write(values)
    modbus.flush()
    r = []
    while True:
        c = modbus.read()
        if c == b'':
            break
        r.append(c)

    print(r)
    modbus.close()


# =============================================================================#
def teste_rserial():
    try:
        config = configparser.ConfigParser()
        config.read('rserial.ini')
        config_serial = RSerialConfig('Serial', config)
        serial = RSerialComm(config_serial.read())
        serial.open()
        values = bytearray([1, 1, 0, 1, 0, 0xed, 0xd3])
        serial.write(values)
        serial.flush()
        r = []
        while True:
            c = serial.read()
            if c == b'':
                break
            r.append(c)
        print(r)
        serial.close()

        p = config_serial.read()
        p.baudrate = 9600
        config_serial.write(p)
        with open('rserial.ini', 'w') as configfile:
            config.write(configfile)

    except common.RConfigError as e:
        print('Error setting "' + e.setting + '"')
    except Exception as e:
        print(str(e))


# =============================================================================#
import unittest


class TestCommon(unittest.TestCase):
    def test_rserial(self):
        teste_serial()
        teste_rserial()


# =============================================================================#
if __name__ == '__main__':
    # unittest.main()
    teste_rserial()
