#!/usr/bin/python3
# -*- coding: utf-8 -*-

import serial
import threading
from rlib.common import RConfig, RConfigParms, RConfigError
from rlib.common import CONST

CONST.DEVICE = 'Device'
CONST.BAUDRATE = 'Baudrate'
CONST.DATABITS = 'Databits'
CONST.PARITY = 'Parity'
CONST.STOPBITS = 'Stopbits'
CONST.TIMEOUT = 'Timeout'


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
class RSerialConfig(RConfigParms):
    def read(self) -> RSerialParms:
        device = self._config.conf.get(self.section, CONST.DEVICE)
        baudrate = self._config.conf.getint(self.section, CONST.BAUDRATE)
        databits = self._config.conf.getint(self.section, CONST.DATABITS)
        parity = self._config.conf.get(self.section, CONST.PARITY)
        stopbits = self._config.conf.getint(self.section, CONST.STOPBITS)
        timeout = self._config.conf.getint(self.section, CONST.TIMEOUT)
        return RSerialParms(device, baudrate, databits, parity, stopbits, timeout)

    def write(self, parms: RSerialParms):
        self._config.conf.set(self.section, CONST.DEVICE, parms.device)
        self._config.conf.set(self.section, CONST.BAUDRATE, parms.baudrate)
        self._config.conf.set(self.section, CONST.DATABITS, parms.databits)
        self._config.conf.set(self.section, CONST.PARITY, parms.parity)
        self._config.conf.set(self.section, CONST.STOPBITS, parms.stopbits)
        self._config.conf.set(self.section, CONST.TIMEOUT, parms.timeout)
        super().write(parms)


# =============================================================================#
class RSerialComm():
    threadLock = threading.Lock()

    def __init__(self, parms: RSerialParms):
        self.parms = parms
        self._serial = None

    def open(self):
        RSerialComm.threadLock.acquire()
        try:
            if self._serial:
                self._serial.close()
            self._serial = serial.Serial(port=self.parms.device,
                                         baudrate=self.parms.baudrate,
                                         bytesize=self.parms.databits,
                                         parity=self.parms.parity,
                                         timeout=self.parms.timeout / 1000)
        except Exception:
            raise
        finally:
            RSerialComm.threadLock.release()

    def close(self):
        RSerialComm.threadLock.acquire()
        try:
            if self.is_open():
                self._serial.close()
        finally:
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
        config = RConfig()
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

    except RConfigError as e:
        print('Error setting "' + e.setting + '"')
    except Exception as e:
        print(str(e))