#!/usr/bin/python3
# -*- coding: utf-8 -*-

import enum
import struct
import time
from rlib.common import RData, RByteType, RConfigError, RConfig, _const, CONST
from rlib.rserial import RSerialComm, RSerialConfig, RSerialParms
from configparser import ExtendedInterpolation

RMODBUS = _const()

RMODBUS.INITIAL_MODBUS = 0xFFFF
RMODBUS.INITIAL_DF1 = 0x0000

RMODBUS.DEFAULT = 0
RMODBUS.SLAVE = 0
RMODBUS.FUNCTION = 1
RMODBUS.ADDR = 2
RMODBUS.QTY = 4
RMODBUS.COIL = 4
RMODBUS.REGISTER = 4
RMODBUS.SUBFUNC = 2
RMODBUS.DATADIAG = 4
RMODBUS.QUERY_BYTECOUNT = 6
RMODBUS.RESPONSE_BYTECOUNT = 2
RMODBUS.EXCEPTION = 2

RMODBUS.COIL_TRUE = 0xff00
RMODBUS.COIL_FALSE = 0x0000

RMODBUS.SIZE_3 = 3
RMODBUS.SIZE_7 = 7
RMODBUS.SIZE_6 = 6

RMODBUS.EXCEPTION_ITEM_NOT_EXIST = 0
RMODBUS.EXCEPTION_NOT_APPLICABLE = 1
RMODBUS.EXCEPTION_INVALID_DATA = 2
RMODBUS.EXCEPTION_INVALID_CRC = 3
RMODBUS.EXCEPTION_INVALID_FUNCTION = 4
RMODBUS.EXCEPTION_INVALID_SIZE = 5
RMODBUS.EXCEPTION_INVALID_BYTECOUNT = 6
RMODBUS.EXCEPTION_NO_ANSWER = 7
RMODBUS.EXCEPTION_UNKNOWN = 8
RMODBUS.EXCEPTION_NOT_USEFUL = 9
RMODBUS.EXCEPTION_MESSAGE = 10
RMODBUS.EXCEPTION_BUFFER_OVERFLOW = 11

RMODBUS.EXCEPTION_DIC = {
    RMODBUS.EXCEPTION_ITEM_NOT_EXIST: "Item not exist",
    RMODBUS.EXCEPTION_NOT_APPLICABLE: "Not applicable",
    RMODBUS.EXCEPTION_INVALID_DATA: "Invalid data",
    RMODBUS.EXCEPTION_INVALID_CRC: "Invalid CRC",
    RMODBUS.EXCEPTION_INVALID_FUNCTION: "Invalid function",
    RMODBUS.EXCEPTION_INVALID_SIZE: "Invalid size",
    RMODBUS.EXCEPTION_INVALID_BYTECOUNT: "Invalid bytecount",
    RMODBUS.EXCEPTION_NO_ANSWER: "No answer",
    RMODBUS.EXCEPTION_UNKNOWN: "Unknown error",
    RMODBUS.EXCEPTION_NOT_USEFUL: "Not useful",
    RMODBUS.EXCEPTION_MESSAGE: "Message exception received",
    RMODBUS.EXCEPTION_BUFFER_OVERFLOW: "Receive buffer overflow"
}

RMODBUS.CRC_TABLE = (
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040)

CONST.RECV_BUFFER = 'RecvBuffer'


# =============================================================================#
def calc_byte(ch, crc):
    """Given a new Byte and previous CRC, Calc a new CRC-16"""
    if type(ch) == type("c"):
        by = ord(ch)
    else:
        by = ch
    crc = (crc >> 8) ^ RMODBUS.CRC_TABLE[(crc ^ by) & 0xFF]
    return (crc & 0xFFFF)


# =============================================================================#
def calc_string(st, crc):
    """Given a binary string and starting CRC, Calc a final CRC-16 """
    for ch in st:
        crc = (crc >> 8) ^ RMODBUS.CRC_TABLE[(crc ^ ord(ch)) & 0xFF]
    return crc


# =============================================================================#
def calc_crc(rdata: RData):
    crc = RMODBUS.INITIAL_MODBUS
    for ch in rdata:
        crc = calc_byte(ch, crc)
    return crc


# =============================================================================#
def add_crc(rdata: RData):
    crc = calc_crc(rdata)
    var = struct.pack('H', crc)
    rdata.append(var[0])
    rdata.append(var[1])


# =============================================================================#
def valida_crc(rdata: RData):
    if len(rdata) > 2:
        ldata = RData(rdata)
        b = bytearray()
        hi = ldata.pop()
        lo = ldata.pop()
        b.append(lo)
        b.append(hi)
        crc = calc_crc(ldata)
        return crc == struct.unpack('H', bytes(b))[0]
    else:
        return False


# =============================================================================#
def valida_crc_extract(rdata: RData):
    if len(rdata) > 2:
        b = bytearray()
        hi = rdata.pop()
        lo = rdata.pop()
        b.append(lo)
        b.append(hi)
        crc = calc_crc(rdata)
        return crc == struct.unpack('H', bytes(b))[0]
    else:
        return False


# =============================================================================#
class RModbusFunction(enum.Enum):
    READ_COIL_STATUS = 1
    READ_INPUT_STATUS = 2
    READ_HOLDING_REGISTER = 3
    READ_INPUT_REGISTER = 4
    FORCE_SINGLE_COIL = 5
    PRESET_SINGLE_REGISTER = 6
    DIAGNOSTICS = 8
    FORCE_MULTIPLE_COILS = 15
    PRESET_MULTIPLE_REGISTERS = 16
    READ_COIL_STATUS_EX = 129
    READ_INPUT_STATUS_EX = 130
    READ_HOLDING_REGISTER_EX = 131
    READ_INPUT_REGISTER_EX = 132
    FORCE_SINGLE_COIL_EX = 133
    PRESET_SINGLE_REGISTER_EX = 134
    DIAGNOSTICS_EX = 136
    FORCE_MULTIPLE_COILS_EX = 143
    PRESET_MULTIPLE_REGISTERS_EX = 144


# =============================================================================#
class RModbusResponceType(enum.Enum):
    NO_RESPONSE = 0
    READ_RESPONSE = 1
    MULTIPLE_RESPONSE = 2
    FORCE_SINGLE_COIL_RESPONSE = 3
    PRESET_SINGLE_REGISTER_RESPONSE = 4
    DIAGNOSTICS_RESPONSE = 5
    EXCEPTION_RESPONSE = 6


# =============================================================================#
class RModbusError(Exception):
    def __init__(self, code, msg: RData = None):
        self.code = code
        self.excpiton_msg = msg
        self.message = RMODBUS.EXCEPTION_DIC[code]


# =============================================================================#
class RModbusMessage:
    def __init__(self, data, response=False):
        self.__load(data, response)

    def __load(self, rdata: RData, response: bool):
        self._data = RData(rdata)
        self._response = response
        if len(self._data) < 3:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_SIZE)
        if not valida_crc_extract(self._data):
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_CRC)

    def is_response(self):
        return self._response

    def is_exception_msg(self):
        return RModbusMessage.get_function(self).value & (1 << 7) == (1 << 7)

    def response_type(self) -> RModbusResponceType:
        if not self._response:
            return RModbusResponceType(RModbusResponceType.NO_RESPONSE)
        f = self.get_function()
        if f is RModbusFunction.READ_COIL_STATUS or \
                        f is RModbusFunction.READ_INPUT_STATUS or \
                        f is RModbusFunction.READ_HOLDING_REGISTER or \
                        f is RModbusFunction.READ_INPUT_REGISTER:
            return RModbusResponceType(RModbusResponceType.READ_RESPONSE)
        if f is RModbusFunction.FORCE_MULTIPLE_COILS or f is RModbusFunction.PRESET_MULTIPLE_REGISTERS:
            return RModbusResponceType(RModbusResponceType.MULTIPLE_RESPONSE)
        if f is RModbusFunction.FORCE_SINGLE_COIL:
            return RModbusResponceType(RModbusResponceType.FORCE_SINGLE_COIL_RESPONSE)
        if f is RModbusFunction.PRESET_SINGLE_REGISTER:
            return RModbusResponceType(RModbusResponceType.PRESET_SINGLE_REGISTER_RESPONSE)
        if f is RModbusFunction.DIAGNOSTICS:
            return RModbusResponceType(RModbusResponceType.DIAGNOSTICS_RESPONSE)
        if f is RModbusFunction.READ_COIL_STATUS_EX or \
                        f is RModbusFunction.READ_INPUT_STATUS_EX or \
                        f is RModbusFunction.READ_HOLDING_REGISTER_EX or \
                        f is RModbusFunction.READ_INPUT_REGISTER_EX or \
                        f is RModbusFunction.FORCE_MULTIPLE_COILS_EX or \
                        f is RModbusFunction.PRESET_MULTIPLE_REGISTERS_EX or \
                        f is RModbusFunction.FORCE_SINGLE_COIL_EX or \
                        f is RModbusFunction.PRESET_SINGLE_REGISTER_EX or \
                        f is RModbusFunction.DIAGNOSTICS_EX:
            return RModbusResponceType(RModbusResponceType.EXCEPTION_RESPONSE)
        raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)

    def __get_slave(self):
        return self._data.get_byte(RByteType.BYTE8, RMODBUS.SLAVE, bigendian=True)

    def __set_slave(self, slave):
        self._data.set_byte(RByteType.BYTE8, RMODBUS.SLAVE, slave, bigendian=True)

    def get_function(self) -> RModbusFunction:
        try:
            return RModbusFunction(self._data.get_byte(RByteType.BYTE8, RMODBUS.FUNCTION, bigendian=True))
        except ValueError:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)

    def get_exchange_data(self) -> RData:
        data = RData(self._data)
        add_crc(data)
        return data

    def tostring(self) -> str:
        r = ''
        for n in self._data:
            r += str(int(n)) + ','
        return r[:-1]

    def tostring_with_crc(self) -> str:
        data = RData(self._data)
        add_crc(data)
        r = ''
        for n in data:
            r += str(int(n)) + ','
        return r[:-1]

    def dump(self) -> str:
        return self._data.dump()

    slave = property(__get_slave, __set_slave)


# =============================================================================#
class __RModbusReadMessage(RModbusMessage):
    def __get_addr(self):
        return self._data.get_byte(RByteType.BYTE16, RMODBUS.ADDR, bigendian=True)

    def __set_addr(self, addr):
        self._data.set_byte(RByteType.BYTE16, RMODBUS.ADDR, addr, bigendian=True)

    def __get_qty(self):
        return self._data.get_byte(RByteType.BYTE16, RMODBUS.QTY, bigendian=True)

    def __set_qty(self, qty):
        self._data.set_byte(RByteType.BYTE16, RMODBUS.QTY, qty, bigendian=True)

    addr = property(__get_addr, __set_addr)
    qty = property(__get_qty, __set_qty)


# =============================================================================#
class RModbusReadCoilStatus(__RModbusReadMessage):
    def __init__(self, data):
        super().__init__(data, False)
        if self.get_function() != RModbusFunction.READ_COIL_STATUS:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        if len(self._data) != RMODBUS.SIZE_6:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_SIZE)

    @classmethod
    def create(cls, slave, addr, qty):
        data = RData()
        data.add_byte(RByteType.BYTE8, slave, bigendian=True)
        data.add_byte(RByteType.BYTE8, RModbusFunction.READ_COIL_STATUS.value, bigendian=True)
        data.add_byte(RByteType.BYTE16, addr, bigendian=True)
        data.add_byte(RByteType.BYTE16, qty, bigendian=True)
        add_crc(data)
        return cls(data)


# =============================================================================#
class RModbusReadInputStatus(__RModbusReadMessage):
    def __init__(self, data):
        super().__init__(data, False)
        if self.get_function() != RModbusFunction.READ_INPUT_STATUS:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        if len(self._data) != RMODBUS.SIZE_6:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_SIZE)

    @classmethod
    def create(cls, slave, addr, qty):
        data = RData()
        data.add_byte(RByteType.BYTE8, slave, bigendian=True)
        data.add_byte(RByteType.BYTE8, RModbusFunction.READ_INPUT_STATUS.value, bigendian=True)
        data.add_byte(RByteType.BYTE16, addr, bigendian=True)
        data.add_byte(RByteType.BYTE16, qty, bigendian=True)
        add_crc(data)
        return cls(data)


# =============================================================================#
class RModbusReadHoldingRegister(__RModbusReadMessage):
    def __init__(self, data):
        super().__init__(data, False)
        if self.get_function() != RModbusFunction.READ_HOLDING_REGISTER:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        if len(self._data) != RMODBUS.SIZE_6:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_SIZE)

    @classmethod
    def create(cls, slave, addr, qty):
        data = RData()
        data.add_byte(RByteType.BYTE8, slave, bigendian=True)
        data.add_byte(RByteType.BYTE8, RModbusFunction.READ_HOLDING_REGISTER.value, bigendian=True)
        data.add_byte(RByteType.BYTE16, addr, bigendian=True)
        data.add_byte(RByteType.BYTE16, qty, bigendian=True)
        add_crc(data)
        return cls(data)


# =============================================================================#
class RModbusReadInputRegister(__RModbusReadMessage):
    def __init__(self, data):
        super().__init__(data, False)
        if self.get_function() != RModbusFunction.READ_INPUT_REGISTER:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        if len(self._data) != RMODBUS.SIZE_6:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_SIZE)

    @classmethod
    def create(cls, slave, addr, qty):
        data = RData()
        data.add_byte(RByteType.BYTE8, slave, bigendian=True)
        data.add_byte(RByteType.BYTE8, RModbusFunction.READ_INPUT_REGISTER.value, bigendian=True)
        data.add_byte(RByteType.BYTE16, addr, bigendian=True)
        data.add_byte(RByteType.BYTE16, qty, bigendian=True)
        add_crc(data)
        return cls(data)


# =============================================================================#
class RModbusForceSingleCoil(RModbusMessage):
    def __init__(self, data, response=False):
        super().__init__(data, response)
        if self.get_function() != RModbusFunction.FORCE_SINGLE_COIL:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        if len(self._data) != RMODBUS.SIZE_6:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_SIZE)

    @classmethod
    def create(cls, slave, addr, coil: bool, response=False):
        data = RData()
        data.add_byte(RByteType.BYTE8, slave, bigendian=True)
        data.add_byte(RByteType.BYTE8, RModbusFunction.FORCE_SINGLE_COIL.value, bigendian=True)
        data.add_byte(RByteType.BYTE16, addr, bigendian=True)
        data.add_byte(RByteType.BYTE16, RMODBUS.COIL_TRUE, bigendian=True) if coil \
            else data.add_byte(RByteType.BYTE16, RMODBUS.COIL_FALSE, bigendian=True)
        add_crc(data)
        return cls(data, response)

    def __get_addr(self):
        return self._data.get_byte(RByteType.BYTE16, RMODBUS.ADDR, bigendian=True)

    def __set_addr(self, addr):
        self._data.set_byte(RByteType.BYTE16, RMODBUS.ADDR, addr, bigendian=True)

    def __get_coil(self) -> bool:
        return self._data.get_byte(RByteType.BYTE16, RMODBUS.COIL, bigendian=True) == RMODBUS.COIL_TRUE

    def __set_coil(self, coil):
        self._data.set_byte(RByteType.BYTE16, RMODBUS.COIL, RMODBUS.COIL_TRUE, bigendian=True) if coil \
            else self._data.set_byte(RByteType.BYTE16, RMODBUS.COIL, RMODBUS.COIL_FALSE, bigendian=True)

    addr = property(__get_addr, __set_addr)
    coil = property(__get_coil, __set_coil)


# =============================================================================#
class RModbusPresetSingleRegister(RModbusMessage):
    def __init__(self, data, response=False):
        super().__init__(data, response)
        if self.get_function() != RModbusFunction.PRESET_SINGLE_REGISTER:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        if len(self._data) != RMODBUS.SIZE_6:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_SIZE)

    @classmethod
    def create(cls, slave, addr, register, response=False):
        data = RData()
        data.add_byte(RByteType.BYTE8, slave, bigendian=True)
        data.add_byte(RByteType.BYTE8, RModbusFunction.PRESET_SINGLE_REGISTER.value, bigendian=True)
        data.add_byte(RByteType.BYTE16, addr, bigendian=True)
        data.add_byte(RByteType.BYTE16, register, bigendian=True)
        add_crc(data)
        return cls(data, response)

    def __get_addr(self):
        return self._data.get_byte(RByteType.BYTE16, RMODBUS.ADDR, bigendian=True)

    def __set_addr(self, addr):
        self._data.set_byte(RByteType.BYTE16, RMODBUS.ADDR, addr, bigendian=True)

    def __get_register(self):
        return self._data.get_byte(RByteType.BYTE16, RMODBUS.REGISTER, bigendian=True)

    def __set_register(self, register):
        self._data.set_byte(RByteType.BYTE16, RMODBUS.REGISTER, register, bigendian=True)

    addr = property(__get_addr, __set_addr)
    register = property(__get_register, __set_register)


# =============================================================================#
class RModbusDiagnostics(RModbusMessage):
    def __init__(self, data, response=False):
        super().__init__(data, response)
        if self.get_function() != RModbusFunction.DIAGNOSTICS:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        if len(self._data) != RMODBUS.SIZE_6:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_SIZE)

    @classmethod
    def create(cls, slave, subfunc, datadiag, response=False):
        data = RData()
        data.add_byte(RByteType.BYTE8, slave, bigendian=True)
        data.add_byte(RByteType.BYTE8, RModbusFunction.DIAGNOSTICS.value, bigendian=True)
        data.add_byte(RByteType.BYTE16, subfunc, bigendian=True)
        data.add_byte(RByteType.BYTE16, datadiag, bigendian=True)
        add_crc(data)
        return cls(data, response)

    def __get_subfunc(self):
        return self._data.get_byte(RByteType.BYTE16, RMODBUS.SUBFUNC, bigendian=True)

    def __set_subfunc(self, subfunc):
        self._data.set_byte(RByteType.BYTE16, RMODBUS.ADDR, subfunc, bigendian=True)

    def __get_datadiag(self):
        return self._data.get_byte(RByteType.BYTE16, RMODBUS.DATADIAG, bigendian=True)

    def __set_datadiag(self, datadiag):
        self._data.set_byte(RByteType.BYTE16, RMODBUS.DATADIAG, datadiag, bigendian=True)

    subfunc = property(__get_subfunc, __set_subfunc)
    datadiag = property(__get_datadiag, __set_datadiag)


# =============================================================================#
class RModbusForceMultipleCoils(__RModbusReadMessage):
    def __init__(self, data):
        super().__init__(data, False)
        if self.get_function() != RModbusFunction.FORCE_MULTIPLE_COILS:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        if len(self._data) < RMODBUS.SIZE_7:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_SIZE)
        if self._data[RMODBUS.QUERY_BYTECOUNT] != len(self._data) - RMODBUS.SIZE_7:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_BYTECOUNT)

    @classmethod
    def create(cls, slave, addr, qty):
        data = RData()
        data.add_byte(RByteType.BYTE8, slave, bigendian=True)
        data.add_byte(RByteType.BYTE8, RModbusFunction.FORCE_MULTIPLE_COILS.value, bigendian=True)
        data.add_byte(RByteType.BYTE16, addr, bigendian=True)
        data.add_byte(RByteType.BYTE16, qty, bigendian=True)
        count = int(qty / 8)
        if (qty % 8 != 0):
            count += 1
        data.add_byte(RByteType.BYTE8, count)
        for i in range(count):
            data.add_byte(RByteType.BYTE8, 0)
        add_crc(data)
        return cls(data)

    @property
    def query_byte_count(self) -> int:
        return self._data.get_byte(RByteType.BYTE8, RMODBUS.QUERY_BYTECOUNT, bigendian=True)

    @property
    def query_bit_count(self) -> int:
        return self._data.get_byte(RByteType.BYTE8, RMODBUS.QUERY_BYTECOUNT, bigendian=True) * 8

    def get_byte(self, bytetype, item, signed=False, bigendian=True):
        item += RMODBUS.SIZE_7
        return self._data.get_byte(bytetype, item, signed, bigendian)

    def set_byte(self, bytetype, item, data, signed=False, bigendian=True):
        item += RMODBUS.SIZE_7
        self._data.set_byte(bytetype, item, data, signed, bigendian)

    def is_bit(self, bit_index) -> bool:
        if bit_index < self.query_bit_count * -1 or bit_index > self.query_bit_count - 1:
            raise RModbusError(RMODBUS.EXCEPTION_ITEM_NOT_EXIST)
        return self._data.is_bit(bit_index, RMODBUS.SIZE_7)

    def set_bit(self, bit_index):
        if bit_index < self.query_bit_count * -1 or bit_index > self.query_bit_count - 1:
            raise RModbusError(RMODBUS.EXCEPTION_ITEM_NOT_EXIST)
        self._data.set_bit(bit_index, RMODBUS.SIZE_7)

    def clear_bit(self, bit_index):
        if bit_index < self.query_bit_count * -1 or bit_index > self.query_bit_count - 1:
            raise RModbusError(RMODBUS.EXCEPTION_ITEM_NOT_EXIST)
        self._data.clear_bit(bit_index, RMODBUS.SIZE_7)

    def toggle_bit(self, bit_index):
        if bit_index < self.query_bit_count * -1 or bit_index > self.query_bit_count - 1:
            raise RModbusError(RMODBUS.EXCEPTION_ITEM_NOT_EXIST)
        self._data.toggle_bit(bit_index, RMODBUS.SIZE_7)


# =============================================================================#
class RModbusPresetMultipleRegisters(__RModbusReadMessage):
    def __init__(self, data):
        super().__init__(data, False)
        if self.get_function() != RModbusFunction.PRESET_MULTIPLE_REGISTERS:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        if len(self._data) < RMODBUS.SIZE_7:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_SIZE)
        if self._data[RMODBUS.QUERY_BYTECOUNT] != len(self._data) - RMODBUS.SIZE_7:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_BYTECOUNT)

    @classmethod
    def create(cls, slave, addr, qty):
        data = RData()
        data.add_byte(RByteType.BYTE8, slave, bigendian=True)
        data.add_byte(RByteType.BYTE8, RModbusFunction.PRESET_MULTIPLE_REGISTERS.value, bigendian=True)
        data.add_byte(RByteType.BYTE16, addr, bigendian=True)
        data.add_byte(RByteType.BYTE16, qty, bigendian=True)
        count = qty * 2
        data.add_byte(RByteType.BYTE8, count)
        for i in range(count):
            data.add_byte(RByteType.BYTE8, 0)
        add_crc(data)
        return cls(data)

    @property
    def query_byte_count(self) -> int:
        return self._data.get_byte(RByteType.BYTE8, RMODBUS.QUERY_BYTECOUNT, bigendian=True)

    def get_byte(self, bytetype, item, signed=False, bigendian=True):
        item += RMODBUS.SIZE_7
        return self._data.get_byte(bytetype, item, signed, bigendian)

    def set_byte(self, bytetype, item, data, signed=False, bigendian=True):
        item += RMODBUS.SIZE_7
        self._data.set_byte(bytetype, item, data, signed, bigendian)


# =============================================================================#
class RModbusReadResponse(RModbusMessage):
    def __init__(self, data):
        super().__init__(data, True)
        f = self.get_function().value
        if f < RModbusFunction.READ_COIL_STATUS.value or f > RModbusFunction.READ_INPUT_REGISTER.value:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        if len(self._data) < RMODBUS.SIZE_3:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_SIZE)
        if self._data[RMODBUS.RESPONSE_BYTECOUNT] != len(self._data) - RMODBUS.SIZE_3:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_BYTECOUNT)

    @classmethod
    def create(cls, function: RModbusFunction, slave):
        data = RData()
        if function.value < RModbusFunction.READ_COIL_STATUS.value or function.value > RModbusFunction.READ_INPUT_REGISTER.value:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        data.add_byte(RByteType.BYTE8, slave, bigendian=True)
        data.add_byte(RByteType.BYTE8, function.value, bigendian=True)
        data.add_byte(RByteType.BYTE8, 0, bigendian=True)
        add_crc(data)
        return cls(data)

    def set_function(self, function: RModbusFunction):
        if function.value < RModbusFunction.READ_COIL_STATUS.value or function.value > RModbusFunction.READ_INPUT_REGISTER.value:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        self._data.set_byte(RByteType.BYTE8, RMODBUS.FUNCTION, function.value, bigendian=True)

    @property
    def get_response_byte_count(self) -> int:
        return self._data.get_byte(RByteType.BYTE8, RMODBUS.RESPONSE_BYTECOUNT, bigendian=True)

    @property
    def get_bit_count(self) -> int:
        return self._data.get_byte(RByteType.BYTE8, RMODBUS.RESPONSE_BYTECOUNT, bigendian=True) * 8

    def get_byte(self, bytetype, item, signed=False, bigendian=True):
        item += RMODBUS.SIZE_3
        return self._data.get_byte(bytetype, item, signed, bigendian)

    def set_byte(self, bytetype, item, data, signed=False, bigendian=True):
        item += RMODBUS.SIZE_3
        self._data.set_byte(bytetype, item, data, signed, bigendian)

    def add_byte(self, bytetype, data, signed=False, bigendian=True):
        self._data.add_byte(bytetype, data, signed, bigendian)
        if bytetype.value == 33 or bytetype.value == 65:
            b = bytetype.value - 1
        else:
            b = bytetype.value
        n = int(self.get_response_byte_count + (b / 8))
        self._data.set_byte(RByteType.BYTE8, RMODBUS.RESPONSE_BYTECOUNT, n, bigendian=True)

    def is_bit(self, bit_index) -> bool:
        if bit_index < self.get_bit_count * -1 or bit_index > self.get_bit_count - 1:
            raise RModbusError(RMODBUS.EXCEPTION_ITEM_NOT_EXIST)
        return self._data.is_bit(bit_index, RMODBUS.SIZE_3)

    def set_bit(self, bit_index):
        if bit_index < self.get_bit_count * -1 or bit_index > self.get_bit_count - 1:
            raise RModbusError(RMODBUS.EXCEPTION_ITEM_NOT_EXIST)
        self._data.set_bit(bit_index, RMODBUS.SIZE_3)

    def clear_bit(self, bit_index):
        if bit_index < self.get_bit_count * -1 or bit_index > self.get_bit_count - 1:
            raise RModbusError(RMODBUS.EXCEPTION_ITEM_NOT_EXIST)
        self._data.clear_bit(bit_index, RMODBUS.SIZE_3)

    def toggle_bit(self, bit_index):
        if bit_index < self.get_bit_count * -1 or bit_index > self.get_bit_count - 1:
            raise RModbusError(RMODBUS.EXCEPTION_ITEM_NOT_EXIST)
        self._data.toggle_bit(bit_index, RMODBUS.SIZE_3)


# =============================================================================#
class RModbusMultipleResponse(__RModbusReadMessage):
    def __init__(self, data):
        super().__init__(data, True)
        f = self.get_function()
        if f != RModbusFunction.FORCE_MULTIPLE_COILS and f != RModbusFunction.PRESET_MULTIPLE_REGISTERS:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        if len(self._data) != RMODBUS.SIZE_6:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_SIZE)

    @classmethod
    def create(cls, function: RModbusFunction, slave, addr, qty):
        data = RData()
        if function != RModbusFunction.FORCE_MULTIPLE_COILS and function != RModbusFunction.PRESET_MULTIPLE_REGISTERS:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        data.add_byte(RByteType.BYTE8, slave, bigendian=True)
        data.add_byte(RByteType.BYTE8, function.value, bigendian=True)
        data.add_byte(RByteType.BYTE16, addr, bigendian=True)
        data.add_byte(RByteType.BYTE16, qty, bigendian=True)
        add_crc(data)
        return cls(data)

    def set_function(self, function: RModbusFunction):
        if function != RModbusFunction.FORCE_MULTIPLE_COILS and function != RModbusFunction.PRESET_MULTIPLE_REGISTERS:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        self._data.set_byte(RByteType.BYTE8, RMODBUS.FUNCTION, function.value, bigendian=True)


# =============================================================================#
class RModbusExceptionMessage(RModbusMessage):
    def __init__(self, data):
        super().__init__(data, True)
        f = self.get_function().value
        if f & (1 << 7) != (1 << 7):
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        # if (f < RModbusFunction.READ_COIL_STATUS_EX.value or f > RModbusFunction.READ_INPUT_REGISTER_EX.value) \
        #         and f != RModbusFunction.DIAGNOSTICS_EX.value \
        #         and f != RModbusFunction.FORCE_MULTIPLE_COILS_EX.value \
        #         and f != RModbusFunction.PRESET_MULTIPLE_REGISTERS_EX.value:
        #     raise RModbusError(EXCEPTION_INVALID_FUNCTION)
        if len(self._data) != RMODBUS.SIZE_3:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_SIZE)

    @classmethod
    def create(cls, function: RModbusFunction, slave, excode):
        data = RData()
        f = function.value
        if f & (1 << 7) != (1 << 7):
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        # if (f < RModbusFunction.READ_COIL_STATUS_EX.value or f > RModbusFunction.READ_INPUT_REGISTER_EX.value) \
        #         and f != RModbusFunction.DIAGNOSTICS_EX.value \
        #         and f != RModbusFunction.FORCE_MULTIPLE_COILS_EX.value \
        #         and f != RModbusFunction.PRESET_MULTIPLE_REGISTERS_EX.value:
        #     raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        data.add_byte(RByteType.BYTE8, slave, bigendian=True)
        data.add_byte(RByteType.BYTE8, f, bigendian=True)
        data.add_byte(RByteType.BYTE8, excode, bigendian=True)
        add_crc(data)
        return cls(data)

    def set_function(self, function: RModbusFunction):
        f = function.value ^ 0x80
        if (f < RModbusFunction.READ_COIL_STATUS_EX.value or f > RModbusFunction.READ_INPUT_REGISTER_EX.value) \
                and f != RModbusFunction.DIAGNOSTICS_EX.value \
                and f != RModbusFunction.FORCE_MULTIPLE_COILS_EX.value \
                and f != RModbusFunction.PRESET_MULTIPLE_REGISTERS_EX.value:
            raise RModbusError(RMODBUS.EXCEPTION_INVALID_FUNCTION)
        self._data.set_byte(RByteType.BYTE8, RMODBUS.FUNCTION, function.value, bigendian=True)

    def __get_excode(self):
        return self._data.get_byte(RByteType.BYTE8, RMODBUS.EXCEPTION, bigendian=True)

    def __set_excode(self, excode):
        self._data.set_byte(RByteType.BYTE8, RMODBUS.EXCEPTION, excode, bigendian=True)

    excode = property(__get_excode, __set_excode)


# =============================================================================#
class RModbusParms(RSerialParms):
    def __init__(self, device, baudrate=9600, databits=8, parity='N', stopbits=1, timeout=300, recv_buffer=16384):
        super().__init__(device, baudrate, databits, parity, stopbits, timeout)
        self.recv_buffer = recv_buffer

    @classmethod
    def create_from_serial_parms(cls, parms: RSerialParms, recv_buffer: int):
        return cls(parms.device, baudrate=parms.baudrate, databits=parms.databits, parity=parms.parity,
                   stopbits=parms.stopbits, timeout=parms.timeout, recv_buffer=recv_buffer)

    def __str__(self) -> str:
        return 'Device:{} Baudrate:{} Databits:{} Parity:{} Stopbits:{} Timeout:{} RecvBuffer:{}'.format(self.device,
                                                                                                    self.baudrate,
                                                                                                    self.databits,
                                                                                                    self.parity,
                                                                                                    self.stopbits,
                                                                                                    self.timeout,
                                                                                                    self.recv_buffer)


# =============================================================================#
class RModbusConfig(RSerialConfig):
    def __init__(self, section, config: RConfig):
        super().__init__(section, config)

    def read(self) -> RModbusParms:
        s = super().read()
        recv_buffer = self._config.conf.getint(self.section, CONST.RECV_BUFFER)
        return RModbusParms.create_from_serial_parms(s, recv_buffer)

    def write(self, parms: RModbusParms):
        self._config.conf.set(self.section, CONST.RECV_BUFFER, parms.recv_buffer)
        super().write(parms)



# =============================================================================#
class RModbusComm(RSerialComm):
    def __init__(self, parms: RModbusParms):
        super().__init__(parms)
        self.tmodbus = 4 / (parms.baudrate / 10)

    def exchange(self, send: RModbusMessage) -> RModbusMessage:
        RSerialComm.threadLock.acquire()
        try:
            d = send.get_exchange_data()
            time.sleep(self.tmodbus)
            self.write(d)
            self.flush()
            # while self.out_waiting() != 0:
            #     pass
            time.sleep(self.tmodbus)
            r = RData()
            while True:
                c = self.read()
                if c.__len__() == 0:
                    break
                r.append(c[0])
                if len(r) > self.parms.recv_buffer:
                    break
            # print(r)
            if len(r) == 0:
                raise RModbusError(RMODBUS.EXCEPTION_NO_ANSWER)
            if len(r) > self.parms.recv_buffer:
                raise RModbusError(RMODBUS.EXCEPTION_BUFFER_OVERFLOW)
            return RModbusMessage(r, True)
        finally:
            RSerialComm.threadLock.release()


# =============================================================================#
def teste_modbus():
    r = RModbusReadCoilStatus.create(3, 23, 400)
    print(r.slave)
    print(r.get_function())
    print(r.qty)
    print(r.addr)
    print(r.tostring())
    r.addr = 256
    print(r.tostring())

    r1 = RModbusReadHoldingRegister.create(4, 609, 10)
    print(r1.tostring())

    r2 = RModbusPresetSingleRegister.create(2, 234, 13)
    print(r2.tostring())

    r3 = RModbusForceSingleCoil.create(56, 100, True)
    print(r3.dump())
    r3.coil = False
    print(r3.dump())
    r3.coil = True
    print(r3.dump())

    r4 = RModbusPresetSingleRegister.create(29, 700, 128)
    print(r4.dump())
    r4.register = 64
    print(r4.dump())
    r4.register = 32
    print(r4.dump())

    r5 = RModbusDiagnostics.create(56, 12, 67, True)
    print(r5.dump())
    print(r5.is_response())
    r6 = RModbusDiagnostics.create(56, 12, 67, False)
    print(r6.dump())
    print(r6.is_response())

    r7 = RModbusForceMultipleCoils.create(52, 120, 28)
    print(r7.dump())
    r7.set_bit(-32)
    r7.toggle_bit(23)
    r7.toggle_bit(-3)
    r7.toggle_bit(-5)
    print(r7.dump())
    print(r7.get_byte(RByteType.BYTE8, 0))

    r8 = RModbusReadResponse.create(RModbusFunction.READ_INPUT_REGISTER, 23)
    print(r8.tostring())
    r8.set_function(RModbusFunction.READ_HOLDING_REGISTER)
    print(r8.tostring())
    print(r8.get_response_byte_count)
    r8.add_byte(RByteType.BYTE8, 24)
    print(r8.tostring())
    r8.add_byte(RByteType.BYTE16, 12376)
    print(r8.tostring())
    r8.add_byte(RByteType.BYTE32, 568344)
    print(r8.tostring())
    r8.add_byte(RByteType.BYTE64, 72978562789)
    print(r8.tostring())
    r8.add_byte(RByteType.FLOAT, 1234.827)
    print(r8.tostring())
    r8.add_byte(RByteType.DOUBLE, 72978562789.92)
    print(r8.tostring())

    r9 = RModbusMultipleResponse.create(RModbusFunction.PRESET_MULTIPLE_REGISTERS, 1, 45, 34)
    print(r9.tostring())
    print(r9.is_response())
    print(r9.is_exception_msg())
    r9.set_function(RModbusFunction.FORCE_MULTIPLE_COILS)
    print(r9.tostring())

    r10 = RModbusExceptionMessage.create(RModbusFunction.FORCE_MULTIPLE_COILS_EX, 12, 2)
    print(r10.tostring())


# =============================================================================#
def teste_modbus1():
    st = RData([1, 1, 0, 1, 0, 20])
    add_crc(st)
    print(valida_crc(st))
    rcoil = RModbusReadCoilStatus(st)
    print(rcoil.tostring_with_crc())
    print(rcoil.get_function())
    print(rcoil.slave)
    print(rcoil.addr)
    print(rcoil.qty)
    print(rcoil.dump())
    print(rcoil.tostring())

    rcoil1 = RModbusReadCoilStatus.create(1, 2, 10)
    print(rcoil1.tostring_with_crc())
    print(rcoil1.get_function())
    print(rcoil1.slave)
    print(rcoil1.addr)
    print(rcoil1.qty)

    resp = RModbusReadResponse.create(RModbusFunction.READ_HOLDING_REGISTER, 23)
    resp1 = RModbusReadResponse(resp.get_exchange_data())
    print(resp.tostring_with_crc())
    print(resp1.tostring_with_crc())

    print(rcoil.is_exception_msg())
    print(rcoil.is_response())
    print(resp.is_exception_msg())
    print(resp.is_response())


# =============================================================================#
def teste_modbuscomm():
    config = RConfig(interpolation=ExtendedInterpolation())
    try:
        config.read('rmodbus.ini')
        config_comm = RModbusConfig('Modbus', config)
        parms = config_comm.read()
        print(parms)
        modbus_comm = RModbusComm(parms)
        # send = RModbusReadCoilStatus.create(1, 1, 1)
        # send1 = RModbusReadHoldingRegister.create(1, 159, 8)
        # send2 = RModbusReadHoldingRegister.create(2, 159, 8)
        send = RModbusReadHoldingRegister.create(1, 0, 1)
        modbus_comm.open()
        count = 0
        while count < 500:
            recv = modbus_comm.exchange(send)
            # recv2 = modbus_comm.exchange(send2)
            count = count + 1
            print(recv.tostring())
        # print(recv2.tostring())
        modbus_comm.close()
    except RConfigError as e:
        print('Error setting "' + e.setting + '"')
    except RModbusError as e:
        print(e.message)
    except Exception as e:
        print(str(e))


# =============================================================================#
if __name__ == '__main__':
    # teste_modbus1()
    # teste_modbus()
    teste_modbuscomm()

# try:
#     RModbusReadCoilStatus([1])
# except RModbusError as err:
#     print("{:s}, codigo {:d}.".format(err.message, err.code))
#
# try:
#     RModbusReadCoilStatus(st)
# except RModbusError as err:
#     print("{:s}, codigo {:d}.".format(err.message, err.code))
#
# add_crc(st)
#
# try:
#     m = RModbusReadCoilStatus(st)
#     print("Modbus with valid CRC.")
#     m.tostring()
#     print(m.get_slave())
#     print(RMODBUS_FUNCTION_DIC[m.get_function()])
#     m.clear()
#     m.tostring()
#     print(m.get_slave())
#     print(RMODBUS_FUNCTION_DIC[m.get_function()])
# except RModbusError as err:
#     print("{:s}, codigo {:d}.".format(err.message, err.code))
#
