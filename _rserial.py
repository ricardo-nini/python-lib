#!/usr/bin/python
# -*- coding: utf-8 -*-

# =============================================================================#
class __const:
    class ConstError(TypeError):
        pass

    def __setattr__(self, name, value):
        if name in self.__dict__:
            raise self.ConstError("Can't rebind const(%s)" % name)
        self.__dict__[name] = value


RSERIAL = __const()

RSERIAL.DEVICE = 'Device'
RSERIAL.BAUDRATE = 'Baudrate'
RSERIAL.DATABITS = 'Databits'
RSERIAL.PARITY = 'Parity'
RSERIAL.STOPBITS = 'Stopbits'
RSERIAL.TIMEOUT = 'Timeout'

RSERIAL.DEF_BAUDRATE = 9600
RSERIAL.DEF_DATABITS = 8
RSERIAL.DEF_PARITY = 'N'
RSERIAL.DEF_STOPBITS = 1
RSERIAL.DEF_TIMEOUT = 200