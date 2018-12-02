#!/usr/bin/python3
# -*- coding: utf-8 -*-

import fcntl
import re
import os
import time
from subprocess import Popen, PIPE, STDOUT

# =============================================================================#
AF_NONE = -1
AF_RETURNCODE_OK = 0
AF_RETURNCODE_KILLED = 1
AF_UP = 0
AF_NOT_CONFIGURED = 1
AF_ALREADY_CONFIGURED = 2
AF_DOWN = 3
AF_FAIL = 4
AF_NONE_IP = '0.0.0.0'


# =============================================================================#
class RControlDHCP(object):
    def __init__(self, ifdown_path='/sbin/ifdown', ifup_path='/sbin/ifup', sudo_path='/usr/bin/sudo', finnish_func=None,
                 verbose_func=None, timeout=60):
        self._output = ''
        self.ifdown_path = ifdown_path
        if not os.path.isfile(self.ifdown_path) or not os.access(self.ifdown_path, os.X_OK):
            raise IOError('%s not found' % self.ifdown_path)
        self.ifup_path = ifup_path
        if not os.path.isfile(self.ifup_path) or not os.access(self.ifup_path, os.X_OK):
            raise IOError('%s not found' % self.ifup_path)
        self.sudo_path = sudo_path
        if not os.path.isfile(self.sudo_path) or not os.access(self.sudo_path, os.X_OK):
            raise IOError('%s not found' % self.sudo_path)
        self._finnish_func = finnish_func
        self._verbose_func = verbose_func
        self._timeout = timeout

    @property
    def output(self):
        return self._output

    @property
    def timeout(self):
        return self.timeout

    @timeout.setter
    def timeout(self, value):
        self._timeout = value

    @property
    def ip(self):
        ip = re.search(r'DHCPACK of ([\d\.]+)', self._output)
        if ip:
            return ip.group(1)
        else:
            return AF_NONE_IP

    def ifdown(self, iface: str, sudo=False) -> (int, int):
        return self._ifcmd(False, iface, sudo)

    def ifup(self, iface: str, sudo=False) -> (int, int):
        return self._ifcmd(True, iface, sudo)

    def release(self, iface: str, sudo=False) -> (int, int):
        return self._ifcmd(False, iface, sudo)

    def renew(self, iface: str, sudo=False) -> (int, int):
        self._ifcmd(False, iface, sudo)
        return self._ifcmd(True, iface, sudo)

    def _ifcmd(self, cmd, iface: str, sudo=False) -> (int, int):
        commands = []
        self._output = ''
        if sudo:
            commands.append(self.sudo_path)
        if cmd:
            commands.append(self.ifup_path)
        else:
            commands.append(self.ifdown_path)
        commands.append(iface)
        self.proc = Popen(commands, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
        self._set_non_bloking()
        return self._process(iface)

    def _set_non_bloking(self):
        # set stdout to non-blocking
        fd = self.proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    def _process(self, iface: str) -> (int, int):
        x = time.time() + self._timeout
        while time.time() < x:
            rt = self.proc.poll()
            try:
                b = self.proc.stdout.readline()
                if len(b) != 0:
                    if self._verbose_func is not None:
                        self._verbose_func(b.rstrip('\n\r '))
                    self._output += b
            except IOError as e:
                if e.errno != 11:
                    raise
                time.sleep(1)
            except Exception as e:
                print(e)
            if 'interface ' + iface + ' not configured' in self._output:
                return self._exec_func(AF_NOT_CONFIGURED, AF_RETURNCODE_OK)
            if 'interface ' + iface + ' already configured' in self._output:
                return self._exec_func(AF_ALREADY_CONFIGURED, AF_RETURNCODE_OK)
            if 'DHCPACK' in self._output:
                return self._exec_func(AF_UP, AF_RETURNCODE_OK)
            if 'DHCPRELEASE' in self._output:
                return self._exec_func(AF_DOWN, AF_RETURNCODE_OK)
            elif rt is not None:
                if rt == 0:
                    return self._exec_func(AF_NONE, AF_RETURNCODE_OK)
                else:
                    return self._exec_func(AF_NONE, rt)
        self.proc.terminate()
        return AF_FAIL, AF_RETURNCODE_KILLED

    def _exec_func(self, status, returncode) -> (int, int):
        if self._finnish_func is not None:
            self._finnish_func(status, returncode)
        return (status, returncode)


# =============================================================================#

def verbose(verb):
    print(verb)

def finnish(a, b):
    print('Code:{} ReturnCode:{}'.format(a, b))

if __name__ == '__main__':
    p = RControlDHCP(timeout=20, verbose_func=verbose, finnish_func=finnish)
    print(p.renew('eth0'))
    print(p.ip)
