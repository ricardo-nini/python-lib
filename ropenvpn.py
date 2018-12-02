#!/usr/bin/python3
# -*- coding: utf-8 -*-

import fcntl
import os
import re
import time
import threading
import logging
import enum
from subprocess import Popen, PIPE, STDOUT


# =============================================================================#
class OpenvpnState(enum.Enum):
    OPENVPN_START = 0
    OPENVPN_FINNISHED = 1
    OPENVPN_CONNECTED = 2
    OPENVPN_CONNECTING = 3


# =============================================================================#
class OpenvpnConnect(threading.Thread):
    def __init__(self, configfile, openvpn_path='/usr/sbin/openvpn', sudo_path='/usr/bin/sudo', connect_func=None,
                 disconnect_func=None, exit_func=None, verbose_func=None, sudo=False):
        threading.Thread.__init__(self)
        self._configfile = configfile
        self._openvpn_path = openvpn_path
        self._sudo_path = sudo_path
        self._connect_func = connect_func
        self._disconnect_func = disconnect_func
        self._exit_func = exit_func
        self._verbose_func = verbose_func
        self._sudo = sudo
        self.logger = logging.getLogger(__name__)
        self._output = ''
        self._state = OpenvpnState.OPENVPN_START

    def run(self):
        commands = []
        if self._sudo:
            commands.append(self._sudo_path)
        commands.append(self._openvpn_path)
        commands.append('--config')
        commands.append(self._configfile)
        self._proc = Popen(commands, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
        self._set_non_bloking()
        while True:
            try:
                r = self._proc.stdout.readline()
                if len(r) != 0:
                    if self._verbose_func is not None:
                        self._verbose_func(r.rstrip('\n\r '))
                    self._output += r
            except IOError as e:
                if e.errno != 11:
                    raise
                time.sleep(1)
            if 'Initialization Sequence Completed' in r:
                self._state = OpenvpnState.OPENVPN_CONNECTED
                if self._connect_func is not None:
                    self._connect_func(self)
            elif 'TUN/TAP device' in r and 'opened' in r:
                self._device = r.split(' ')[7].strip()
            elif 'addr add' in r and 'local' in r and 'peer' in r:
                a = r.split(' ')
                self._local_ip = a[11].strip()
                self._remote_ip = a[13].strip()
            elif r != '' and self._state == OpenvpnState.OPENVPN_CONNECTED:
                self._output = ''
                if self._disconnect_func is not None:
                    self._disconnect_func()
                self._state = OpenvpnState.OPENVPN_CONNECTING
            elif self._proc.poll() is not None:
                self._state = OpenvpnState.OPENVPN_FINNISHED
                self._output = ''
                if self._exit_func is not None:
                    self._exit_func(self._proc.returncode)
                break

    def stop(self):
        if self._proc.poll() is None:
            self._proc.terminate()

    @property
    def state(self):
        return self._state

    @property
    def local_ip(self):
        return self._local_ip

    @property
    def remote_ip(self):
        return self._remote_ip

    @property
    def device(self):
        return self._device

    def _set_non_bloking(self):
        # set stdout to non-blocking
        fd = self._proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)


# =============================================================================#
def connect(s: OpenvpnConnect):
    print('Connected device:{} at local ip:{} and peer:{}'.format(s.device, s.local_ip, s.remote_ip))


def disconnect():
    print('Disconnected')


def exit(returncode):
    print('Exit code:{}'.format(returncode))


def verbose(verb):
    print(verb)


# =============================================================================#
if __name__ == '__main__':
    p = OpenvpnConnect('/etc/openvpn/client.conf', exit_func=exit, connect_func=connect, disconnect_func=disconnect,
                       verbose_func=verbose)
    p.start()
    time.sleep(2)


    while p.state != OpenvpnState.OPENVPN_FINNISHED:
        time.sleep(1)

    p.stop()
    p.join()

