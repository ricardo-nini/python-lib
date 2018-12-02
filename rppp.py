#!/usr/bin/python3
# -*- coding: utf-8 -*-

import fcntl
import os
import re
import time
import threading
import logging
import rlib.common as common
import rlib.rgpio as GPIO
from subprocess import Popen, PIPE, STDOUT

# =============================================================================#
PPP_NONE_IP = '0.0.0.0'
PPP_DISCONNECTED = 0
PPP_CONNECTING = 1
PPP_CONNECTED = 2

PPPD_RETURNCODES = {
    1: 'Fatal error occured',
    2: 'Error processing options',
    3: 'Not executed as root or setuid-root',
    4: 'No kernel support, PPP kernel driver not loaded',
    5: 'Received SIGINT, SIGTERM or SIGHUP',
    6: 'Modem could not be locked',
    7: 'Modem could not be opened',
    8: 'Connect script failed',
    9: 'pty argument command could not be run',
    10: 'PPP negotiation failed',
    11: 'Peer failed (or refused) to authenticate',
    12: 'The link was terminated because it was idle',
    13: 'The link was terminated because the connection time limit was reached',
    14: 'Callback negotiated',
    15: 'The link was terminated because the peer was not responding to echo requests',
    16: 'The link was terminated by the modem hanging up',
    17: 'PPP negotiation failed because serial loopback was detected',
    18: 'Init script failed',
    19: 'Failed to authenticate to the peer',
}


# =============================================================================#
class PPPConnectionError(Exception):
    def __init__(self, code, output=None):
        self.code = code
        self.message = PPPD_RETURNCODES.get(code, 'Undocumented error occured')
        self.output = output
        super(Exception, self).__init__(code, output)

    def __str__(self):
        return self.message


# =============================================================================#
class PPPConnection(threading.Thread):
    def __init__(self, profile,
                 attrb: dict,
                 pppd_path='/usr/sbin/pppd',
                 sudo_path='/usr/bin/sudo',
                 connect_func=None,
                 disconnect_func=None,
                 verbose_func=None,
                 sudo=False):
        threading.Thread.__init__(self)
        self._profile = profile
        self._attrb = attrb
        self._pppd_path = pppd_path
        self._sudo_path = sudo_path
        self._connect_func = connect_func
        self._disconnect_func = disconnect_func
        self._verbose_func = verbose_func
        self._sudo = sudo
        self._state = PPP_DISCONNECTED
        self._iface = ''
        self._wait = 0
        self._wait_time = 0
        self._stop_event = threading.Event()
        self.logger = logging.getLogger(__name__)

    def run(self):
        while not self._stop_event.is_set():
            if self._wait == 0:
                if not 'ModemReset' in self._attrb:
                    self._attrb['ModemReset'] = 0
                if self._attrb['ModemReset'] == 1 and 'PinResetGSM' in self._attrb:
                    GPIO.setup(self._attrb['PinResetGSM'], GPIO.GPIO.OUT)
                    GPIO.output(self._attrb['PinResetGSM'], GPIO.GPIO.LOW)
                    time.sleep(.1)
                    GPIO.output(self._attrb['PinResetGSM'], GPIO.GPIO.HIGH)
                    time.sleep(self._attrb['ResetGSMTime'])
                elif self._attrb['ModemReset'] == 2 and 'VendorModel' in self._attrb:
                    devpath = common.get_device_path_by_id(self._attrb['VendorModel'])
                    if devpath:
                        common.send_usb_reset(devpath)
                        time.sleep(self._attrb['ResetGSMTime'])
                commands = []
                self._output = ''
                if self._sudo:
                    commands.append(self._sudo_path)
                commands.append(self._pppd_path)
                commands.append('call')
                commands.append(self._profile)
                commands.append('nodetach')
                self.proc = Popen(commands, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
                self._set_non_bloking()
                self._state = PPP_CONNECTING
                while True:
                    try:
                        r = self.proc.stdout.readline()
                        if len(r) != 0:
                            if self._verbose_func is not None:
                                self._verbose_func(r.rstrip('\n\r '))
                            # get interface
                            if 'Using interface' in r:
                                iface = re.search(r'Using interface ([ppp\d]+)', r)
                                if iface:
                                    self._iface = iface.group(1)
                            self._output += r
                    except IOError as e:
                        if e.errno != 11:
                            raise
                        time.sleep(1)
                    if 'DNS address' in self._output and self._state != PPP_CONNECTED:
                        self._state = PPP_CONNECTED
                        if self._connect_func is not None:
                            self._connect_func()
                    elif self.proc.poll() is not None:
                        self._state = PPP_DISCONNECTED
                        self._output = ''
                        if self._disconnect_func is not None:
                            self._disconnect_func(self.proc.returncode)
                        break
            else:
                self._wait = self._wait - 1
            time.sleep(10)

    @property
    def state(self) -> int:
        return self._state

    @property
    def local_ip(self) -> str:
        if self._state == PPP_CONNECTED:
            ip = re.search(r'local  IP address ([\d\.]+)', self._output)
            if ip:
                return ip.group(1)
        return PPP_NONE_IP

    @property
    def remote_ip(self) -> str:
        if self._state == PPP_CONNECTED:
            ip = re.search(r'remote IP address ([\d\.]+)', self._output)
            if ip:
                return ip.group(1)
        return PPP_NONE_IP

    @property
    def dns1(self) -> ():
        if self._state == PPP_CONNECTED:
            dns1 = re.search(r'primary   DNS address ([\d\.]+)', self._output)
            if dns1:
                return dns1.group(1)
        return PPP_NONE_IP

    @property
    def dns2(self) -> ():
        if self._state == PPP_CONNECTED:
            dns2 = re.search(r'secondary DNS address ([\d\.]+)', self._output)
            if dns2:
                return dns2.group(1)
        return PPP_NONE_IP

    @property
    def iface(self) -> str:
        return self._iface

    def disconnect(self):
        self._stop_event.set()
        if self._state == PPP_CONNECTED:
            self.proc.terminate()
            self._state = PPP_DISCONNECTED

    def disconnect_interval(self, interval_count_10x):
        self._wait = interval_count_10x
        self.proc.terminate()
        self._state = PPP_DISCONNECTED

    def verbose_code(self, code) -> str:
        return PPPD_RETURNCODES.get(code, 'Undocumented error occured')

    def _set_non_bloking(self):
        # set stdout to non-blocking
        fd = self.proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)


# =============================================================================#
def connect():
    print('Connected')


def disconnect(returncode):
    print('Disconnected code:{} is {}'.format(returncode, PPPConnection.verbose_code(returncode)))


def verbose(verb):
    print(verb)


# =============================================================================#
if __name__ == '__main__':
    p = PPPConnection(profile='dweb', connect_func=connect, disconnect_func=disconnect, verbose_func=verbose)
    p.start()
    time.sleep(2)

    while p.state == PPP_CONNECTING:
        time.sleep(1)

    if p.state == PPP_CONNECTED:
        print('Local IP:{} Remoto IP:{} DNS1:{} DNS2:{}'.format(p.local_ip, p.remote_ip, p.dns1, p.dns2))
    else:
        print('Fail to connect...')

    time.sleep(5)
    p.disconnect()
    p.join()
