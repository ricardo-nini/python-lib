#!/usr/bin/python3
# -*- coding: utf-8 -*-

import platform


def isRaspberry() -> bool:
    return (platform.uname().node == 'raspberrypi' or platform.uname().node == 'demanda')


def isSunxi() -> bool:
    return ('sunxi' in platform.uname().release or 'OrangePI' in platform.uname().node)


if isSunxi():
    import OPi.GPIO as GPIO
elif isRaspberry():
    import RPi.GPIO as GPIO
else:
    raise Exception('Not know processor !')


def getmode():
    return GPIO.getmode()


def setmode(mode):
    GPIO.setmode(mode)


def setwarnings(enabled):
    GPIO.setwarnings(enabled)


def setup(channel, direction, pull_up_down=None):
    if isRaspberry():
        if direction == GPIO.IN and pull_up_down:
            GPIO.setup(int(channel), direction, pull_up_down=pull_up_down)
        else:
            GPIO.setup(int(channel), direction)
    else:
        if not channel in GPIO._exports:
            GPIO.setup(channel, direction)


def input(channel):
    if isRaspberry():
        return GPIO.input(int(channel))
    else:
        return GPIO.input(channel)


def output(channel, state):
    if isRaspberry():
        GPIO.output(int(channel), state)
    else:
        GPIO.output(channel, state)


def cleanup(channel=None):
    if isRaspberry():
        GPIO.cleanup(int(channel))
    else:
        GPIO.cleanup(channel)


def wait_for_edge(channel, trigger, timeout=-1):
    if isRaspberry():
        GPIO.wait_for_edge(int(channel), trigger, timeout)
    else:
        GPIO.wait_for_edge(channel, trigger, timeout)


def add_event_detect(channel, trigger, callback=None, bouncetime=None):
    if isRaspberry():
        GPIO.add_event_detect(int(channel), trigger, callback, bouncetime)
    else:
        GPIO.add_event_detect(channel, trigger, callback, bouncetime)


def remove_event_detect(channel):
    if isRaspberry():
        GPIO.remove_event_detect(int(channel))
    else:
        GPIO.remove_event_detect(channel)


def add_event_callback(channel, callback, bouncetime=None):
    if isRaspberry():
        GPIO.add_event_callback(int(channel), callback, bouncetime)
    else:
        GPIO.add_event_callback(channel, callback, bouncetime)


def event_detected(channel):
    if isRaspberry():
        GPIO.event_detected(int(channel))
    else:
        GPIO.event_detected(channel)
