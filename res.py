#!/usr/bin/python3
# -*- coding: utf-8 -*-

import yaml


# =============================================================================#
class RResource:
    def __init__(self, resfilename):
        self._resfilename = resfilename
        self.__f = open(resfilename, "r")
        self.data = yaml.load(self.__f)

    @property
    def ressfilename(self):
        return self._resfilename

    def get_resource(self, resname):
        try:
            r = self.data[resname]
            return r
        except KeyError:
            return ""

    def get_fresource(self, resname, *args):
        try:
            r = str(self.data[resname])
            r = r.format(*args)
            return r
        except KeyError:
            return ""

    def close(self):
        self.__f.close()


# =============================================================================#
def teste():
    r = RResource('res.txt')
    print(r.get_resource('title1'))
    a = ["teste.txt", r.get_resource('sistema1'), 32]
    print(r.get_fresource('arquivo_nao_existe', *a))
    print(r.get_fresource('arquivo_nao_existe', "teste.txt", r.get_resource('sistema1'), 32))
    print(r.get_fresource('url_nao_encontrada', "www.teste.com", 8080))
    r.close()


# =============================================================================#
import unittest


class TestCommon(unittest.TestCase):
    def test_res(self):
        teste()


# =============================================================================#
if __name__ == '__main__':
    unittest.main()
