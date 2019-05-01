
#
# Copyright (c) 2013 - 2016 MasterCard International Incorporated
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are 
# permitted provided that the following conditions are met:
# 
# Redistributions of source code must retain the above copyright notice, this list of 
# conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of 
# conditions and the following disclaimer in the documentation and/or other materials 
# provided with the distribution.
# Neither the name of the MasterCard International Incorporated nor the names of its 
# contributors may be used to endorse or promote products derived from this software 
# without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
# SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER 
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
# SUCH DAMAGE.
#

import json

class Domain:

    def __init__(self, values = None):
        if values is None:
            values = {}
        for key, value in values.iteritems():
            self.__dict__[key] = build_payment_object(key, value)

        if "id" in self.__dict__:
            self.object_id =  self.__dict__["id"]

    def __getitem__(self, key):
        if key in self.__dict__:
            return self.__dict__[key]

    def __setitem__(self, key, value):
        self.__dict__[key] = value

    def to_dict(self):

        d = dict()
        for key, value in self.__dict__.iteritems():
            if isinstance(value, Domain):
                d[key] = value.to_dict()
            else:
                d[key] = value
        return d

    def class_name(self):
        return self.__class__.__name__.lower()

    def __str__(self):
        return json.dumps(self.to_dict(), sort_keys = True, indent = 2, cls = PaymentObjectEncoder)

class PaymentObjectEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Domain):
            return obj.to_dict()
        else:
            return json.JSONEncoder.default(self, obj)

def build_payment_object(typ, value):
    if isinstance(value, dict):
        return DomainFactory.factory(typ, value)
    else:
        return value

class DomainFactory(object):

    cache = {}

    @classmethod
    def factory(cls, module_name, values = None, fail_on_error = False):

        class_name = module_name[0].upper() + module_name[1:]
        try:
            if class_name in cls.cache:
                class_ = cls.cache[class_name]
            else:
                module_ = __import__('simplify')
                class_ = getattr(module_, class_name)
                cls.cache[class_name] = class_
            if isinstance(values, dict):
                return class_(values)
            else:
                return class_()
        except AttributeError as e:
            if fail_on_error:
                raise e
            else:
                return DomainFactory.factory("domain", values, True)
