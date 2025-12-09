import copy
import threading


__version__ = 20250716.1


class ThreadSafeVariable:

    storage = threading.local()
    master_thread = threading.current_thread()
    defaults = {}
    
    @staticmethod
    def ensure_vars():
        if getattr(ThreadSafeVariable.storage, "vars", None) is None:
            ThreadSafeVariable.storage.vars = {}

    def __set__(self, instance, value):
        key = "%s.%s" % (id(instance), id(self))
        if self.master_thread == threading.current_thread():
            self.defaults[key] = value
        self.ensure_vars()
        self.storage.vars[key] = value

    def __get__(self, instance, owner):
        key = "%s.%s" % (id(instance), id(self))
        self.ensure_vars()
        try:
            return self.storage.vars[key]
        except KeyError: 
            return self.defaults.get(key)

    @staticmethod
    def freeze():
        ThreadSafeVariable.ensure_vars()
        return copy.copy(ThreadSafeVariable.storage.vars)

    @staticmethod
    def restore(image):
        ThreadSafeVariable.ensure_vars()
        ThreadSafeVariable.storage.vars = copy.copy(image)
