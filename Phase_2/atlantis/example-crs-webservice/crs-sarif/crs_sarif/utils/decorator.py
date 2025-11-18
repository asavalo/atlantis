def singleton(cls):
    _instances = {}

    def get_instance(*args, force_new_instance=False, **kwargs):
        if force_new_instance or cls not in _instances:
            _instances[cls] = cls(*args, **kwargs)

        return _instances[cls]

    return get_instance
