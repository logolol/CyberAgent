import importlib
try:
    importlib.import_module("os")
except Exception as e:
    err = str(e)
    print(f"{err:.60}")
