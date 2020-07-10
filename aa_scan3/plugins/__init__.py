import glob
import os.path
import importlib.util

files = [f for f in glob.glob(os.path.join(os.path.dirname(__file__), "*.py"))
         if os.path.isfile(f) and not os.path.basename(f) == "__init__.py"]

plugins = {}
for f in files:
    p_name = os.path.basename(f)[:-3]
    name = "aa_scan3.{}".format(p_name)
    spec = importlib.util.spec_from_file_location(name, f)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    plugins[p_name] = mod

del p_name, name, spec, mod
