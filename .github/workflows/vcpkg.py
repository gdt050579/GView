import os

cwd = os.path.dirname(os.path.realpath(__file__))
os.chdir(cwd)             
os.system("call vcpkg.bat")
