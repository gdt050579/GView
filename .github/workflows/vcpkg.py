import os

cwd = os.path.dirname(os.path.realpath(__file__))
print('CWD: ' + cwd)
os.chdir(cwd)             
os.system("call vcpkg.bat")
