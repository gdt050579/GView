git clone https://github.com/microsoft/vcpkg vcpkg
cd vcpkg
call bootstrap-vcpkg.bat
vcpkg.exe integrate install
vcpkg.exe install openssl:x64-windows
