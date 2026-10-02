import platform
import socket

print("=== System Security Information ===")
print("Hostname:", socket.gethostname())
print("OS:", platform.system())
print("OS Version:", platform.version())
print("Architecture:", platform.machine())
print("Python:", platform.python_version())
