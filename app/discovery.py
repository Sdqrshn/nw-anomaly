import subprocess

ip = "192.168.1.1"

result = subprocess.run(
    ["ping", "-n", "1", ip],
    capture_output=True,
    text=True
)

print(result.stdout)