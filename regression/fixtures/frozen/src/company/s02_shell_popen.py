import subprocess
def run(cmd):
    return subprocess.Popen(cmd, shell=True)
