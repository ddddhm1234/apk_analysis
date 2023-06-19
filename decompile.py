import os
import sys
from concurrent import futures

def decompile_apk(file):
    EXE = "jadx -d %s %s"  # 1: 输出目录, 2: apk名
    EXE %= (os.path.join(os.path.dirname(file), "out"), file)
    os.system(EXE)

def main():
    if len(sys.argv) < 2:
        return -1

    path = sys.argv[1]
    if not os.path.exists(path):
        print("文件不存在")
        return -1

    if os.path.isfile(path):
        decompile_apk(path)
    elif os.path.isdir(path):
        dirs = os.listdir(path)
        for file in dirs:
            if os.path.isdir(os.path.join(path, file)):
                p1 = os.path.join(path, file, file + ".apk")
                decompile_apk(p1)

if __name__ == "__main__":
    main()