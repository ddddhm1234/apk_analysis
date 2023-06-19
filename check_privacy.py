import os
import platform
import sys
from concurrent import futures

import apk_analysis


def extract_apk(path: str):
    print("[+] START: ", path)
    apk = apk_analysis.ApkAnalysis(path)
    results = apk.analysis_privacy()
    if len(results) == 0:
        print("[+]", path, "NO PRIVACY")
        return

    if platform.system() == "windows":
        p2 = path.split("\\")[-2]
    else:
        p2 = path.split("/")[-2]
    with open(p2 + ".txt", "w") as f:
        for k, v in results.items():
            f.write("[+] File:" + k + "\n")
            for ele in v["string"]:
                f.write(str(ele) + "\n")
                f.flush()

            for ele in v["variable"]:
                f.write(str(ele) + "\n")
                f.flush()


    print("[+]", p2, "WITH PRIVACY")

def main():
    if len(sys.argv) >= 2:
        dir = sys.argv[1]
        dirs = os.listdir(dir)
        tasks = []
        pool = futures.ThreadPoolExecutor(max_workers=16)
        for p in dirs:
            path = os.path.join(dir, p, "out")
            tasks.append(pool.submit(extract_apk, path))

        futures.wait(tasks, None, futures.ALL_COMPLETED)

if __name__ == "__main__":
    main()


