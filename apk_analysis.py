import os
import java_extract


class ApkAnalysis:
    def __init__(self, dir):
        if not os.path.exists(os.path.join(dir, "sources")):
            raise FileNotFoundError("<dir>/sources目录不存在, 没有正确指定jadx反编译结果目录")
        self.dir = dir

    def analysis_privacy(self):
        queue = []
        r = os.path.join(self.dir, "sources")
        queue.append(r)
        results = {}
        # 排除第3方库
        blocked = ["android", "google", "javax", "kotlin", "okhttp", "opencv", "alibaba", "jsse", "netty",
                   "spongycastle", "bouncycastle"]
        while len(queue) > 0:
            root = queue.pop(0)
            files = os.listdir(root)
            for file in files:
                for _ in blocked:
                    if file.find(_) > -1:
                        break
                else:
                    file_path = os.path.join(root, file)
                    if os.path.isdir(file_path):
                        queue.append(file_path)
                    elif os.path.isfile(file_path):
                        if file.lower().endswith(".java"):
                            try:
                                java = java_extract.JavaAnalysis(file_path)
                            except:
                                continue
                            sp, vp = java.extract_privacy()
                            if len(sp) > 0 or len(vp) > 0:
                                results[file_path] = {"string": sp, "variable": vp}
                            del java

        return results

