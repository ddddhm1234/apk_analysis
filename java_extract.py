import string
import javalang.tree
from javalang import *

class StringInfo():
    def __init__(self):
        # 在源代码中的位置
        self.position = None
        # 所在方法名
        self.method = None
        # 所在类名
        self.classname = None
        # 如果是变量, 类成员, 则为名字
        self.vname = None
        # 敏感原因
        self.reason = ""
        # 字符串字面值
        self.value = ""

    def __str__(self):
        s = "[String Privacy]\nmethod: %s.%s\nvarname: %s\nreason: %s\nvalue: %s\nposition: %s" % (self.classname,
                                                                                 self.method,
                                                                                 self.vname,
                                                                                 self.reason,
                                                                                 self.value,
                                                                                 self.position)
        return s

class VarInfo():
    def __init__(self):
        self.position = None
        self.method = None
        self.classname = None
        self.vname = None
        self.value = ""

    def __str__(self):
        s = "[Sensitive Var]\nmethod: %s.%s\nvarname: %s\nvalue: %s" % (self.classname, self.method, self.vname
                                                             , self.value)
        return s

class JavaAnalysis():
    def __init__(self, file):
        with open(file, "r") as f:
            self.source = f.read()
            self.tree = parse.parse(self.source)

    def open_file(self, file):
        with open(file, "r") as f:
            self.source = f.read()
            self.tree = parse.parse(self.source)

    @staticmethod
    def get_parent_name(path: [javalang.tree.Node], parent_class: {str: javalang.tree.Node}):
        values = {}
        for i in range(len(path)):
            cur_node = path[-i]
            for name, class_type in parent_class.items():
                if isinstance(cur_node, class_type):
                    values[name] = cur_node.name
                if len(values.keys()) == len(parent_class.keys()):
                    return values

        return values

    @staticmethod
    def get_position_from_path(path: []):
        for i in range(len(path)):
            cur_node = path[-i]
            if isinstance(cur_node, javalang.tree.Node):
                if cur_node.position is not None:
                    return cur_node.position
        return None

    @staticmethod
    def is_sensitive_string(s: str, path: [javalang.tree.Node]):
        def is_key(s1: str):
            s1 = s1.replace('"', '')
            d_count = 0
            l_count = 0
            # 密钥一般长度是16的整数倍，并且都是数字或字母
            if len(s1) % 16 == 0 and len(s1) > 16:
                for a in s1:
                    if a in string.ascii_letters:
                        l_count += 1
                    elif a in string.digits:
                        d_count += 1
                    else:
                        return False

                if d_count == 0 or l_count == 0:
                    return False
                return True

        def is_url(s1: str):
            s1 = s1.replace('"', '')
            prefix = ["ftp://", "rtsp://"]
            for _ in prefix:
                if s1.startswith(_):
                    return True
            return False

        def get_method_class_vname():
            method_name = None
            class_name = None
            var_name = None
            for i in range(len(path)):
                node = path[-i]
                if isinstance(node, javalang.tree.MethodDeclaration):
                    method_name = node.name
                elif isinstance(node, javalang.tree.ClassDeclaration):
                    class_name = node.name
                    break
                elif isinstance(node, javalang.tree.VariableDeclarator):
                    var_name = node.name
            return method_name, class_name, var_name

        if is_key(s):
            m, c, v = get_method_class_vname()
            r = "key"
        elif is_url(s):
            m, c, v = get_method_class_vname()
            r = "url"
        else:
            return None

        sinfo = StringInfo()
        sinfo.method = m
        sinfo.classname = c
        sinfo.vname = v
        sinfo.position = JavaAnalysis.get_position_from_path(path)
        sinfo.reason = r
        sinfo.value = s
        return sinfo

    @staticmethod
    def level_order_traversal(parent: javalang.tree.Node, callback, *args, **kwargs):
        """
        层次遍历AST中的节点，回调函数原型
        def call_back(node, 自定义参数...):
            # node是遍历到的当前节点
        :param parent: 遍历起始节点
        :param callback: 回调函数
        :param args: 回调函数的自定义参数
        :param kwargs: 回调函数的自定义参数
        :return:
        """
        queue = []
        queue.append(parent)
        while len(queue) > 0:
            for i in range(len(queue)):
                cur_node: Node = queue.pop(0)
                callback(cur_node, *args, **kwargs)
                attrs = cur_node.attrs
                for attr in attrs:
                    child = getattr(cur_node, attr)
                    if isinstance(child, javalang.tree.Node):
                        queue.append(child)
                    elif isinstance(child, list):
                        for sub_child in child:
                            if isinstance(sub_child, javalang.tree.Node):
                                queue.append(sub_child)

    def extract_privacy(self):
        def extract_literal_value(root):
            """
            提取变量初始化语句中的所有字面值
            :param root: 变量初始化节点
            :return: 初始化字面值
            """

            def wrapper(cur_node, cur_value):
                if not isinstance(cur_node, javalang.tree.Literal):
                    return
                cur_value.append(cur_node.value)

            buf = []
            self.level_order_traversal(root, wrapper, buf)
            return buf

        string_privacy = []
        # 通过遍历AST中的字面量提取敏感字符串
        for path, node in self.tree.filter(javalang.tree.Literal):
            if not node.value.startswith('"'):
                continue
            sinfo = self.is_sensitive_string(node.value, path)
            if sinfo:
                string_privacy.append(sinfo)

        var_privacy = []
        for path, node in self.tree.filter(javalang.tree.VariableDeclarator):
            keys = ["password", "passwd", "apikey", "api_key", "sessionkey", "session_key"]
            name_lower = node.name.lower()
            for k in keys:
                if name_lower.find(k) > -1:
                    values = extract_literal_value(node)
                    if len(values) > 0:
                        cur_var = VarInfo()
                        cur_var.value = values
                        cur_var.vname = node.name
                        names = self.get_parent_name(path, {"method": javalang.tree.MethodDeclaration,
                                                    "class": javalang.tree.ClassDeclaration})
                        if "method" in names.keys():
                            cur_var.method = names["method"]
                        if "class" in names.keys():
                            cur_var.classname = names["class"]
                            blocked = ["R", "R2"]
                            if names["class"] in blocked:   # 过滤资源类
                                break
                            if names["class"].startswith("R$"):
                                break
                        cur_var.position = self.get_position_from_path(path)
                        var_privacy.append(cur_var)
                        break

        return string_privacy, var_privacy

    def get_code_snippet_by_position(self, position):
        pass