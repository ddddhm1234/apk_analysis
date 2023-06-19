### 使用说明
1. 环境要求
* pip3 install javalang
* 安装jadx，并将jadx添加至环境变量

2. 使用说明
1. python3 decompile.py <APP目录>
2. python3 check_privacy.py <APP目录>
3. 在当前目录下生成对每个APP的检测结果

APP目录的目录结构如下所示，APP名/APP名.apk
```
☁  priv-app  tree -L 2 
.
├── BackupRestoreConfirmation
│   ├── BackupRestoreConfirmation.apk
│   ├── oat
│   └── out
├── BlockedNumberProvider
│   ├── BlockedNumberProvider.apk
│   ├── oat
│   └── out
```

生成的检测结果如下所示，FILE表示所在文件
```
[+] File:Radio***.java
[String Privacy]
method: RadioApi.None
varname: API_KEY
reason: key
value: "***************************"
position: Position(line=32, column=25)
[Sensitive Var]
method: RadioApi.None
varname: API_KEY
value: ['"***************************"']
```