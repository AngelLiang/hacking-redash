# Quick Start

在Windows 10环境下运行该工程的配置步骤。

## 准备工作

- 安装PostgreSQL
- 安装Redis
- 安装NodeJS
- 安装Python27
- 安装[Microsoft Visual C++ 9.0](`http://aka.ms/vcpython27`)

## 前端

### 安装

```PowerShell
> npm install
```

安装完成后可以启动前端服务

```PowerShell
> npm run start
```

### 编译前端代码（可略过）

> 注意：由于我已经把编译好的文件夹`client/dist`加进仓库了，所以可以略过该步骤。

```PowerShell
> npm run clean
> webpack
# 由于是Windows的PowerShell环境，不能使用下面命令
# npm run build
```

检查主目录下的`client/dist`文件夹，有文件则说明编译通过


#### 报错解决方案

报错一

```
error  Expected linebreaks to be 'LF' but found 'CRLF'  linebreak-style
```

打开`client/.eslintrc.js`文件，在`rules`后面添加

```
"linebreak-style": [0 ,"error", "windows"], //允许windows开发环境
```

目前工程已经修改。



## 后端

### Python环境初始化

```PowerShell
# 由于依赖冲突，暂时无法锁定版本
pipenv install --skip-lock
pipenv shell
```

### 配置环境变量

配置环境变量，这里在主目录下创建`.env`文件，并通过`pipenv shell`自动加载。

```
# .env
DATABASE_URL = "postgresql://postgres:postgres@127.0.0.1:5432/redash"
```

同时手动创建redash数据库。

### 数据库

```PowerShell
pipenv shell
python manage.py database create_tables
```

### 启动服务

```PowerShell
python manage.py run
```

```PowerShell
$env:FORKED_BY_MULTIPROCESSING=1
pipenv shell
celery worker -A redash.worker -P eventlet -l info -Q queries,scheduled_queries,celery,schemas --maxtasksperchild=10 -Ofair
```

```PowerShell
# 可以不用执行
celery beat -A redash.worker
```

最后访问`http://127.0.0.1:5000`即可。

### 安装报错解决方案

错误一：无法安装mysql-python

解决方法

到[这里](https://www.lfd.uci.edu/~gohlke/pythonlibs/#mysql-python)下载 mysql-python 扩展包并安装（Win32版本已经放到`install-ext`文件夹里了）。

```PowerShell
pipenv install install-ext\MySQL_python-1.2.5-cp27-none-win32.whl --skip-lock
```

错误二：无法安装sasl

解决方法同上。

```PowerShell
pipenv install install-ext\sasl-0.2.1-cp27-cp27m-win32.whl --skip-lock
```

错误三：Windows下Celery无法启动

```PowerShell
pipenv install eventlet --skip-lock
pipenv shell
celery worker -A redash.worker -P eventlet -l info -Q queries,scheduled_queries,celery,schemas --maxtasksperchild=10 -Ofair
```

错误四：无法安装pycrypto

到`http://aka.ms/vcpython27`下载并安装Microsoft Visual C++ 9.0。


## 执行测试

```PowerShell
# Python27 in Windows
python -m unittest discover -v
```

## 主页截图

![setup](screenshot/setup.png)

![index](screenshot/index.png)

![setting](screenshot/setting.png)

## 相关链接

- (Developer Guide)[https://redash.io/help/open-source/dev-guide]


