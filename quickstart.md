
## 准备工作

- 安装NodeJS
- 安装PostgreSQL
- 安装Redis
- 安装Python27

## 前端

```PowerShell
> npm install
```

安装完成后可以启动前端服务

```PowerShell
> npm run start
```

### 编译前端代码（可略过）

> 注意：由于我把`client/dist`加进了仓库，所以可以略过该步骤。

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

配置环境变量，这里在主目录下创建`.env`文件，并通过`pipenv shell`自动加载。

```
# .env
DATABASE_URL = "postgresql://postgres:postgres@127.0.0.1:5432/redash"
```

同时手动创建redash数据库。

### 数据库

```PowerShell
pipenv install
pipenv shell
python manage.py database create_tables
python manage.py run
```

最后访问`http://127.0.0.1:5000`即可。

## 主页截图

![index](screenshot/index.png)
