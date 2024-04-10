# mitmproxy-copilot

为了简化 mitmproxy 的使用，建议通过容器化部署 mitmproxy-copilot，这样可以避免因为 mitmproxy 的版本不同导致的问题。

1. Dockerfile 用于生成 mitmproxy-copilot 镜像；
2. proxy-es.py 用于在mitmproxy中使用elasticsearch存储数据，可以通过此脚本对mitmproxy进行扩展；
3. creds.txt 用于存储用户名和密码，用于mitmproxy的认证；


## 部署架构

![Architecture](https://github.com/nickhou1983/mitmproxy-copilot/blob/main/image.png)

## 资源配置

| 服务器 | 规格 | 数量 | 用途 |
| --- | --- | --- | --- |
| mitmproxy | 4C16G 200GDisk | 1 | 部署mitmproxy
| elasticsearch | 2C8G 500GDisk | 3 | 存储mitmproxy数据
| kibana | 2C8G 200GDisk | 1 | 可视化mitmproxy数据


## 使用方法

1. 在部署mitmproxy的服务器上安装 Docker，参考 [Docker 安装文档](https://docs.docker.com/get-docker/)
```
yum install -y yum-utils
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
yum install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
2. 通过 Dockerfile 构建镜像
```
docker build . -t mitmproxy-copilot:v1
```

3. 运行容器
```
docker run -d --net="host" mitmproxy-copilot:v1
```