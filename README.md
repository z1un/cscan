# cscan

基于`python3`和[httpscan](https://github.com/zer0h/httpscan#httpscan)的多端口c段扫描器。

![](https://i.loli.net/2020/08/14/rmvJuNkgAbRcQTw.png)

用法：

```bash
python cscan.py -i IP/CIDR –t threads
```

例：

```bash
python cscan.py -i 10.20.30.0/24 –t 100
```

默认线程为100

