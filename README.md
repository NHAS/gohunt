# gohunt

```sh
sudo docker run -d --name postgres-gohunt -e POSTGRES_USER=gohunt -e POSTGRES_PASSWORD=gohunt -e POSTGRES_DB=gohunt -p 127.0.0.1:5432:5432 postgres
```


DNS

```
example.com A 1.1.1.1
*.example.com CNAME example.com
```