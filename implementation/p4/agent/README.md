# Configure and start P4 switch
```
python switchPAPI.py <json file> <thrift port>
```

```
Ex: python switchPAPI.py 64_keys.json 9090
```

* json file: Contains output of CMPH library. Code to generate new json files will be released soon
* thrift port: Port on which P4 switch control plane listens to. Default port numbers are 9090, 9091, 9092...

