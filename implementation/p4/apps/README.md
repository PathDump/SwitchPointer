# How to run applications

* cd to application directory, then run
``` 
sh run.sh
```
* Mininet CLI would start

## To run ping application
```
xterm h1 h2
```
* On h2, start monitoring agent
``` 
python flow-mon.py 
```
* On h1, run
```
ping -c 1 10.1.1.2
```
* For now, please look at epoch ids printed on the h2 and switchAPI screen.

