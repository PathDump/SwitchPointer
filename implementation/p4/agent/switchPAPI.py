from bm_runtime.standard import Standard
import bmpy_utils as utils
from bm_runtime.simple_pre import SimplePre
import math
from time import sleep
import json
import sys
from datetime import datetime

K=3
ALPHA=10
REG_SIZE=32 #bits
fch_config=''
thrift_port=9090

class switchPTimer():
    
    def __init__(self, thrift_ip="127.0.0.1",thrift_port=9090,services=[('standard',Standard.Client),('simple_pre',SimplePre.Client)]):
        self.client, mc_client=utils.thrift_connect(thrift_ip,thrift_port,services)
        self.level_epoch_data={}
        self.ptr_reg_name='pointers'
        self.level_reg_name='level_pointer_idx'
        self.fch_reg_name='fch_reg'
        self.g_reg_name='g_reg'
        self.epoch_reg_name='epochid_reg'
        self.key_ipaddrs={}
        self.epoch_id=0
        self.init_fch()
        self.init_levels()
    
    def init_fch(self):
        print 'configuring fch'
        fch_data=json.load(open(fch_config))
        self.NUM_KEYS=fch_data['m']
        self.PNTR_SIZE=(self.NUM_KEYS/REG_SIZE) #In num of registers

        self.write_reg_idx(self.fch_reg_name,0,0)
        self.write_reg_idx(self.fch_reg_name,1,fch_data['m'])
        self.write_reg_idx(self.fch_reg_name,2,fch_data['b'])
        self.write_reg_idx(self.fch_reg_name,3,fch_data['p1'])
        self.write_reg_idx(self.fch_reg_name,4,fch_data['p2'])
        self.write_reg_idx(self.fch_reg_name,5,fch_data['h1_seed'])
        self.write_reg_idx(self.fch_reg_name,6,fch_data['h2_seed'])
        for x in range(fch_data['b']):
            self.write_reg_idx(self.g_reg_name,x,fch_data['garray'][x])
        for x in fch_data['key_ipaddr_arr']:
            key_ipaddr=x.split('-')
            self.key_ipaddrs.update({key_ipaddr[0]:key_ipaddr[1]})
        

    def init_levels(self):
        print 'configuring switchp multi-level pointers'
        for level in range(K):
            self.level_epoch_data.update({level:{'clock':0,'trigger':math.pow(ALPHA,level+1),'pointer_idx':0,'s_epochid':0,'e_epochid':0}})
    
    
    def start_timer(self):
        print 'started timer'
        while(True):
            for level in range(K):
                e=self.level_epoch_data[level]
                if e['clock']==e['trigger']:
                    e['clock']=0
                    e['s_epochid']=e['e_epochid']
                    e['e_epochid']=self.epoch_id
                    curr_pntr_idx=e['pointer_idx']
                    nxt_pntr_idx=(curr_pntr_idx+1)%ALPHA

                    #Reset next pointer
                    start_reg_idx=((level*ALPHA)+nxt_pntr_idx)*self.PNTR_SIZE
                    end_reg_idx=start_reg_idx+self.PNTR_SIZE-1
                    #print 'level',level,'start',start_reg_idx,'end',end_reg_idx
                    #start=datetime.now()
                    self.reset_reg_range(self.ptr_reg_name,start_reg_idx,end_reg_idx)
                    #print 'time to reset',(datetime.now()-start).total_seconds()
                    
                    #Move to next pointer
                    e['pointer_idx']=nxt_pntr_idx
                    self.write_reg_idx(self.level_reg_name, level,nxt_pntr_idx)
                    self.write_reg_idx(self.epoch_reg_name, 0, self.epoch_id)
                    start_reg_idx=((level*ALPHA)+curr_pntr_idx)*self.PNTR_SIZE
                    end_reg_idx=start_reg_idx+self.PNTR_SIZE-1
                    if level==K-1:
                        #print 'level',level,'start',start_reg_idx,'end',end_reg_idx
                        self.get_ipaddrs(e['s_epochid'],e['e_epochid'],self.read_reg_range(self.ptr_reg_name,start_reg_idx,end_reg_idx))
                e['clock'] += ALPHA
            sleep(ALPHA/1000.0)
	    self.epoch_id +=1
    
    def get_ipaddrs(self,s,e,epochptrs):
        key=0
        for ptr in epochptrs:
            print 'pnt val:',ptr
            for x in range(32):
                if(ptr & (1<<x)):
                    print 'Epochid range start',s,'end',e,'Seen IP:',self.key_ipaddrs[str(key)]
                key += 1

    def read_reg_idx(self,reg_name,idx):
        return self.client.bm_register_read(0, reg_name, idx)

    def read_reg_idx_all(self, reg_name):
        return self.client.bm_register_read_all(0, reg_name)
    
    def write_reg_idx(self, reg_name,idx,val):
        return self.client.bm_register_write(0, reg_name, idx, val)

    def read_reg_range(self, reg_name,start_idx,end_idx):
        return [self.client.bm_register_read(0,reg_name, x) for x in range(start_idx,end_idx+1)]
    
    def write_reg_range(self, reg_name,start_idx,end_idx,val):
        for x in range(start_idx,end_idx+1):
            self.client.bm_register_write(0, reg_name, x, val)

    def reset_reg_idx(self, reg_name, idx):
        self.client_bm_register_write(0, reg_name, idx, 0)
    
    def reset_reg_range(self, reg_name,start_idx,end_idx):
        for x in range(start_idx,end_idx+1):
            #print 'reg_idx',x
            self.client.bm_register_write(0, reg_name, x, 0)


def main():
    cli=switchPTimer(thrift_port=thrift_port)
    cli.start_timer()
    #print cli.read_reg_idx('pointers',60)

if __name__ == '__main__':
    if len (sys.argv) == 3:
        fch_config = sys.argv[1]
	thrift_port=int(sys.argv[2])
    else:
        fch_config='64_keys.json'
	thrift_port=9090
    main()
            
