import socket
import threading
import sys
import queue
from Crypto.Cipher import AES

ENCODING="utf-8"
HOST=""
SERVER_PORT=5007
CLIENT_PORT=5008

KEY = b'WuLiuJingYiYuXin'
cipher = AES.new(KEY, AES.MODE_ECB)

### structure
## command type
# client side
LOGIN=0
LOGOUT=1
SIGNIN=2
SEND=3
# server side 
FAIL=4
INIT=5
CREATE=6
ADD=7
DELETE=8
RECIEVE=9
TEND=10
## total length(header not included)
## id of sender (password)
## number of recievers 
## ids of recievers (optional)
## names 
# length of name    (optional)
# name
## message          (optional)

users_db={"server":0,"henry":1}
users_id={0:"server",1:"henry"}
commons=["Log in failed!\n","Sign in failed\n"]
users_code={"henry":123}
infos={}

def writer(userid,addr):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((addr,CLIENT_PORT))
    while True:
        msg=infos[userid].get()
        s.sendall(msg[1])
        if msg[0]==0:
            break
    infos.pop(userid)
    print("Writer for No."+str(userid)+" exit.\n")
    s.shutdown(socket.SHUT_RDWR)
    s.close()

def log_in(userid,addr):

    infos[userid]=queue.Queue()
    threading.Thread(target=writer,args=[userid,addr]).start()
    content=bytes()
    for id in infos.keys():
        raw=bytes(users_id[id],ENCODING)
        content+=itob(len(raw))
        content+=raw
    msg=server_cat(INIT,users_db["server"],infos.keys(),content)
    infos[userid].put((1,msg))
    raw=bytes(users_id[userid],ENCODING)
    for id in infos.keys():
        if id!=userid:
            msg=server_cat(ADD,users_db["server"],[userid],itob(len(raw))+raw)
            infos[id].put((1,msg))
    return 

def log_out(userid):
    for id in infos.keys():
        if id!=userid:
            msg=server_pack(DELETE,userid,[],'')
            infos[id].put((1,msg))
    msg=server_pack(TEND,users_db["server"],[],"bye!\n")
    infos[userid].put((0,msg))
    return

def sign_in(msg,password):
    new_id=0
    while True:
        if new_id not in users_id.keys():
            users_id[new_id]=msg
            users_db[msg]=new_id
            users_code[msg]=password
            break
        new_id+=1
    return server_pack(CREATE,users_db["server"],[],"Signin success!\n")


def send(sender,recievers,raw_msg):
    for id in recievers:
        msg=server_cat(RECIEVE,sender,[id],raw_msg)
        if id in infos.keys():
            infos[id].put((1,msg))


def reader(fd,addr):
    while True:
        data=fd.recv(1024)

        if not data:
            break
        opcode,length,sender,nums,recievers,msg,raw_msg=server_unpack(data)

        if opcode==LOGIN:
            if msg[-1]=='\n':
                msg=msg[:-1]
            if msg in users_db.keys() and users_code[msg]==sender\
             and users_db[msg] not in infos.keys():
                log_in(users_db[msg],addr)
            else:
                new_msg=server_pack(FAIL,users_db["server"],[],commons[0])
                fd.sendall(new_msg)
                break
        
        elif opcode==LOGOUT:
            log_out(sender)
            break

        elif opcode==SIGNIN:
            if msg[-1]=='\n':
                msg=msg[:-1]
            if msg not in users_db.keys():
                new_msg=sign_in(msg,sender)
            else:
                new_msg=server_pack(FAIL,users_db["server"],[],commons[1])
            fd.sendall(new_msg)
            break

        elif opcode==SEND:
            send(sender,recievers,raw_msg)

        else:
            print("invalid opcode\n")
            break

    print("reader exit:"+threading.currentThread().name+"\n")
    fd.shutdown(socket.SHUT_RDWR)
    fd.close()

def btoi(x):
    return int.from_bytes(x,"big")

def itob(x):
    return x.to_bytes(4,"big")

def server_pack(opcode,sender,recievers,msg):
    msgb=bytes(msg,ENCODING)
    header=itob(opcode)+itob(len(msgb))+itob(sender)+itob(len(recievers))
    header=cipher.encrypt(header)
    for r in recievers:
        header+=itob(r)
    return header+msgb

def server_cat(opcode,sender,recievers,msgb):
    header=itob(opcode)+itob(len(msgb))+itob(sender)+itob(len(recievers))
    header=cipher.encrypt(header)
    for r in recievers:
        header+=itob(r)
    return header+msgb

def server_unpack(raw_msg):
    raw_msg_d=cipher.decrypt(raw_msg[0:16])
    opcode=btoi(raw_msg_d[0:4])
    length=btoi(raw_msg_d[4:8])
    sender=btoi(raw_msg_d[8:12])
    nums=btoi(raw_msg_d[12:16])
    recievers=[]
    i=0
    while i<nums:
        recievers.append(btoi(raw_msg[16+4*i:20+4*i]))
        i+=1
    msg=str(raw_msg[16+4*i:],encoding=ENCODING)
    print(str(opcode)+'\n'+str(length)+'\n'+str(sender)+'\n'+str(nums)+'\n')
    print(msg)
    return opcode,length,sender,nums,recievers,msg,raw_msg[16+4*i:]

if __name__ == "__main__":

    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((HOST,SERVER_PORT))
    s.listen(10)
   
    while True:
        conn,addr=s.accept()
        if conn:
            print("Connected by",addr)
            print("Thread numbers:"+str(threading.activeCount())+'\n')
        threading.Thread(target=reader,args=[conn,addr[0]]).start()

    
    

