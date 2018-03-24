from tkinter import *
import datetime
import time
import threading 
import socket
import sys
from Crypto.Cipher import AES

HOST="127.0.0.1"
SERVER_PORT=5007 
CLIENT_PORT=5008
ENCODING="utf-8"
OFFSET=16
KEY=int(19970903)
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
## id of sender
## numbers of reciever 
## ids of recievers (optional)
## names 
# length of name    (optional)
# name
## message          (optional)
#writer=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
commons=["Success!\n"]
client_name=''
client_id=0
users_db={}
users_id={}

login_flag=0

KEY = b'nixuyiygnijuiluw'
cipher = AES.new(KEY, AES.MODE_ECB)

def send_local(sender,content):
    if sender:
        msgcontent = sender + ":"+time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()) + '\n '
    else:
        msgcontent = "sender" + ":"+time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()) + '\n '
    text_msglist.insert(END, msgcontent, 'green')
    #
    if content:
        text_msglist.insert(END, content)
    else:
        text_msglist.insert(END, text_msg.get('0.0', END))
    text_msg.delete('0.0', END)
    return
 
def itob(x):
    return x.to_bytes(4,"big")

def btoi(x):
    return int.from_bytes(x,"big")

def client_pack(opcode,sender,recievers,msg):
    msgb=bytes(msg,ENCODING)
    header=itob(opcode)+itob(len(msgb))+itob(sender)+itob(len(recievers))
    header=cipher.encrypt(header)
    for r in recievers:
        header+=itob(r)
    return header+msgb

def client_unpack(raw_msg):
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
    
def reader():
    global writer
    global login_flag
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((HOST,CLIENT_PORT))
    s.listen(1)
    s.settimeout(5)
    try:
        conn,addr=s.accept()
    except socket.timeout:
        s.close()
        try:
            writer.shutdown(socket.SHUT_RDWR)
        except:
            pass
        writer.close()
        send_local("Local","Log in failed\n")

        print("Timeout.\n")
        pass
        return

    s.settimeout(None)
    s.close()
    conn.settimeout(None)
    while True:
        data=conn.recv(1024)

        if not data:
            break
        opcode,length,sender,nums,recievers,msg,raw_msg=client_unpack(data)

        if opcode==INIT:
            login_flag=1
            server_init(recievers,raw_msg)

        elif opcode==RECIEVE:
            if sender in users_db.keys():
                send_local(users_db[sender],msg)

        elif opcode==ADD:
            add_tab(recievers,raw_msg)

        elif opcode==DELETE:
            i = lb.get(0, END).index(users_db[sender])
            lb.delete(i)
            users_id.pop(users_db[sender])
            users_db.pop(sender)
            
        elif opcode==TEND:
            login_flag=0
            send_local("Server",msg)
            break
        else:
            print("invalid opcode\n")
            break

    print("reader exit:",threading.currentThread().name)
    conn.shutdown(socket.SHUT_RDWR)
    conn.close()

def server_init(ids,raw_msg):
    global client_name,client_id
    offset=0
    for id in ids:
        length=btoi(raw_msg[offset:offset+4])
        offset+=4
        name=str(raw_msg[offset:offset+length],encoding=ENCODING)
        lb.insert(END,name)
        offset+=length
        if client_name==name:
            client_id=id
            print("id",client_id)
        users_db[id]=name
        users_id[name]=id

    send_local("Server",commons[0])

def log_in():
    global login_flag
    if login_flag==1:
        send_local("Local","Please log out first.\n")
        return
    try:
        password=int(entry_pass.get())
    except:
        send_local("Local","Please enter your password.\n")
        return
    threading.Thread(target=reader,args=[]).start()
    global writer
    try:
        writer=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        writer.connect((HOST,SERVER_PORT))
    except:
        send_local("Local","Server not in service.\n")
        writer.close()
        return
    name=text_msg.get('0.0', END)
    text_msg.delete('0.0', END)
    global client_name
    client_name=name[:-1]
    print("client name:",client_name)
    msg=client_pack(LOGIN,password,[],name)
    writer.sendall(msg)
    return

def log_out():
    global login_flag
    if login_flag==0:
        send_local("Local","Please log in first.\n")
        return
    global writer,client_id,client_name,users_db,users_id
    msg=client_pack(LOGOUT,client_id,[],'')
    writer.sendall(msg)
    writer.shutdown(socket.SHUT_RDWR)
    writer.close()
    client_name=''
    client_id=0
    users_db={}
    users_id={}
    lb.delete(0,END)
    return

def sign_in():
    global login_flag
    if login_flag==1:
        send_local("Local","Please log out first.\n")
        return
    try:
        password=int(entry_pass.get())
    except:
        send_local("Local","Please enter your password.\n")
        return
    try:
        agent=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        agent.connect((HOST,SERVER_PORT))
    except:
        send_local("Local","Server not in service.\n")
        agent.close()
        return
    password=int(entry_pass.get())
    name=text_msg.get('0.0', END)
    text_msg.delete('0.0', END)
    msg=client_pack(SIGNIN,password,[],name)
    agent.sendall(msg)
    data=agent.recv(1024)
    opcode,length,sender,nums,recievers,msg,raw_msg=client_unpack(data)
    send_local("Server",msg)
    agent.shutdown(socket.SHUT_RDWR)
    agent.close()
    return

def send_remote():
    global login_flag
    if login_flag==0:
        send_local("Local","Please log in first.\n")
        return
    global writer
    message=text_msg.get('0.0', END)
    text_msg.delete('0.0', END)
    recievers=[]
    ids=lb.curselection()
    print(ids)
    for id in ids:
        recievers.append(users_id[lb.get(id)])
    msg=client_pack(SEND,client_id,recievers,message)
    writer.sendall(msg)
    return

def add_tab(ids,raw_msg):
    offset=0
    for id in ids:
        length=btoi(raw_msg[offset:offset+4])
        offset+=4
        name=str(raw_msg[offset:offset+length],encoding=ENCODING)
        lb.insert(END,name)
        offset+=length
        users_db[id]=name
        users_id[name]=id
    
## UI

root = Tk()
#root.geometry("680x430")
root.title("Chat Room")
#frames
left_top   = Frame(width=380, height=270, bg='white')
left_center  = Frame(width=380, height=100, bg='white')
left_bottom  = Frame(width=380, height=60)
right_top     = Frame(width=300, height=370)
right_bottom     = Frame(width=300, height=60)
#objects

text_msglist    = Text(left_top,wrap=WORD)
text_msg      = Text(left_center,wrap=WORD)
entry_pass = Entry(right_bottom,show='*')
scroll_1 = Scrollbar(left_top)
button_send   = Button(left_bottom, text='Send', command=send_remote)
button_login   = Button(left_bottom, text='Log In', command=log_in)
button_logout   = Button(left_bottom, text='Log Out', command=log_out)
button_signin   = Button(left_bottom, text='Sign In', command=sign_in)
#abel = Label(left_bottom, text='User Name')
label_p=Label(right_bottom, text='Password')
#text_name =Text(left_bottom)
lb = Listbox(right_top,selectmode = MULTIPLE,width=200,height=370)
#tags
text_msglist.tag_config('green', foreground='#008B00')
#grid
left_top.grid(row=0, column=0, padx=2, pady=5)
left_center.grid(row=1, column=0, padx=2, pady=5)
left_bottom.grid(row=2, column=0)
right_top.grid(row=0, column=1, rowspan=2, padx=4, pady=5)
right_bottom.grid(row=2, column=1)
left_top.grid_propagate()
left_center.grid_propagate()
left_bottom.grid_propagate()
right_bottom.grid_propagate(0)
right_top.grid_propagate(0)
#layout
text_msglist.grid(row=0,column=0)
text_msg.grid()
button_login.grid(row=0,column=0,padx=5)
button_logout.grid(row=0,column=1,padx=5)
button_signin.grid(row=0,column=2,padx=5)
button_send.grid(row=0,column=3,padx=5)
label_p.grid(row=0,column=0)
entry_pass.grid(row=0,column=1)
lb.grid(sticky=N+S)
#lb.pack(expand=True,fill="both")
text_msglist.configure(yscrollcommand=scroll_1.set)
scroll_1.grid(row=0,column=1)
scroll_1.configure(command=text_msglist.yview)
send_local("Local","Please log in with your name or sign in with a new name.\n")
root.mainloop()