# coding:utf-8
__author__='zjgcjy'

from idaapi import *
from idautils import *
from idc import *
import os

# 没用到，效果不好，或者说dbg_library_load更方便
def Modules():
    mod = idaapi.module_info_t()
    result = idaapi.get_first_module(mod)
    while result:
        yield idaapi.object_t(name=mod.name, size=mod.size, base=mod.base, rebase_to=mod.rebase_to)
        result = idaapi.get_next_module(mod)

class MyDbgHook(DBG_Hooks):
    #GIF计数
    count = 0
    #保存目录
    savepath = "C:\\Users\\xxxxxx\\Desktop\\emotion"
    keyLocation = 0

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        #不要在这里插入断点
        #for i in Modules():
        #   if 'WeChatWin.dll' in i.name:
        #       print "module:[%s]\tsize:[%#x]\tbase:[%#x]\tend:[%#x]" %(i.name, i.size, i.base, i.rebase_to)
        #       self.keyLocation = i.base
        #self.keyLocation += 0x247970
        #AddBpt(self.keyLocation)
        #print 'keybreakpoint:[%#x]' % self.keyLocation
        print "MyDbgHook : Process started, pid=%d tid=%d name=%s" % (pid, tid, name)

    def dbg_process_exit(self, pid, tid, ea, code):  
        print "MyDbgHook : Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code)

    def dbg_library_load(self, pid, tid, ea, name, base, size):  
        print "MyDbgHook : Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base)
        # 对WeChatWin.dll下断点
        if 'WeChatWin.dll' in name:
            self.keyLocation = base
            self.keyLocation = self.keyLocation + 0x1000 + 0x247970
            AddBpt(self.keyLocation)
            print 'keybreakpoint:[%#x]' % self.keyLocation

    def dbg_library_unload(self, pid, tid, ea, info):  
        print "MyDbgHook : Library unloaded: pid=%d tid=%d ea=0x%x info=%s" % (pid, tid, ea, info)
        return 0  

    def dbg_bpt(self, tid, ea):
        print "MyDbgHook : Break point at %s[0x%x] pid=%d" % (GetFunctionName(ea), ea, tid)
        #是否到了关键的地址
        if GetRegValue('eip') == self.keyLocation :
            location = GetRegValue('edi')
            sizeptr = GetRegValue('edi') + 0x4
            print "[*]\tGif location:[%08x],sizeptr:[%08x]"% (location, sizeptr)
            start = DbgDword(location)
            n = DbgDword(sizeptr)
            print "[*]\tGif start:[%08x],n:[%08x]"% (start, n)
            dump = DbgRead(start,n)
            f = open(os.path.join(self.savepath, str(self.count))+'.gif','wb')
            f.write(dump)
            f.close()
            self.count = self.count + 1
        else:
            print "[%x] - [%x]" %(GetRegValue('eip'),self.keyLocation)

        idaapi.continue_process()  
        return 0  

    def dbg_suspend_process(self):  
        print "MyDbgHook : Process suspended"

    def dbg_step_into(self):  
        print "MyDbgHook : Step into"
        self.dbg_step_over()

debughook = MyDbgHook()  
debughook.hook()

print "ok"