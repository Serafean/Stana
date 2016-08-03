from statPlugins.StatBase import StatBase


class ProcessFiles(StatBase):

    def __init__(self):
        self.basePID = set()
        self.pids = {}

    def isOperational(self, straceOptions):
        if straceOptions['havePid'] is not True:
            return False
        return True

    def getSyscallHooks(self):
        return_dict = {}
        for syscall in ["read", "write", "open", "close", "stat"]:
            return_dict[syscall] = self.statFile
        for syscall in ["clone", "execve"]:
            return_dict[syscall] = self.newPid
        return return_dict

    def setOption(self, optionDict):
        return True

    def statFile(self, result):
        pid = result['pid']
        if result['return'] == '-1':
            self.pids[pid]['files'].add(result['args'][0])
        return

    def newPid(self, result):
        pid = result['pid']
        pidInfo = {}
        pidInfo['children'] = list()
        pidInfo['files'] = set()
        pidInfo['command'] = '<Anonymous>'

        if result['syscall'] == 'clone':
            childPid = result['return']
            pidInfo['pid'] = childPid
            self.pids[childPid] = pidInfo
            pidInfo['parent'] = self.pids[pid]
            self.pids[pid]['children'].append(pidInfo)

        elif result['syscall'] == 'execve':
            #  exec and not in list => root process
            if pid not in self.pids:
                pidInfo['pid'] = pid
                pidInfo['parent'] = None
                self.pids[pid] = pidInfo
                self.basePID.add(pid)
            self.pids[pid]['command'] = result['args'][0]
        return

    def _printProc(self, proc, level=0):
        prefix = " " * level * 4
        print("%s%s %s" % (prefix, proc['pid'], proc['command']))
        print("%s%s" % (prefix, proc['files']))
        for child in proc['children']:
            self._printProc(child, level+1)

    def printOutput(self):
        for i in self.basePID:
            self._printProc(self.pids[i])

    def getOutputObject(self):
        return self.pids
