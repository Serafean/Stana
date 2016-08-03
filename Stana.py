import os
import io
from straceParserLib.StraceParser import StraceParser


class Stana:

    def __init__(self, *args, **kwargs):
        self.__enabledPlugins = {}
        self.__file = None
        self.__options = None
        pass

    def enablePlugin(self, pluginName, pluginOptions=None):
        """Enable plugin named pluginName

        Optionally also set plugin options through the pluginOptions parameter."""

        try:
            plugin = __import__("statPlugins."+pluginName, globals(), locals(), [pluginName])
        except Exception as e:
            raise Exception("plugin {} couldn't be loaded ".format(pluginName))

        pluginObj = getattr(plugin, pluginName)()
        self.__enabledPlugins[pluginName] = pluginObj

        if not pluginOptions:
            return

        self.enablePluginOptions(pluginName, pluginOptions)

    def enablePluginOptions(self, pluginName, Options):
        """Set Options of plugin pluginName"""

        try:
            pluginObj = self.__enabledPlugins[pluginName]
        except KeyError:
            raise Exception("Plugin {} not loaded".format(pluginName))

        if not pluginObj.setOption(Options):
            raise Exception("Plugin {} doesn't understand passed options".format(pluginName))

    def setFile(self, fileName):
        if os.path.isfile(fileName):
            self.__file = fileName
        else:
            raise IOError("{} does not exist".format(fileName))

    def parse(self, file=None):
        """Starts parsing strace input
        the file to parse may be specified in the file parameter,
        in which case it overrides any file set using the setFile() method."""

        self.parser = StraceParser()

        for plugin in self.__enabledPlugins:

            hooks = self.__enabledPlugins[plugin].getSyscallHooks()
            if hooks:
                for syscall, func in hooks.items():
                    self.parser.registerSyscallHook(syscall, func)

            hooks = self.__enabledPlugins[plugin].getRawSyscallHooks()
            if hooks:
                for syscall, func in hooks.items():
                    self.parser.registerRawSyscallHook(syscall, func)

        with io.open(self.__file, 'r', 1) as f:
            if not self.__options:
                self.__options = self.parser.autoDetectFormat(f)
            else:
                pass  # TODO : finish

            for plugin in self.__enabledPlugins:
                ret = self.__enabledPlugins[plugin].isOperational(self.__options)
                if not ret:
                    raise Exception("required strace options not met for {}".format(plugin))

            self.parser.startParse(f, self.__options)

    def getResults(self, pluginName=None):
        """Returns object created by plugin

        If pluginName is None, will return a dict of plugins
        Otherwise only the returnObj of the specified plugin will be returned
        Raises an exception if plugin is not enabled."""
        if pluginName:
            try:
                return self.__enabledPlugins[pluginName].getOutputObject()
            except KeyError:
                raise Exception("{} not loaded, can't print".format(pluginName))
        else:
            ret = {}
            for plugin in self.__enabledPlugins:
                ret[plugin] = (self.__enabledPlugins[plugin].getOutputObject())
            return ret

    def printResults(self, pluginName=None):
        """Print plugin results to stdout

        If pluginName is None, all enabled plugins will print one by one
        Otherwise only the specified plugin will print.
        Raises an exception if plugin is not enabled."""

        if pluginName:
            try:
                self.__enabledPlugins[pluginName].printOutput()
            except KeyError:
                raise Exception("{} not loaded, can't print".format(pluginName))
        else:
            for plugin in self.__enabledPlugins:
                self.__enabledPlugins[plugin].printOutput()

    def __listPlugins(self):
        return self.__enabledPlugins.keys()
    
if __name__ == '__main__':
    print ("running some tests...")
    import doctest
    doctest.testmod()
