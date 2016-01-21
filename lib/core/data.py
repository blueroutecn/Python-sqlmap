#coding=utf-8
#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.datatype import AttribDict
from lib.core.log import LOGGER

# sqlmap paths sqlmap路径
paths = AttribDict()

# object to store original command line options 对象来存储原始的命令行选项
cmdLineOptions = AttribDict()

# object to store merged options (command line, configuration file and default options) 对象存储合并选项(命令行配置文件和默认选项)
mergedOptions = AttribDict()

# object to share within function and classes command 
# line options and settings 对象内部共享函数和类命令行选项和设置
conf = AttribDict()

# object to share within function and classes results 对象内部共享函数和类的结果
kb = AttribDict()

# object with each database management system specific queries 与每个数据库管理系统特定的查询对象
queries = {}

# logger 日志记录
logger = LOGGER
