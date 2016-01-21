#coding=utf-8
#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import re

from xml.sax.handler import ContentHandler

from lib.core.common import checkFile
from lib.core.common import parseXmlFile
from lib.core.data import kb
from lib.core.data import paths
from lib.core.threads import getCurrentThreadData

class HTMLHandler(ContentHandler):
    """
    This class defines methods to parse the input HTML page to
    fingerprint the back-end database management system. 这个类定义方法来解析输入HTML页面指纹后端数据库管理系统
    """

    def __init__(self, page):
        ContentHandler.__init__(self)

        self._dbms = None
        self._page = page

        self.dbms = None

    def _markAsErrorPage(self):
        threadData = getCurrentThreadData()
        threadData.lastErrorPage = (threadData.lastRequestUID, self._page)

    def startElement(self, name, attrs):
        if name == "dbms":
            self._dbms = attrs.get("value")

        elif name == "error":
            if re.search(attrs.get("regexp"), self._page, re.I):
                self.dbms = self._dbms
                self._markAsErrorPage()

def htmlParser(page): #htmlParser函数，就是根据不同的数据库指纹去识别当前的数据库究竟是什么
    """
    This function calls a class that parses the input HTML page to
    fingerprint the back-end database management system
    """

    xmlfile = paths.ERRORS_XML #paths.ERRORS_XML这一变量的就是SQLMAP用来识别的指纹配置文件路径，位置在于./xml/errors.xml中
    checkFile(xmlfile)
    handler = HTMLHandler(page)
    ##最终实现的的其实是HTMLHandler这个类，
    parseXmlFile(xmlfile, handler)

    if handler.dbms and handler.dbms not in kb.htmlFp:
        kb.lastParserStatus = handler.dbms
        kb.htmlFp.append(handler.dbms)
    else:
        kb.lastParserStatus = None

    # generic SQL warning/error messages
    if re.search(r"SQL (warning|error|syntax)", page, re.I):
        handler._markAsErrorPage()

    return handler.dbms
