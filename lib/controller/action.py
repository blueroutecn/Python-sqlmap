#coding=utf-8
#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.controller.handler import setHandler
from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import CONTENT_TYPE
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUnsupportedDBMSException
from lib.core.settings import SUPPORTED_DBMS
from lib.techniques.brute.use import columnExists
from lib.techniques.brute.use import tableExists

def action():
    """
    This function exploit the SQL injection on the affected
    URL parameter and extract requested data from the
    back-end database management system or operating system
    if possible。如果可能的话，这个函数利用SQL注入的影响请求URL参数和提取数据从后端数据库管理系统或操作系统,
    """
    #action()是很总要的一个函数，该函数主要根据攻城师的命令行参数选型，从而利用存在注入漏洞的url，以进一步获取攻城师要获取的数据。比如：当前的数据库用户、枚举数据库的所有数据表等等
    # First of all we have to identify the back-end database management
    # system to be able to go ahead with the injection 首先我们必须确定后端数据库管理系统能够继续注入
    setHandler() # hander.py 检测目标web应用程序的后端数据库管理系统

    if not Backend.getDbms() or not conf.dbmsHandler:
        htmlParsed = Format.getErrorParsedDBMSes()

        errMsg = "sqlmap was not able to fingerprint the "
        errMsg += "back-end database management system" #sqlmap无法指纹后端数据库管理系统

        if htmlParsed:
            errMsg += ", but from the HTML error page it was "
            errMsg += "possible to determinate that the "
            errMsg += "back-end DBMS is %s" % htmlParsed #但从HTML错误页面可以定后端数据库管理系统

        if htmlParsed and htmlParsed.lower() in SUPPORTED_DBMS:
            errMsg += ". Do not specify the back-end DBMS manually, "
            errMsg += "sqlmap will fingerprint the DBMS for you" #没有指定后端手动DBMS,sqlmap将指纹DBMS吗
        elif kb.nullConnection:
            errMsg += ". You can try to rerun without using optimization " #你可以尝试重新运行不使用优化开关
            errMsg += "switch '%s'" % ("-o" if conf.optimize else "--null-connection")
        else:
            errMsg += ". Support for this DBMS will be implemented at "
            errMsg += "some point" #支持该DBMS将在某种程度上实现

        raise SqlmapUnsupportedDBMSException(errMsg)

    conf.dumper.singleString(conf.dbmsHandler.getFingerprint())

    # Enumeration options 枚举选项
    if conf.getBanner:
        conf.dumper.banner(conf.dbmsHandler.getBanner())

    if conf.getCurrentUser:
        conf.dumper.currentUser(conf.dbmsHandler.getCurrentUser())

    if conf.getCurrentDb:
        conf.dumper.currentDb(conf.dbmsHandler.getCurrentDb())

    if conf.getHostname:
        conf.dumper.hostname(conf.dbmsHandler.getHostname())

    if conf.isDba:
        conf.dumper.dba(conf.dbmsHandler.isDba())

    if conf.getUsers:
        conf.dumper.users(conf.dbmsHandler.getUsers())

    if conf.getPasswordHashes:
        try:
            conf.dumper.userSettings("database management system users password hashes",
                                    conf.dbmsHandler.getPasswordHashes(), "password hash", CONTENT_TYPE.PASSWORDS)
        except SqlmapNoneDataException, ex:
            logger.critical(ex)
        except:
            raise

    if conf.getPrivileges:
        try:
            conf.dumper.userSettings("database management system users privileges",
                                    conf.dbmsHandler.getPrivileges(), "privilege", CONTENT_TYPE.PRIVILEGES)
        except SqlmapNoneDataException, ex:
            logger.critical(ex)
        except:
            raise

    if conf.getRoles:
        try:
            conf.dumper.userSettings("database management system users roles",
                                    conf.dbmsHandler.getRoles(), "role", CONTENT_TYPE.ROLES)
        except SqlmapNoneDataException, ex:
            logger.critical(ex)
        except:
            raise

    if conf.getDbs:
        conf.dumper.dbs(conf.dbmsHandler.getDbs())

    if conf.getTables:
        conf.dumper.dbTables(conf.dbmsHandler.getTables())

    if conf.commonTables:
        conf.dumper.dbTables(tableExists(paths.COMMON_TABLES))

    if conf.getSchema:
        conf.dumper.dbTableColumns(conf.dbmsHandler.getSchema(), CONTENT_TYPE.SCHEMA)

    if conf.getColumns:
        conf.dumper.dbTableColumns(conf.dbmsHandler.getColumns(), CONTENT_TYPE.COLUMNS)

    if conf.getCount:
        conf.dumper.dbTablesCount(conf.dbmsHandler.getCount())

    if conf.commonColumns:
        conf.dumper.dbTableColumns(columnExists(paths.COMMON_COLUMNS))

    if conf.dumpTable:
        conf.dbmsHandler.dumpTable()

    if conf.dumpAll:
        conf.dbmsHandler.dumpAll()

    if conf.search:
        conf.dbmsHandler.search()

    if conf.query:
        conf.dumper.query(conf.query, conf.dbmsHandler.sqlQuery(conf.query))

    if conf.sqlShell:
        conf.dbmsHandler.sqlShell()

    if conf.sqlFile:
        conf.dbmsHandler.sqlFile()

    # User-defined function options 用户定义函数的选择
    if conf.udfInject:
        conf.dbmsHandler.udfInjectCustom()

    # File system options 文件系统选项
    if conf.rFile:
        conf.dumper.rFile(conf.dbmsHandler.readFile(conf.rFile))

    if conf.wFile:
        conf.dbmsHandler.writeFile(conf.wFile, conf.dFile, conf.wFileType)

    # Operating system options 操作系统选项
    if conf.osCmd:
        conf.dbmsHandler.osCmd()

    if conf.osShell:
        conf.dbmsHandler.osShell()

    if conf.osPwn:
        conf.dbmsHandler.osPwn()

    if conf.osSmb:
        conf.dbmsHandler.osSmb()

    if conf.osBof:
        conf.dbmsHandler.osBof()

    # Windows registry options windows 注册表选项
    if conf.regRead:
        conf.dumper.registerValue(conf.dbmsHandler.regRead())

    if conf.regAdd:
        conf.dbmsHandler.regAdd()

    if conf.regDel:
        conf.dbmsHandler.regDel()

    # Miscellaneous options 杂项选项
    if conf.cleanup:
        conf.dbmsHandler.cleanup()

    if conf.direct:
        conf.dbmsConnector.close()
