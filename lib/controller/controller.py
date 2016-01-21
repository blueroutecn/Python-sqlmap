#coding=utf-8
#!/usr/bin/env python

"""
Copyright (c) 2006-2013 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import re

from lib.controller.action import action
from lib.controller.checks import checkSqlInjection
from lib.controller.checks import checkDynParam
from lib.controller.checks import checkStability
from lib.controller.checks import checkString
from lib.controller.checks import checkRegexp
from lib.controller.checks import checkConnection
from lib.controller.checks import checkNullConnection
from lib.controller.checks import checkWaf
from lib.controller.checks import heuristicCheckSqlInjection
from lib.controller.checks import identifyWaf
from lib.core.agent import agent
from lib.core.common import extractRegexResult
from lib.core.common import getFilteredPageContent
from lib.core.common import getPublicTypeMembers
from lib.core.common import getUnicode
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import intersect
from lib.core.common import parseTargetUrl
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import safeCSValue
from lib.core.common import showHttpErrorCodes
from lib.core.common import urlencode
from lib.core.common import urldecode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CONTENT_TYPE
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import HEURISTIC_TEST
from lib.core.enums import HTTPMETHOD
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.exception import SqlmapBaseException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapNotVulnerableException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapValueException
from lib.core.exception import SqlmapUserQuitException
from lib.core.settings import ASP_NET_CONTROL_REGEX
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import EMPTY_FORM_FIELDS_REGEX
from lib.core.settings import IGNORE_PARAMETERS
from lib.core.settings import LOW_TEXT_PERCENT
from lib.core.settings import HOST_ALIASES
from lib.core.settings import REFERER_ALIASES
from lib.core.settings import USER_AGENT_ALIASES
from lib.core.target import initTargetEnv
from lib.core.target import setupTargetEnv
from thirdparty.pagerank.pagerank import get_pagerank

def _selectInjection():
    """
    Selection function for injection place, parameters and type.注入的地方,选择函数参数和类型
    """

    points = {}

    for injection in kb.injections:
        place = injection.place
        parameter = injection.parameter
        ptype = injection.ptype

        point = (place, parameter, ptype)

        if point not in points:
            points[point] = injection
        else:
            for key in points[point].keys():
                if key != 'data':
                    points[point][key] = points[point][key] or injection[key]
            points[point]['data'].update(injection['data'])

    if len(points) == 1:
        kb.injection = kb.injections[0]

    elif len(points) > 1:
        message = "there were multiple injection points, please select "
        message += "the one to use for following injections:\n"

        points = []

        for i in xrange(0, len(kb.injections)):
            place = kb.injections[i].place
            parameter = kb.injections[i].parameter
            ptype = kb.injections[i].ptype
            point = (place, parameter, ptype)

            if point not in points:
                points.append(point)
                ptype = PAYLOAD.PARAMETER[ptype] if isinstance(ptype, int) else ptype

                message += "[%d] place: %s, parameter: " % (i, place)
                message += "%s, type: %s" % (parameter, ptype)

                if i == 0:
                    message += " (default)"

                message += "\n"

        message += "[q] Quit"
        select = readInput(message, default="0")

        if select.isdigit() and int(select) < len(kb.injections) and int(select) >= 0:
            index = int(select)
        elif select[0] in ("Q", "q"):
            raise SqlmapUserQuitException
        else:
            errMsg = "invalid choice"
            raise SqlmapValueException(errMsg)

        kb.injection = kb.injections[index]

def _formatInjection(inj):
    data = "Place: %s\n" % inj.place
    data += "Parameter: %s\n" % inj.parameter

    for stype, sdata in inj.data.items():
        title = sdata.title
        vector = sdata.vector
        comment = sdata.comment
        payload = agent.adjustLateValues(sdata.payload)
        if inj.place == PLACE.CUSTOM_HEADER:
            payload = payload.split(',', 1)[1]
        if stype == PAYLOAD.TECHNIQUE.UNION:
            count = re.sub(r"(?i)(\(.+\))|(\blimit[^A-Za-z]+)", "", sdata.payload).count(',') + 1
            title = re.sub(r"\d+ to \d+", str(count), title)
            vector = agent.forgeUnionQuery("[QUERY]", vector[0], vector[1], vector[2], None, None, vector[5], vector[6])
            if count == 1:
                title = title.replace("columns", "column")
        elif comment:
            vector = "%s%s" % (vector, comment)
        data += "    Type: %s\n" % PAYLOAD.SQLINJECTION[stype]
        data += "    Title: %s\n" % title
        data += "    Payload: %s\n" % urldecode(payload, unsafe="&", plusspace=(inj.place == PLACE.POST and kb.postSpaceToPlus))
        data += "    Vector: %s\n\n" % vector if conf.verbose > 1 else "\n"

    return data

def _showInjections():
    header = "sqlmap identified the following injection points with "
    header += "a total of %d HTTP(s) requests" % kb.testQueryCount

    if hasattr(conf, "api"):
        conf.dumper.string("", kb.injections, content_type=CONTENT_TYPE.TECHNIQUES)
    else:
        data = "".join(set(map(lambda x: _formatInjection(x), kb.injections))).rstrip("\n")
        conf.dumper.string(header, data)

    if conf.tamper:
        warnMsg = "changes made by tampering scripts are not "
        warnMsg += "included in shown payload content(s)"
        logger.warn(warnMsg)

    if conf.hpp:
        warnMsg = "changes made by HTTP parameter pollution are not "
        warnMsg += "included in shown payload content(s)"
        logger.warn(warnMsg)

def _randomFillBlankFields(value):
    retVal = value

    if extractRegexResult(EMPTY_FORM_FIELDS_REGEX, value):
        message = "do you want to fill blank fields with random values? [Y/n] "
        test = readInput(message, default="Y")
        if not test or test[0] in ("y", "Y"):
            for match in re.finditer(EMPTY_FORM_FIELDS_REGEX, retVal):
                item = match.group("result")
                if not any(_ in item for _ in IGNORE_PARAMETERS) and not re.search(ASP_NET_CONTROL_REGEX, item):
                    if item[-1] == DEFAULT_GET_POST_DELIMITER:
                        retVal = retVal.replace(item, "%s%s%s" % (item[:-1], randomStr(), DEFAULT_GET_POST_DELIMITER))
                    else:
                        retVal = retVal.replace(item, "%s%s" % (item, randomStr()))

    return retVal

def _saveToHashDB():
    injections = hashDBRetrieve(HASHDB_KEYS.KB_INJECTIONS, True) or []
    injections.extend(_ for _ in kb.injections if _ and _.place is not None and _.parameter is not None)

    _ = dict()
    for injection in injections:
        key = (injection.place, injection.parameter, injection.ptype)
        if key not in _:
            _[key] = injection
        else:
            _[key].data.update(injection.data)
    hashDBWrite(HASHDB_KEYS.KB_INJECTIONS, _.values(), True)

    _ = hashDBRetrieve(HASHDB_KEYS.KB_ABS_FILE_PATHS, True) or set()
    _.update(kb.absFilePaths)
    hashDBWrite(HASHDB_KEYS.KB_ABS_FILE_PATHS, _, True)

    if not hashDBRetrieve(HASHDB_KEYS.KB_CHARS):
        hashDBWrite(HASHDB_KEYS.KB_CHARS, kb.chars, True)

    if not hashDBRetrieve(HASHDB_KEYS.KB_DYNAMIC_MARKINGS):
        hashDBWrite(HASHDB_KEYS.KB_DYNAMIC_MARKINGS, kb.dynamicMarkings, True)

def _saveToResultsFile():
    if not conf.resultsFP:
        return

    results = {}
    techniques = dict(map(lambda x: (x[1], x[0]), getPublicTypeMembers(PAYLOAD.TECHNIQUE)))

    for inj in kb.injections:
        if inj.place is None or inj.parameter is None:
            continue

        key = (inj.place, inj.parameter)
        if key not in results:
            results[key] = []

        results[key].extend(inj.data.keys())

    for key, value in results.items():
        place, parameter = key
        line = "%s,%s,%s,%s%s" % (safeCSValue(kb.originalUrls.get(conf.url) or conf.url), place, parameter, "".join(map(lambda x: techniques[x][0].upper(), sorted(value))), os.linesep)
        conf.resultsFP.writelines(line)

    if not results:
        line = "%s,,,%s" % (conf.url, os.linesep)
        conf.resultsFP.writelines(line)

def start():#sqlmap 开始检测 get post cookie user-agent
    """
    This function calls a function that performs checks on both URL
    stability and all GET, POST, Cookie and User-Agent parameters to
    check if they are dynamic and SQL injection affected这个函数调用一个函数,执行检查URL所有GET、POST、cookie和user-agent参数 们是否动态和SQL注入的影响
    """

    if conf.direct:  # conf.direct是通过命令行参数："-d" .指定的 通过参数"-d"指定要连接的数据库
        initTargetEnv() #初始化目标环境 target.py initTargetEnv()函数主要就是完成全局变量conf和kb的初始化工作
        setupTargetEnv()
        action()    # 如果你使用-d选项，那么sqlmap就会直接进入action()函数，连接数据库 .  eg：-d "mysql:123123//root:@127.0.0.1:3306/security"
        return True

    if conf.url and not any((conf.forms, conf.crawlDepth)):
        kb.targets.add((conf.url, conf.method, conf.data, conf.cookie))
        # 把url,methos,data,cookie加入到kb.targets，这些参数就是由我们输入的
    if conf.configFile and not kb.targets:
        errMsg = "you did not edit the configuration file properly, set "
        errMsg += "the target URL, list of targets or google dork" #你没有正确编辑配置文件,设置目标URL,目标列表或谷歌码头
        logger.error(errMsg)
        return False

    if kb.targets and len(kb.targets) > 1:
        infoMsg = "sqlmap got a total of %d targets" % len(kb.targets) #sqlmap总数的**目标
        logger.info(infoMsg)

    hostCount = 0

    for targetUrl, targetMethod, targetData, targetCookie in kb.targets: #循环检测
        try:
            conf.url = targetUrl
            conf.method = targetMethod
            conf.data = targetData
            conf.cookie = targetCookie

            initTargetEnv() # initTargetEnv()函数主要就是完成全局变量conf和kb的初始化工作
            parseTargetUrl()  # 此循环先初始化一些一些变量，然后判断之前是否注入过,parseTargetUrl()函数主要完成针对目标网址的解析工作，如获取协议名、路径、端口、请求参数等信息

            testSqlInj = False # False 表示注入过 不会执行 injection = checkSqlInjection(place, parameter, value)这句代码
            #测试过的url参数信息会保存到kb.testedParams中，所以在进行test之前，会先判断当前的url是否已经test过
            if PLACE.GET in conf.parameters and not any([conf.data, conf.testParameter]):
                for parameter in re.findall(r"([^=]+)=([^%s]+%s?|\Z)" % (conf.pDel or DEFAULT_GET_POST_DELIMITER, conf.pDel or DEFAULT_GET_POST_DELIMITER), conf.parameters[PLACE.GET]):
                    paramKey = (conf.hostname, conf.path, PLACE.GET, parameter[0])

                    if paramKey not in kb.testedParams:
                        testSqlInj = True  # True表示未注入过  执行 injection = checkSqlInjection(place, parameter, value)这句代码
                        break
            else:
                paramKey = (conf.hostname, conf.path, None, None)
                if paramKey not in kb.testedParams:
                    testSqlInj = True # True表示未注入过

            if testSqlInj and conf.hostname in kb.vulnHosts:
                if kb.skipVulnHost is None:
                    message = "SQL injection vulnerability has already been detected "
                    message += "against '%s'. Do you want to skip " % conf.hostname
                    message += "further tests involving it? [Y/n]"
                    kb.skipVulnHost = readInput(message, default="Y").upper() != 'N' # SQL注入漏洞已被发现对“% s”。你想跳过此测试涉及吗?[Y / n]
                testSqlInj = not kb.skipVulnHost

            if not testSqlInj:
                infoMsg = "skipping '%s'" % targetUrl
                logger.info(infoMsg)
                continue

            if conf.multipleTargets:
                hostCount += 1

                if conf.forms:
                    message = "[#%d] form:\n%s %s" % (hostCount, conf.method or HTTPMETHOD.GET, targetUrl)
                else:
                    message = "URL %d:\n%s %s%s" % (hostCount, conf.method or HTTPMETHOD.GET, targetUrl, " (PageRank: %s)" % get_pagerank(targetUrl) if conf.googleDork and conf.pageRank else "")

                if conf.cookie:
                    message += "\nCookie: %s" % conf.cookie

                if conf.data is not None:
                    message += "\nPOST data: %s" % urlencode(conf.data) if conf.data else ""

                if conf.forms:
                    if conf.method == HTTPMETHOD.GET and targetUrl.find("?") == -1:
                        continue

                    message += "\ndo you want to test this form? [Y/n/q] "
                    test = readInput(message, default="Y")

                    if not test or test[0] in ("y", "Y"):
                        if conf.method == HTTPMETHOD.POST:
                            message = "Edit POST data [default: %s]%s: " % (urlencode(conf.data) if conf.data else "None", " (Warning: blank fields detected)" if conf.data and extractRegexResult(EMPTY_FORM_FIELDS_REGEX, conf.data) else "")
                            conf.data = readInput(message, default=conf.data)
                            conf.data = _randomFillBlankFields(conf.data)
                            conf.data = urldecode(conf.data) if conf.data and urlencode(DEFAULT_GET_POST_DELIMITER, None) not in conf.data else conf.data

                        elif conf.method == HTTPMETHOD.GET:
                            if targetUrl.find("?") > -1:
                                firstPart = targetUrl[:targetUrl.find("?")]
                                secondPart = targetUrl[targetUrl.find("?") + 1:]
                                message = "Edit GET data [default: %s]: " % secondPart
                                test = readInput(message, default=secondPart)
                                test = _randomFillBlankFields(test)
                                conf.url = "%s?%s" % (firstPart, test)

                        parseTargetUrl()

                    elif test[0] in ("n", "N"):
                        continue
                    elif test[0] in ("q", "Q"):
                        break

                else:
                    message += "\ndo you want to test this URL? [Y/n/q]" #你想测试这个URL ?[Y / n / q]
                    test = readInput(message, default="Y")

                    if not test or test[0] in ("y", "Y"):
                        pass
                    elif test[0] in ("n", "N"):
                        continue
                    elif test[0] in ("q", "Q"):
                        break

                    infoMsg = "testing URL '%s'" % targetUrl
                    logger.info(infoMsg)

            setupTargetEnv() # setupTargetEnv()函数中包含了5个函数  都不可或缺，将get或post发送的数据解析成字典形式，并保存到conf.paramDict中

            if not checkConnection(suppressOutput=conf.forms) or not checkString() or not checkRegexp():
                continue

            if conf.checkWaf:
                checkWaf() #是检测是否有WAF

            if conf.identifyWaf: #sqlmap的参数–identify-waf
                identifyWaf() # 进入identifyWaf()函数

            if conf.nullConnection:
                checkNullConnection()
                #提取url中的参数信息，并将其传递给checkSqlInjection函数
            if (len(kb.injections) == 0 or (len(kb.injections) == 1 and kb.injections[0].place is None)) \
                and (kb.injection.place is None or kb.injection.parameter is None):
                #判断是否注入过，如果还没有测试过参数是否可以注入，则进入if语句中。如果之前测试过，则不会进入此语句
                if not any((conf.string, conf.notString, conf.regexp)) and PAYLOAD.TECHNIQUE.BOOLEAN in conf.tech:
                    # NOTE: this is not needed anymore, leaving only to display 注意:这是不需要了,只留下显示
                    # a warning message to the user in case the page is not stable 一条警告消息给用户的页面是不稳定的
                    checkStability()

                # Do a little prioritization reorder of a testable parameter list 做一个可测试的参数列表的优先级排序
                parameters = conf.parameters.keys()

                # Order of testing list (first to last) #测试顺序列表(第一个)
                orderList = (PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER, PLACE.URI, PLACE.POST, PLACE.GET)

                for place in orderList[::-1]:
                    if place in parameters:
                        parameters.remove(place)
                        parameters.insert(0, place)

                proceed = True
                for place in parameters:
                    # Test User-Agent and Referer headers only if #只有测试用户代理和推荐人头
                    # --level >= 3 级别>=3
                    skip = (place == PLACE.USER_AGENT and conf.level < 3)
                    skip |= (place == PLACE.REFERER and conf.level < 3)

                    # Test Host header only if 仅有主机头
                    # --level >= 5 级别>=5
                    skip |= (place == PLACE.HOST and conf.level < 5)

                    # Test Cookie header only if --level >= 2 #只有cookie 级别>=2
                    skip |= (place == PLACE.COOKIE and conf.level < 2)

                    skip |= (place == PLACE.USER_AGENT and intersect(USER_AGENT_ALIASES, conf.skip, True) not in ([], None))
                    skip |= (place == PLACE.REFERER and intersect(REFERER_ALIASES, conf.skip, True) not in ([], None))
                    skip |= (place == PLACE.COOKIE and intersect(PLACE.COOKIE, conf.skip, True) not in ([], None))

                    skip &= not (place == PLACE.USER_AGENT and intersect(USER_AGENT_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.REFERER and intersect(REFERER_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.HOST and intersect(HOST_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.COOKIE and intersect((PLACE.COOKIE,), conf.testParameter, True))

                    if skip:
                        continue

                    if place not in conf.paramDict:
                        continue

                    paramDict = conf.paramDict[place]

                    for parameter, value in paramDict.items():
                        if not proceed:
                            break

                        kb.vainRun = False
                        testSqlInj = True # True表示未注入过
                        paramKey = (conf.hostname, conf.path, place, parameter)

                        if paramKey in kb.testedParams:
                            testSqlInj = False # False 表示注入过

                            infoMsg = "skipping previously processed %s parameter '%s'" % (place, parameter)
                            logger.info(infoMsg)

                        elif parameter in conf.testParameter:
                            pass

                        elif parameter == conf.rParam:
                            testSqlInj = False # False 表示注入过

                            infoMsg = "skipping randomizing %s parameter '%s'" % (place, parameter)
                            logger.info(infoMsg)

                        elif parameter in conf.skip:
                            testSqlInj = False # False 表示注入过

                            infoMsg = "skipping %s parameter '%s'" % (place, parameter)
                            logger.info(infoMsg)

                        # Ignore session-like parameters for --level < 4
                        elif conf.level < 4 and parameter.upper() in IGNORE_PARAMETERS:
                            testSqlInj = False # False 表示注入过

                            infoMsg = "ignoring %s parameter '%s'" % (place, parameter)
                            logger.info(infoMsg)

                        elif PAYLOAD.TECHNIQUE.BOOLEAN in conf.tech:
                            check = checkDynParam(place, parameter, value) #checkDynParam()函数会判断参数是否是动态的

                            if not check:
                                warnMsg = "%s parameter '%s' does not appear dynamic" % (place, parameter) #参数没有出现动态的
                                logger.warn(warnMsg)

                            else:
                                infoMsg = "%s parameter '%s' is dynamic" % (place, parameter) #参数出现动态的
                                logger.info(infoMsg)

                        kb.testedParams.add(paramKey)

                        if testSqlInj:# sql注入测试
                            check = heuristicCheckSqlInjection(place, parameter)#启发性sql注入测试，其实就是先进行一个简单的测试

                            if check != HEURISTIC_TEST.POSITIVE:
                                if conf.smart or (kb.ignoreCasted and check == HEURISTIC_TEST.CASTED):
                                    infoMsg = "skipping %s parameter '%s'" % (place, parameter)
                                    logger.info(infoMsg)
                                    continue

                            infoMsg = "testing for SQL injection on %s " % place
                            infoMsg += "parameter '%s'" % parameter #在 **参数测试SQL注入**”
                            logger.info(infoMsg)
                            #判断testSqlInj,如果为true，就代表之前没有检测过，然后就会到checkSqlInjection，checkSqlInjection()才是真正开始测试的函数，传入的参数是注入方法如GET，参数名，参数值
                            injection = checkSqlInjection(place, parameter, value) #这里开始执行sql注入，当testSqlInj = False的时候，不会执行
                            proceed = not kb.endDetection

                            if injection is not None and injection.place is not None:
                                kb.injections.append(injection)

                                # In case when user wants to end detection phase (Ctrl+C) #如果当用户想要检测阶段(Ctrl + C)
                                if not proceed:
                                    break

                                msg = "%s parameter '%s' " % (injection.place, injection.parameter)
                                msg += "is vulnerable. Do you want to keep testing the others (if any)? [y/N] "# **参数是脆弱的。你想要测试其他的(如果有的话)?[y / N]
                                test = readInput(msg, default="N")

                                if test[0] not in ("y", "Y"):
                                    proceed = False
                                    paramKey = (conf.hostname, conf.path, None, None)
                                    kb.testedParams.add(paramKey)
                            else:
                                warnMsg = "%s parameter '%s' is not " % (place, parameter)
                                warnMsg += "injectable" #　**参数是不可注入的
                                logger.warn(warnMsg)

            if len(kb.injections) == 0 or (len(kb.injections) == 1 and kb.injections[0].place is None):
                if kb.vainRun and not conf.multipleTargets:
                    errMsg = "no parameter(s) found for testing in the provided data " #没有发现参数提供的测试数据
                    errMsg += "(e.g. GET parameter 'id' in 'www.site.com/index.php?id=1')" # 例子
                    raise SqlmapNoneDataException(errMsg)
                else:
                    errMsg = "all tested parameters appear to be not injectable." #所有测试参数似乎不是注射

                    if conf.level < 5 or conf.risk < 3:
                        errMsg += " Try to increase '--level'/'--risk' values "
                        errMsg += "to perform more tests."

                    if isinstance(conf.tech, list) and len(conf.tech) < 5:
                        errMsg += " Rerun without providing the option '--technique'." #重新运行没有提供选项

                    if not conf.textOnly and kb.originalPage:
                        percent = (100.0 * len(getFilteredPageContent(kb.originalPage)) / len(kb.originalPage))

                        if kb.dynamicMarkings:
                            errMsg += " You can give it a go with the switch '--text-only' "
                            errMsg += "if the target page has a low percentage "
                            errMsg += "of textual content (~%.2f%% of " % percent
                            errMsg += "page content is text)."
                        elif percent < LOW_TEXT_PERCENT and not kb.errorIsNone:
                            errMsg += " Please retry with the switch '--text-only' "
                            errMsg += "(along with --technique=BU) as this case "
                            errMsg += "looks like a perfect candidate "
                            errMsg += "(low textual content along with inability "
                            errMsg += "of comparison engine to detect at least "
                            errMsg += "one dynamic parameter)." #请重试开关”——text-only(along with --technique=BU),这种情况下看起来像一个完美的候选人(低文本内容以及比较引擎无法检测至少一个动态参数)

                    if kb.heuristicTest == HEURISTIC_TEST.POSITIVE:
                        errMsg += " As heuristic test turned out positive you are "
                        errMsg += "strongly advised to continue on with the tests. "
                        errMsg += "Please, consider usage of tampering scripts as "
                        errMsg += "your target might filter the queries." #作为启发式测试结果积极强烈建议你继续测试。请考虑使用篡改脚本作为你的目标可能过滤查询。

                    if not conf.string and not conf.notString and not conf.regexp:
                        errMsg += " Also, you can try to rerun by providing "
                        errMsg += "either a valid value for option '--string' "
                        errMsg += "(or '--regexp')" #此外,你可以尝试重新运行通过提供一个有效的价值选择
                    elif conf.string:
                        errMsg += " Also, you can try to rerun by providing a "
                        errMsg += "valid value for option '--string' as perhaps the string you "
                        errMsg += "have chosen does not match "
                        errMsg += "exclusively True responses" #此外,你可以尝试重新运行选项通过提供一个有效的值,字符串的字符串可能你选择不匹配完全真实的反应
                    elif conf.regexp:
                        errMsg += " Also, you can try to rerun by providing a "
                        errMsg += "valid value for option '--regexp' as perhaps the regular "
                        errMsg += "expression that you have chosen "
                        errMsg += "does not match exclusively True responses" #此外,你可以尝试重新运行通过提供一个有效的值选项“- regexp”也许你选择了不匹配的正则表达式完全真实的反应

                    raise SqlmapNotVulnerableException(errMsg)
            else:
                # Flush the flag
                kb.testMode = False

                _saveToResultsFile() #保存结果
                _saveToHashDB()     #保存session
                _showInjections()   #显示注入结果，包括类型，payload
                _selectInjection()  #

            if kb.injection.place is not None and kb.injection.parameter is not None:
                if conf.multipleTargets:
                    message = "do you want to exploit this SQL injection? [Y/n] "
                    exploit = readInput(message, default="Y")

                    condition = not exploit or exploit[0] in ("y", "Y")
                else:
                    condition = True

                if condition:
                    action() #此函数是判断用户提供的参数

        except KeyboardInterrupt:
            if conf.multipleTargets:
                warnMsg = "user aborted in multiple target mode"
                logger.warn(warnMsg)

                message = "do you want to skip to the next target in list? [Y/n/q]"
                test = readInput(message, default="Y")

                if not test or test[0] in ("y", "Y"):
                    pass
                elif test[0] in ("n", "N"):
                    return False
                elif test[0] in ("q", "Q"):
                    raise SqlmapUserQuitException
            else:
                raise

        except SqlmapUserQuitException:
            raise

        except SqlmapSilentQuitException:
            raise

        except SqlmapBaseException, ex:
            errMsg = getUnicode(ex.message)

            if conf.multipleTargets:
                errMsg += ", skipping to the next %s" % ("form" if conf.forms else "URL")
                logger.error(errMsg)
            else:
                logger.critical(errMsg)
                return False

        finally:
            showHttpErrorCodes()

            if kb.maxConnectionsFlag:
                warnMsg = "it appears that the target "
                warnMsg += "has a maximum connections "
                warnMsg += "constraint"
                logger.warn(warnMsg)

    if kb.dataOutputFlag and not conf.multipleTargets:
        logger.info("fetched data logged to text files under '%s'" % conf.outputPath)

    if conf.multipleTargets and conf.resultsFilename:
        infoMsg = "you can find results of scanning in multiple targets "
        infoMsg += "mode inside the CSV file '%s'" % conf.resultsFilename
        logger.info(infoMsg)

    return True
