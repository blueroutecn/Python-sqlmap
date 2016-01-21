# Python-sqlmap
sqlmap注入流程解析-中文简体
旨在帮助小伙伴更方便的走读sqlmap源码，让想了解的朋友们熟悉一下SQLMAP的原理和一些手工注入的语句
大神勿喷
流程如下：
启动（sqlmap.py)→ 设置变量（setPath设置路径，configuratin初始化：conf，代表配置，如主机，端口, header, 参数等。KnowledgeBase初始化：kb,保存注入时的一些参数。sqlmap的选项如 -d, -r ， -u等。保存注入的数据：session。sqlite
,最后是组合Payloads: /xml/payloads中各种payload.xml和/xml/boundaries.xml相对比，组合出payload）,在此会判断输入是否合法是否可注入 是否注入过等。
注入检测：检测是否有waf， 简单的注入是否可用注入， 六种方法进行测试（布尔型注入，报错型注入，联合查询型注入，多查询条件注入，内链查询注入，基于时间的延时注入）
绕过过滤条件的某些脚本 --tamper
指纹识别（识别数据库）,myslql mssql pgsql oracle access db2
行为输出：由用户传递的参数进行行为输出：action.py：action()方法中根据用户传递的参数，到queries.xml找相应的query语句
显示 current-db current-user tables columns dump等
后续攻击接管：abstraction icmpsh metasploit udf registry
