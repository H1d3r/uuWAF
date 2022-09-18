# 产品介绍

[![GitHub stars](https://img.shields.io/github/stars/Safe3/uuWAF.svg?label=关注&nbsp;南墙&style=for-the-badge)](https://github.com/Safe3/uuWAF)
[![Chat](https://img.shields.io/badge/Discuss-加入讨论组-7289da.svg?style=for-the-badge)](https://github.com/Safe3/uuWAF/discussions)

> **南墙**WEB应用防火墙（简称：`uuWAF`）是有安科技推出的一款全方位网站防护产品。通过有安科技专有的WEB入侵异常检测等技术，结合有安科技团队多年应用安全的攻防理论和应急响应实践经验积累的基础上自主研发而成。协助各级政府、企/事业单位全面保护WEB应用安全，实现WEB服务器的全方位防护解决方案。


## 技术优势 <!-- {docsify-ignore} -->
- :libra: 先进语义引擎

  南墙采用业界领先的`SQL、XSS、RCE、LFI` 4种基于语义分析的检测引擎，结合多种深度解码引擎可对`base64、json、form-data`等HTTP内容真实还原，从而有效抵御各种绕过WAF的攻击方式，并且相比传统正则匹配具备准确率高、误报率低、效率高等特点，管理员无需维护庞杂的规则库，即可拦截多种攻击类型。

- :ophiuchus: 智能0day防御

  南墙创新性的运用机器学习技术，使用**异常检测算法**对http正常与攻击流量进行区分识别，并对正常流量进行白名单威胁建模。通过**机器学习算法**自动学习正常流量中的参数特征，并转化成对应的参数白名单规则库，可以在面对各种突发0day漏洞时，无需添加规则即可拦截攻击，免除网站管理者一出现漏洞就需挑灯夜战升级的痛苦。

-  :gemini: 高级规则引擎

  南墙积极运用`nginx`和`luajit`的高性能、高灵活性特点，除了提供对普通用户友好性较好的传统规则创建模式，还提供了高扩展性、高灵活性的lua脚本规则编写功能，使得有一定编程功底的高级安全管理员可以创造出一系列传统WAF所不能实现的高级漏洞防护规则，用户可以编写一系列插件来扩展WAF现有功能。从而使得在拦截一些复杂漏洞时，可以更加得心应手。
  
  

## 界面预览 <!-- {docsify-ignore} -->

南墙为你提供了简单易用的WAF后台管理界面，安装完成后所有操作都可以在浏览器中完成，所有配置无需重启立即生效，远超市面上大部分免费WAF产品如`ModSecurity`，如下：

- :oden: 管理后台

![](http://waf.uusec.com/_media/waf.png ':size=98%')

- :package: 规则展示

![](http://waf.uusec.com/_media/rule.png)



