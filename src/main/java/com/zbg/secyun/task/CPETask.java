package com.zbg.secyun.task;

import com.zbg.secyun.domain.*;
import com.zbg.secyun.service.*;
import com.zbg.secyun.util.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Slf4j
public class CPETask {

    @Autowired
    private ACpeService aCpeService;
    @Autowired
    private OCpeService oCpeService;

    @Autowired
    private ComponentVulnService comVulnService;

    @Autowired
    private OssComponentCcppService ccppService;
    @Autowired
    private OssComponentDotnetService dotnetService;
    @Autowired
    private OssComponentGoService goService;
    @Autowired
    private OssComponentJavaService javaService;
    @Autowired
    private OssComponentJsService jsService;
    @Autowired
    private OssComponentPhpService phpService;
    @Autowired
    private OssComponentPyService pyService;

    @Autowired
    private OssVulnerabilityService vulnService;
    @Autowired
    private OssOperationLogService logService;

    /**
     * cpe数据解析
     * cpe数据库中的数据，review字段值为0时，循环取出解析
     */
    public String startCpeParsing( ) {

        // 获取cpe对应的漏洞id
        int cpeVulnId = 0;
        // 创建组件漏洞对应关系
        OssComponentVuln componentVuln = new OssComponentVuln();
        // 查找java组件库，匹配对应
        List<OssComponentJava> javaList = null;
        // 查找javaScript组件库，匹配对应
        List<OssComponentJs> jsList = null;
        // 查找python组件库，匹配对应
        List<OssComponentPy> pyList = null;
        // 查找php组件库，匹配对应
        List<OssComponentPhp> phpList = null;
        // 查找golang组件库，匹配对应
        List<OssComponentGo> goList = null;
        // 查找c/c++组件库，匹配对应
        List<OssComponentCcpp> ccppList = null;
        // 查找.net组件库，匹配对应
        List<OssComponentDotnet> dotnetList = null;
        // cpe中获取需要解析的数据
        List<VulnACpe> parsingCpes = aCpeService.getParsingCpes();
        // 需要解析的cpe数量
        int cpeListSize = parsingCpes.size();
        // 组件漏洞关联表添加的数量
        int componentVulnNumber = 0;
        log.info("开始解析cpe数据：共需解析-{}-条数据", cpeListSize);
        for (VulnACpe cpe : parsingCpes) {
            log.info("**********************开始解析-cpeid：{}-数据******************", cpe.getId());
            // 不是应用程序的跳过
            if (!"/a".equals(cpe.getPart())) {
                // 将cpe信息更改到ocpe表中；
                oCpeService.insertCpe(cpe);
                aCpeService.deleteCpe(cpe);
                continue;
            }
            // 获取供应商，用于java模糊查询group
            String vendor = cpe.getVendor();
            // 获取产品，用于模糊查询组件
            String product = cpe.getProduct();

            // 查找cpe对应的漏洞信息并设置组件漏洞表中漏洞id
            cpeVulnId = vulnService.selectVulnIdByCnnvdNo(cpe.getCnnvdNo());
            componentVuln.setVulnId(cpeVulnId);
            // 查找java组件库，匹配对应
            javaList = javaService.selectByName(vendor, product);
            if (javaList.size() > 0) {
                // 版本号能对应上的数据，存为 组件漏洞关联表 ，cpe信息改为通过系统审查（Review=1）
                for (OssComponentJava java : javaList) {
                    if (equalsVersion(cpe, java.getVersion())) {
                        // cpe信息改为通过系统审查（Review=1）
                        cpe.setReview(1);
                        // 保存组件漏洞对应表
                        componentVuln.setLanguage(0);
                        componentVuln.setComponentId(java.getId());
                        componentVulnNumber += comVulnService.insertComponentVuln(componentVuln);
                        break;
                    }
                }
                javaList = null;
            }
            // 查找javaScript组件库，匹配对应
            jsList = jsService.selectByName(product);
            if (jsList.size() > 0) {
                for (OssComponentJs js : jsList) {
                    if (equalsVersion(cpe, js.getVersion())) {
                        // review 不为0，表示已经有对应上数据，此处为多次重复对应，将review改为需要人工 2
                        if (cpe.getReview() != 0) {
                            cpe.setReview(2);
                        }
                        // 保存组件漏洞对应表
                        componentVuln.setLanguage(1);
                        componentVuln.setComponentId(js.getId());
                        componentVulnNumber += comVulnService.insertComponentVuln(componentVuln);
                        break;
                    }
                }
                jsList = null;
            }
            // 查找python组件库，匹配对应
            pyList = pyService.selectByName(product);
            if (pyList.size() > 0) {
                for (OssComponentPy py : pyList) {
                    if (equalsVersion(cpe, py.getVersion())) {
                        // review 不为0，表示已经有对应上数据，此处为多次重复对应，将review改为需要人工 2
                        if (cpe.getReview() != 0) {
                            cpe.setReview(2);
                        }
                        // 保存组件漏洞对应表
                        componentVuln.setLanguage(2);
                        componentVuln.setComponentId(py.getId());
                        componentVulnNumber += comVulnService.insertComponentVuln(componentVuln);
                        break;
                    }
                }
                pyList = null;
            }
            // 查找php组件库，匹配对应
            phpList = phpService.selectByName(product);
            if (phpList.size() > 0) {
                for (OssComponentPhp php : phpList) {
                    if (equalsVersion(cpe, php.getVersion())) {
                        // review 不为0，表示已经有对应上数据，此处为多次重复对应，将review改为需要人工 2
                        if (cpe.getReview() != 0) {
                            cpe.setReview(2);
                        }
                        // 保存组件漏洞对应表
                        componentVuln.setLanguage(3);
                        componentVuln.setComponentId(php.getId());
                        componentVulnNumber += comVulnService.insertComponentVuln(componentVuln);
                        break;
                    }
                }
                phpList = null;
            }
            // 查找golang组件库，匹配对应
            goList = goService.selectByName(product);
            if (goList.size() > 0) {
                for (OssComponentGo go : goList) {
                    if (equalsVersion(cpe, go.getVersion())) {
                        // review 不为0，表示已经有对应上数据，此处为多次重复对应，将review改为需要人工 2
                        if (cpe.getReview() != 0) {
                            cpe.setReview(2);
                        }
                        // 保存组件漏洞对应表
                        componentVuln.setLanguage(4);
                        componentVuln.setComponentId(go.getId());
                        componentVulnNumber += comVulnService.insertComponentVuln(componentVuln);
                        break;
                    }
                }
                goList = null;
            }
            // 查找c/c++组件库，匹配对应
            ccppList = ccppService.selectByName(product);
            if (ccppList.size() > 0) {
                for (OssComponentCcpp ccpp : ccppList) {
                    if (equalsVersion(cpe, ccpp.getVersion())) {
                        // review 不为0，表示已经有对应上数据，此处为多次重复对应，将review改为需要人工 2
                        if (cpe.getReview() != 0) {
                            cpe.setReview(2);
                        }
                        // 保存组件漏洞对应表
                        componentVuln.setLanguage(5);
                        componentVuln.setComponentId(ccpp.getId());
                        componentVulnNumber += comVulnService.insertComponentVuln(componentVuln);
                        break;
                    }
                }
                ccppList = null;
            }
            // 查找.net组件库，匹配对应
            dotnetList = dotnetService.selectByName(product);
            if (dotnetList.size() > 0) {
                for (OssComponentDotnet dotnet : dotnetList) {
                    if (equalsVersion(cpe, dotnet.getVersion())) {
                        // review 不为0，表示已经有对应上数据，此处为多次重复对应，将review改为需要人工 2
                        if (cpe.getReview() != 0) {
                            cpe.setReview(2);
                        }
                        // 保存组件漏洞对应表
                        componentVuln.setLanguage(6);
                        componentVuln.setComponentId(dotnet.getId());
                        componentVulnNumber += comVulnService.insertComponentVuln(componentVuln);
                        break;
                    }
                }
                dotnetList = null;
            }
            // review为0时表示没有一个组件库查到对应的信息
            if (cpe.getReview() == 0) {
                log.info("未找到相关组件。。。。。");
                cpe.setReview(1);
            }
            aCpeService.updateReview(cpe);

        }
        log.info("数据解析完成,共解析-{}-条数据", cpeListSize);
        //操作记录表添加信息
        OssOperationLog osslog = new OssOperationLog();
        osslog.setOperationNumber(cpeListSize);
        osslog.setOperationDesc("cpe表-程序解析cpe信息");
        logService.insertLog(osslog);
        osslog.setOperationNumber(componentVulnNumber);
        osslog.setOperationDesc("程序解析cpe数据后，向组件漏洞关联表里添加-组件漏洞关联信息");
        logService.insertLog(osslog);
        return "数据解析完成";
    }


    /**
     * cpe数据版本与组件版本对应
     *
     * @param cpe              cpe数据对象
     * @param componentVersion 组件版本
     * @return 版本信息是否对应
     */
    private boolean equalsVersion(VulnACpe cpe, String componentVersion) {
        // 获取版本号，用于精确查找
        String version = cpe.getVersion();
        if (StringUtils.isEmpty(version) || StringUtils.isEmpty(componentVersion)) {
            return false;
        }
        // 更改version中的下划线
        version = version.replaceAll("_", "-");
        // 获取更新，版本号的补充
        String update = cpe.getUpdate();
        if (StringUtils.isEmpty(update) || "-".equalsIgnoreCase(update)) {
            if (version.equalsIgnoreCase(componentVersion)) {
                return true;
            }
            return false;
        }
        // 将可能存在的不同单词统一
        update = update.replaceAll("prerelease", "pr");
        update = update.replaceAll("pre", "pr");
        update = update.replaceAll("-", "final");
        update = update.replaceAll("milestone", "m");
        update = update.replaceAll("candidate_release", "cr");

        componentVersion = componentVersion.replaceAll("prerelease", "pr");
        componentVersion = componentVersion.replaceAll("pre", "pr");
        componentVersion = componentVersion.replaceAll("-", "");
        componentVersion = componentVersion.replaceAll("milestone", "m");
        componentVersion = componentVersion.replaceAll("maintenance_", "m");
        componentVersion = componentVersion.replaceAll("v", "");


        String str = version + "." + update;
        if (str.equalsIgnoreCase(componentVersion)) {
            return true;
        }
        str = version + "-" + update;
        if (str.equalsIgnoreCase(componentVersion)) {
            return true;
        }
        str = version + update;
        if (str.equalsIgnoreCase(componentVersion)) {
            return true;
        }
        return false;
    }


}
