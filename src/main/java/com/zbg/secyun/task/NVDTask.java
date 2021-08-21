package com.zbg.secyun.task;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zbg.secyun.domain.OssOperationLog;
import com.zbg.secyun.domain.OssVulnerabilityWithBLOBs;
import com.zbg.secyun.domain.VulnCwe;
import com.zbg.secyun.service.OssOperationLogService;
import com.zbg.secyun.service.OssVulnerabilityService;
import com.zbg.secyun.service.VulnCweService;
import com.zbg.secyun.util.DateUtils;
import com.zbg.secyun.util.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Slf4j
public class NVDTask {

    @Autowired
    private OssVulnerabilityService vulnService;

    @Autowired
    private VulnCweService cweService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private OssOperationLogService logService;

    @Bean
    public RestTemplate restTemplate() {
        // 设置超时时间
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        // 20s
        requestFactory.setConnectTimeout(20*1000);
        requestFactory.setReadTimeout(20*1000);
        return new RestTemplate(requestFactory);
    }

    /**
     * 根据日期获取cve更新
     *
     * @param date cve的更新日期
     * @return 程序运行结果描述
     */
    public String getCveByDate(String date) {
        try {
            /**
             * 在循环中调用的，尽量避免变量的循环创建
             */
            log.info("cve更新开始");
            // 设置日期，字符串转换格式(cve漏洞创建记录时间是20210205格式的)
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'");
            // 记录返回数据的索引index
            int cveIndex = 0;
            // 记录返回数据总数量
            int cveTotal = 0;
            // 记录页面显示数量
            int perPage = 0;
            // 记录页面json对象
            JsonNode jsonNode = null;
            // 记录漏洞对象
            OssVulnerabilityWithBLOBs oVulnerability = null;
            // 记录当前处理的cve json对象
            JsonNode cveItems = null;
            // 小范围处理数据使用的node/iter   随用随清空
            JsonNode node = null;
            Iterator<JsonNode> iter = null;
            // 存储漏洞引用链接
            List<String> references = null;
            while (cveIndex < cveTotal || cveTotal == 0) {
                // cve漏洞按日期更新页面连接
                // 注释： date为2021-07-26，则代表获取更新时间在 (7月26 - 当前) 之间的所有的数据
                // pageIndex 为所有返回数据的索引，
                // 获取页面
                URI uri = URI.create("https://services.nvd.nist.gov/rest/json/cves/1.0?modStartDate=" + date + "T00:00:00:000%20UTC-05:00&startIndex=" + cveIndex);
                try {
                    String cveListJson = restTemplate.getForObject(uri, String.class);
                    // 获取cve详情json对象
                    jsonNode = objectMapper.readTree(cveListJson);
                } catch (Exception e) {
                    log.info("连接失败，重新连接。。。。。。。");
                    // 跳出循环，重新连接网站
                    jsonNode = null;
                    continue;
                }
                // 获取页面显示数量
                perPage = jsonNode.get("resultsPerPage").intValue();
                if (cveTotal == 0) {
                    // 获取返回数据总数量
                    cveTotal = jsonNode.get("totalResults").intValue();
                    log.info("总共需要更新数据为：" + cveTotal);
                }
                // 循环获取当前页面上所有漏洞对象
                for (int i = 0; i < perPage; i++) {
                    // 获取cve json对象
                    cveItems = jsonNode.get("result").get("CVE_Items").get(i);
                    // 实例化漏洞对象
                    oVulnerability = new OssVulnerabilityWithBLOBs();
                    // 设置cve编号
                    oVulnerability.setCveNo(cveItems.get("cve").get("CVE_data_meta").get("ID").asText());
                    // 设置cve厂商
                    oVulnerability.setManufacturer(cveItems.get("cve").get("CVE_data_meta").get("ASSIGNER").asText());
                    /** cve创建时间更新时间不确定
                    // 设置cve漏洞创建记录时间
                    String cvePublishDateStr = getCvePublishDate(oVulnerability.getCveNo());
                    if (cvePublishDateStr != null) {
                        oVulnerability.setPublishDateCve(sdf.parse(cvePublishDateStr));
                         // cve漏洞更新时间暂时使用创建记录时间，因为没有找到更新时间
                        oVulnerability.setAnnounceDateCve(oVulnerability.getPublishDateCve());
                    }
                    */
                    // cve创建更新时间暂时使用nvd时间
                    String publishDate = cveItems.get("publishedDate").asText();
                    if(StringUtils.isNotEmpty(publishDate)){
                        oVulnerability.setPublishDateCve(sdf.parse(publishDate));
                    }
                    String announceDate = cveItems.get("lastModifiedDate").asText();
                    if(StringUtils.isNotEmpty(announceDate)){
                        oVulnerability.setAnnounceDateCve(sdf.parse(announceDate));
                    }
                    // 设置漏洞危险级别
                    if (cveItems.get("impact").has("baseMetricV3")) {
                        if (cveItems.get("impact").get("baseMetricV3").has("cvssV3")) {
                            if (cveItems.get("impact").get("baseMetricV3").get("cvssV3").has("baseSeverity")) {
                                oVulnerability.setCveLevel(cveItems.get("impact").get("baseMetricV3").get("cvssV3").get("baseSeverity").asText());
                            }
                        }
                    } else if (cveItems.get("impact").has("baseMetricV2")) {
                        if (cveItems.get("impact").get("baseMetricV2").has("severity")) {
                            oVulnerability.setCveLevel(cveItems.get("impact").get("baseMetricV2").get("severity").asText());
                        }
                    }
                    // 设置cwe相关信息
                    if (cveItems.get("cve").get("problemtype").get("problemtype_data").size() > 0) {
                        iter = cveItems.get("cve").get("problemtype").get("problemtype_data").iterator();
                        if (iter.hasNext()) {
                            node = iter.next();
                            iter = node.get("description").iterator();
                            if (iter.hasNext()) {
                                node = iter.next();
                                // 漏洞类型为cweid，还需要去cwe表查出具体名称
                                VulnCwe vulnCwe = cweService.selectCweByCweNo(node.get("value").asText());
                                oVulnerability.setCweNo(vulnCwe.getCweId());
                                oVulnerability.setCweName(vulnCwe.getCweName());
                                oVulnerability.setCweRef(vulnCwe.getCweRef());
                            } else {
                                // 数据中不存在cwe信息
                                VulnCwe vulnCwe = cweService.selectCweByCweNo("");
                                oVulnerability.setCweNo(vulnCwe.getCweId());
                                oVulnerability.setCweName(vulnCwe.getCweName());
                                oVulnerability.setCweRef(vulnCwe.getCweRef());
                            }
                        }
                        iter = null;
                        node = null;
                    }
                    // 设置漏洞描述
                    if (cveItems.get("cve").get("description").get("description_data").size() > 0) {
                        iter = cveItems.get("cve").get("description").get("description_data").iterator();
                        if (iter.hasNext()) {
                            oVulnerability.setDescEn(iter.next().get("value").asText());
                        }
                        iter = null;
                    }
                    // 设置cve引用
                    oVulnerability.setCveRef("https://nvd.nist.gov/vuln/detail/" + oVulnerability.getCveNo());
                    // 设置漏洞引用链接
                    if (cveItems.get("cve").get("references").get("reference_data").size() > 0) {
                        references = new ArrayList<>();
                        iter = cveItems.get("cve").get("references").get("reference_data").iterator();
                        while (iter.hasNext()) {
                            node = iter.next();
                            references.add(node.get("refsource") + "\n" + node.get("url"));
                        }
                        node = null;
                        iter = null;
                        oVulnerability.setReferencesRef(String.join("\n", references));
                    }
                    vulnService.saveByCveNo(oVulnerability);
                    log.info(oVulnerability.getCveNo() + "更新成功,已更新数据：" + (cveIndex + i + 1) + "个,一共有：" + cveTotal);
                    cveItems = null;
                    oVulnerability = null;
                }
                jsonNode = null;
                cveIndex = cveIndex + perPage;
            }
            log.info(cveTotal + "个漏洞数据更新成功");
            //操作记录表添加信息
            OssOperationLog osslog = new OssOperationLog();
            osslog.setOperationNumber(cveTotal);
            osslog.setOperationDesc("漏洞数据表更新cve数据");
            logService.insertLog(osslog);
            return cveTotal + "个漏洞数据更新成功";
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "数据更新失败";
    }

    // 记录cve漏洞创建记录时间获取次数
    private int getCvePublishDateIndex = 1;

    /**
     * 通过cveNo获取cve漏洞创建记录时间
     *
     * @param cveNo cve漏洞编号
     * @return cve漏洞创建记录时间/null
     */
    public String getCvePublishDate(String cveNo) {
        try {
            String url = "http://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cveNo;
            Document document = Jsoup.connect(url).timeout(10 * 1000).get();
            Element div = document.getElementById("GeneratedTable");
            return div.getElementsByTag("table").get(0).getElementsByTag("tbody").get(0).getElementsByTag("tr").get(10).getElementsByTag("td").get(0).text();
        } catch (Exception e) {
            // 获取次数达3此不在获取
            if (getCvePublishDateIndex >= 3) {
                return null;
            }
            getCvePublishDateIndex++;
            // 获取失败时尝试重新获取
            return getCvePublishDate(cveNo);
        }

    }

    /**
     * 这个方法获取内容有点问题，暂时不使用
     * 根据cve编号获取cve详情
     *
     * @param cveNo cve编号
     * @return 程序运行结果描述
     */
    public String getCveByCveNo(String cveNo) {
        try {
            /**
             * 在循环中调用的，尽量避免变量的循环创建
             */
            // cve漏洞按cve编号更新数据
            String url = "https://services.nvd.nist.gov/rest/json/cve/1.0/" + cveNo;
            // 获取页面
            URI uri = URI.create(url);
            String cveJson = restTemplate.getForObject(uri, String.class);
            // 获取cve详情json对象
            JsonNode jsonNode = objectMapper.readTree(cveJson);
            // 创建漏洞对象
            OssVulnerabilityWithBLOBs oVulnerability = new OssVulnerabilityWithBLOBs();
            // 获取出漏洞中的所有cpe信息迭代器
            Iterator<JsonNode> confNodesIter = jsonNode.get("configurations").get("nodes").elements();
            // cpe信息字符串集合
            List<String> cpes = new ArrayList<>();
            // 记录cpe节点信息Node
            JsonNode cpeNode = null;
            // 记录cpe中children迭代器
            Iterator<JsonNode> childrenIter = null;
            // 记录cpe中children节点对象
            JsonNode childrenNode = null;
            // 记录cpe中cpeMatch迭代器
            Iterator<JsonNode> cpeMatchIter = null;
            // 循环获取cpe信息
            while (confNodesIter.hasNext()) {
                // 拿到第一个节点信息
                cpeNode = confNodesIter.next();
                // 如果节点中有children信息，遍历拿取
                if (cpeNode.has("children")) {
                    childrenIter = cpeNode.get("children").elements();
                    while (childrenIter.hasNext()) {
                        childrenNode = childrenIter.next();
                        if (childrenNode.has("cpe_match")) {
                            cpeMatchIter = childrenNode.get("cpe_match").elements();
                            while (cpeMatchIter.hasNext()) {
                                // 通过迭代器获取next（）对象获取cpe23Uri节点对应的值放入集合中
                                cpes.add(cpeMatchIter.next().get("cpe23Uri").asText());
                            }
                        }
                    }
                }
                // 如果节点中有cpe_match信息，遍历拿取
                if (cpeNode.has("cpe_match")) {
                    cpeMatchIter = cpeNode.get("cpe_match").elements();
                    while (cpeMatchIter.hasNext()) {
                        // 通过迭代器获取next（）对象获取cpe23Uri节点对应的值放入集合中
                        cpes.add(cpeMatchIter.next().get("cpe23Uri").asText());
                    }
                }
            }

            // 根据cpe获取出项目,将出现次数最多的项目设置成漏洞的项目
//            oVulnerability.setKingdom(StringUtils.findMaxCountEntry(cpes.stream().map((cpe) -> cpe.split(":")[4]).collect(Collectors.toList())));
            // 根据cpe获取出开发组织,将出现次数最多的开发组织设置成漏洞的开发组织
            oVulnerability.setManufacturer(StringUtils.findMaxCountEntry(cpes.stream().map((cpe) -> cpe.split(":")[3]).collect(Collectors.toList())));

            // 解析cpe信息，获取漏洞关联组件信息


            // 设置cve编号
            oVulnerability.setCveNo(jsonNode.get("cve").get("CVE_data_meta").get("ID").asText());
            // 设置漏洞危险级别
//            oVulnerability.setLevel(jsonNode.get("impact").get("baseMetricV3").get("cvssV3").get("baseSeverity").asText());
            // 设置发布日期和最后更新日期
            oVulnerability.setPublishDateCve(DateUtils.parseDate(jsonNode.get("publishedDate").asText(""), "yyyy-MM-dd'T'HH:mm'Z'"));
            oVulnerability.setAnnounceDateCve(DateUtils.parseDate(jsonNode.get("lastModifiedDate").asText(""), "yyyy-MM-dd'T'HH:mm'Z'"));
            // 设置漏洞描述
//            oVulnerability.setDesc(jsonNode.get("cve").get("description").get("description_data").get("value").asText());
            // 设置cve引用
            oVulnerability.setCveRef("https://nvd.nist.gov/vuln/detail/" + cveNo);
            // 设置漏洞引用链接
            List<String> references = new ArrayList<>();
            Iterator<JsonNode> refDataNode = jsonNode.get("cve").get("references").get("reference_data").iterator();
            while (refDataNode.hasNext()) {
                JsonNode refData = refDataNode.next();
                references.add(refData.get("refsource") + "\n" + refData.get("url"));
            }
//            oVulnerability.setReferences(String.join("\n", references));
//            service.saveByCveNo(oVulnerability);
            return cveNo + "漏洞数据更新成功";
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "数据更新失败";
    }


}
