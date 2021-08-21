package com.zbg.secyun.task;

import com.zbg.secyun.domain.OssVulnerabilityWithBLOBs;
import com.zbg.secyun.service.OssVulnerabilityService;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.text.SimpleDateFormat;
import java.util.concurrent.TimeUnit;

@Component
public class CNNVDTask {

    @Autowired
    private OssVulnerabilityService service;

    /**
     * 获取国家信息安全漏洞库中更新的信息
     */
    public String getCnnvdByUpdateDate(String updateDate) {
        try {
            /**
             * 需要多次循环爬取数据，因此变量定义尽量放在循环外，避免重复创建变量
             */
            // 记录一共更新多少条数据
            int cnnvdNumber = 0;
            // 记录当前爬取的页面数字
            int total = 1;
            // 记录总页面数
            int pagecount = 1;
            // 记录国家信息安全漏洞库更新列表页
            String url = "";
            // 记录列表页Document
            Document document = null;
            // 记录总页数Element
            Element page = null;
            // 记录当前页有多少条信息
            int listCount = 0;
            // 记录cnnvd详情页连接
            String cnnvdUrl = "";
            // 记录漏洞详情页Document
            Document cnnvdDocument = null;
            // 创建漏洞实体类储存数据
            OssVulnerabilityWithBLOBs vulnerability = null;
            // 记录当前cnnvd详细信息Element
            Element detailXq = null;
            // 设置日期，字符串转换格式
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            // 设置cnnvd漏洞简介信息Elements
            Elements dLdjj = null;
            int liIndex = 0;
            while (total <= pagecount) {
                url = "http://www.cnnvd.org.cn/web/vulnerability/querylist.tag?pageno="+total+"&cvCnnvdUpdatedateXq=" + updateDate;

                try{
                    document = Jsoup.connect(url).timeout(10*1000).get();
                }catch (Exception e){
                    document = null;
                    TimeUnit.SECONDS.sleep(1);
                    // 获取出错，尝试重新获取
                    total--;
                    continue;
                }
                // 获取总页数
                page = document.getElementById("pagecount");
                if(page == null){
                    break; // 没有数据信息，直接跳出循环
                }
                pagecount = Integer.parseInt(page.val());
                // 获取总条数
                cnnvdNumber = Integer.parseInt(page.nextElementSibling().text().replaceAll("总条数：","").replaceAll(",",""));
                // 获取当前页有多少条信息
                listCount = document.getElementsByClass("list_list").get(0).child(0).children().size();
                // 获取漏洞信息显示div-ul-li-a
                for (int i = 0; i < listCount; i++) {

                    cnnvdUrl = "http://www.cnnvd.org.cn"+document.getElementById("vulner_" + i).child(0).attr("href");
                    try {
                        cnnvdDocument = Jsoup.connect(cnnvdUrl).timeout(10*1000).get();
                    }catch (Exception e){
                        cnnvdDocument = null;
                        TimeUnit.SECONDS.sleep(1);
                        cnnvdDocument = Jsoup.connect(cnnvdUrl).timeout(10*1000).get();
                    }
                    // 创建漏洞实体类储存数据
                    vulnerability = new OssVulnerabilityWithBLOBs();
                    // 获取cnnvd详细信息
                    detailXq = cnnvdDocument.getElementsByClass("detail_xq").get(0);
                    // 此漏洞在cnnvd中的名称
                    vulnerability.setCnnvdName(detailXq.getElementsByTag("h2").get(0).text());


                    Elements li = detailXq.getElementsByTag("li");
                    for (Element l : li){
                        System.out.println(li);
                    }


//                    // 漏洞cnnvd编号
//                    vulnerability.setCnnvdNo(detailXq.child(1).child(0).child(0).text().replaceAll("CNNVD编号：",""));
//                    // 漏洞cnnvd地址
//                    vulnerability.setCnnvdRef(cnnvdUrl);
//                    // cnnvd中的漏洞级别
//                    try {
//                        vulnerability.setLevel(detailXq.child(1).child(1).child(1).text());
//                        liIndex = 1;
//                    }catch (Exception e){
//                        liIndex = 2;
//                        vulnerability.setLevel(detailXq.child(1).child(liIndex).child(1).text());
//                    }
//                    // 漏洞cve编号
//                    vulnerability.setCveNo(detailXq.child(1).child(liIndex+1).child(1).text());
//                    // 漏洞类型（中文）
//                    vulnerability.setCategoryCn(detailXq.child(1).child(liIndex+2).child(1).text());
//                    // cnnvd漏洞发布时间
//                    vulnerability.setPublishDateCnnvd(sdf.parse(detailXq.child(1).child(liIndex+3).child(1).text()));
//                    // cnnvd漏洞更新时间
//                    vulnerability.setAnnounceDateCnnvd(sdf.parse(detailXq.child(1).child(liIndex+5).child(1).text()));
//                    // 获取cnnvd漏洞简介信息
//                    dLdjj = cnnvdDocument.getElementsByClass("d_ldjj");
//                    // 漏洞描述（中文）
//                    vulnerability.setDescCn(dLdjj.get(0).children().text());
//                    // 漏洞修复建议
//                    vulnerability.setRecommendations(dLdjj.get(1).children().text());
//                    // 参考
//                    vulnerability.setReferences(dLdjj.get(2).children().text());
//                    service.saveByCnnvdNo(vulnerability);
                    cnnvdDocument = null;
                    vulnerability = null;
                    detailXq = null;
                    dLdjj = null;
                }
                System.out.println("当前页数"+ total +"，总共页数" + pagecount);
                total ++;
                document = null;
            }
            return "更新完成，共更新"+cnnvdNumber+"条数据";
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "更新失败";
    }




}
