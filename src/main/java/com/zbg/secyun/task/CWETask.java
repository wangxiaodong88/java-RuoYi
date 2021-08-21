package com.zbg.secyun.task;

import com.zbg.secyun.domain.VulnCwe;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.springframework.stereotype.Component;

@Component
public class CWETask {

    public VulnCwe getVulnCwe(String cweNo) {
        try {
            VulnCwe cwe = new VulnCwe();
            String url = "https://cwe.mitre.org/data/definitions/" + (cweNo.replaceAll("CWE-", "")) + ".html";
            cwe.setCweRef(url);
            cwe.setCweId(cweNo);
            Document document = Jsoup.connect(url).timeout(10 * 1000).get();
            // cwe名称所在不好获取，获取后一个div
            Element cweDefinition = document.getElementById("CWEDefinition");
            // 获取cwe名称所在div-h2
            Element cweDiv = cweDefinition.previousElementSibling().getElementsByTag("h2").get(0);
            // 获取cwe名称(用：截取字符串)
            int start = cweDiv.text().indexOf(":") + 1;
            cwe.setCweName(cweDiv.text().substring(start));
            return cwe;
        } catch (Exception e) {
            return null;
        }
    }
}
