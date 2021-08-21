package com.zbg.secyun;

import com.zbg.secyun.domain.OssVulnerabilityWithBLOBs;
import com.zbg.secyun.service.OssVulnerabilityService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class ServiceTest {

    @Autowired
    private OssVulnerabilityService service;

    @Test
    public void serviceInsertTest(){
        OssVulnerabilityWithBLOBs vb = new OssVulnerabilityWithBLOBs();
        vb.setRecommendations("65641651");
        vb.setCnnvdRef("sdfdsf");
        service.insert(vb);
        System.out.println("inset test running success");
    }

    @Test
    public void serviceUpdateTest(){
        OssVulnerabilityWithBLOBs vb = new OssVulnerabilityWithBLOBs();
        vb.setId(1);
        vb.setCveRef("dfsfds");
        vb.setCnnvdName("sdfdsffds");
        service.update(vb);
        System.out.println("update test running success");
    }

}
