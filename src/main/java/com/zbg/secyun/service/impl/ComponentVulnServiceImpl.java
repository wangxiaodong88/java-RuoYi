package com.zbg.secyun.service.impl;

import com.zbg.secyun.domain.OssComponentVuln;
import com.zbg.secyun.mapper.OssComponentVulnMapper;
import com.zbg.secyun.service.ComponentVulnService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class ComponentVulnServiceImpl implements ComponentVulnService {

    @Autowired
    private OssComponentVulnMapper comVulnMapper;


    @Override
    public int insertComponentVuln(OssComponentVuln componentVuln) {
        log.info("保存组件漏洞关联数据。");
        try {
            return comVulnMapper.insertSelective(componentVuln);
        }catch (Exception e){
            return 0;
        }

    }
}
