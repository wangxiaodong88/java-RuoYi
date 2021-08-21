package com.zbg.secyun.service.impl;

import com.zbg.secyun.domain.VulnCwe;
import com.zbg.secyun.domain.VulnCweExample;
import com.zbg.secyun.mapper.VulnCweMapper;
import com.zbg.secyun.service.VulnCweService;
import com.zbg.secyun.task.CWETask;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
public class VulnCweServiceImpl implements VulnCweService {

    @Autowired
    private VulnCweMapper mapper;
    @Autowired
    private CWETask cweTask;

    @Override
    public VulnCwe selectCweByCweNo(String cweNo) {
        // 如果cwe编号为空，返回 NVD-CWE-noinfo
        if ("".equals(cweNo) || cweNo.length() == 0 ) {
            return mapper.selectByPrimaryKey(1);
        }
        // 按cwe编号查数据库，查到直接返回，否则去cwe官网爬数据并存到自己数据库
        VulnCweExample ex = new VulnCweExample();
        VulnCweExample.Criteria criteria = ex.createCriteria();
        criteria.andCweIdEqualTo(cweNo);
        List<VulnCwe> vulnCwes = mapper.selectByExampleWithBLOBs(ex);
        if(vulnCwes.size()>0){
            return vulnCwes.get(0);
        }
        // 去cwe官网查数据
        VulnCwe vulnCwe = cweTask.getVulnCwe(cweNo);
        if(vulnCwe!=null) {
            mapper.insertSelective(vulnCwe);
        }
        return vulnCwe;
    }


}
