package com.zbg.secyun.service.impl;

import com.zbg.secyun.domain.OssComponentJava;
import com.zbg.secyun.domain.OssComponentJavaExample;
import com.zbg.secyun.mapper.OssComponentJavaMapper;
import com.zbg.secyun.service.OssComponentJavaService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
public class OssComponentJavaServiceImpl implements OssComponentJavaService {

    @Autowired
    private OssComponentJavaMapper javaMapper;

    @Override
    public List<OssComponentJava> selectByName(String group, String name) {
        log.info("模糊查找group，name对应的java数据-");
        OssComponentJavaExample ex = new OssComponentJavaExample();
        OssComponentJavaExample.Criteria criteria = ex.createCriteria();
        criteria.andLanguageEqualTo("JAVA");
        criteria.andGroupEqualTo(group);
//        criteria.andNameLike("%"+name+"%");
        criteria.andnameEqualTo(name);
        return javaMapper.selectByExample(ex);
    }
}
