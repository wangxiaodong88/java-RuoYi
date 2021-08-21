package com.zbg.secyun.service.impl;

import com.zbg.secyun.domain.OssComponentCcpp;
import com.zbg.secyun.domain.OssComponentCcppExample;
import com.zbg.secyun.mapper.OssComponentCcppMapper;
import com.zbg.secyun.service.OssComponentCcppService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
public class OssComponentCcppServiceImpl implements OssComponentCcppService {

    @Autowired
    private OssComponentCcppMapper ccppMapper;

    @Override
    public List<OssComponentCcpp> selectByName(String name) {
        log.info("模糊查询c/c++信息");
        OssComponentCcppExample ex = new OssComponentCcppExample();
        OssComponentCcppExample.Criteria criteria = ex.createCriteria();
        criteria.andLanguageEqualTo("C/C++");
//        criteria.andNameLike("%"+name+"%");
        criteria.andNameEqualTo(name);
        return ccppMapper.selectByExample(ex);
    }
}
