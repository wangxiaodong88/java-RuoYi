package com.zbg.secyun.service.impl;

import com.zbg.secyun.domain.OssComponentJs;
import com.zbg.secyun.domain.OssComponentJsExample;
import com.zbg.secyun.mapper.OssComponentJsMapper;
import com.zbg.secyun.service.OssComponentJsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.swing.*;
import java.util.List;

@Service
@Slf4j
public class OssComponentJsServiceImpl implements OssComponentJsService {

    @Autowired
    private OssComponentJsMapper jsMapper;

    @Override
    public List<OssComponentJs> selectByName(String name) {
        log.info("模糊查询js数据");
        OssComponentJsExample ex = new OssComponentJsExample();
        OssComponentJsExample.Criteria criteria = ex.createCriteria();
        criteria.andLanguageEqualTo("JavaScript");
//        criteria.andNameLike("%"+name+"%");
        criteria.andNameEqualTo(name);
        return jsMapper.selectByExample(ex);
    }
}
