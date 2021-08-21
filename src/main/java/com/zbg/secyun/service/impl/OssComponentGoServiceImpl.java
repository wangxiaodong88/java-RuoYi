package com.zbg.secyun.service.impl;

import com.zbg.secyun.domain.OssComponentGo;
import com.zbg.secyun.domain.OssComponentGoExample;
import com.zbg.secyun.mapper.OssComponentGoMapper;
import com.zbg.secyun.service.OssComponentGoService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
public class OssComponentGoServiceImpl implements OssComponentGoService {

    @Autowired
    private OssComponentGoMapper goMapper;

    @Override
    public List<OssComponentGo> selectByName(String name) {
        log.info("模糊查询go信息");
        OssComponentGoExample ex = new OssComponentGoExample();
        OssComponentGoExample.Criteria criteria = ex.createCriteria();
        criteria.andLanguageEqualTo("Golang");
//        criteria.andNameLike("%"+name+"%");
        criteria.andNameEqualTo(name);
        return goMapper.selectByExample(ex);
    }
}
