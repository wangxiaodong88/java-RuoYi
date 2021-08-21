package com.zbg.secyun.service.impl;

import com.zbg.secyun.domain.OssComponentPy;
import com.zbg.secyun.domain.OssComponentPyExample;
import com.zbg.secyun.mapper.OssComponentPyMapper;
import com.zbg.secyun.service.OssComponentPyService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
public class OssComponentPyServiceImpl implements OssComponentPyService {

    @Autowired
    private OssComponentPyMapper pyMapper;

    @Override
    public List<OssComponentPy> selectByName(String name) {
        log.info("模糊查询python数据");
        OssComponentPyExample ex = new OssComponentPyExample();
        OssComponentPyExample.Criteria criteria = ex.createCriteria();
        criteria.andLanguageEqualTo("Python");
//        criteria.andNameLike("%"+name+"%");
        criteria.andNameEqualTo(name);
        return pyMapper.selectByExample(ex);

    }
}
