package com.zbg.secyun.service.impl;

import com.zbg.secyun.domain.OssComponentPhp;
import com.zbg.secyun.domain.OssComponentPhpExample;
import com.zbg.secyun.mapper.OssComponentPhpMapper;
import com.zbg.secyun.service.OssComponentPhpService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
public class OssComponentPhpServiceImpl implements OssComponentPhpService {

    @Autowired
    private OssComponentPhpMapper phpMapper;

    @Override
    public List<OssComponentPhp> selectByName(String name) {
        log.info("模糊查询php数据");
        OssComponentPhpExample ex = new OssComponentPhpExample();
        OssComponentPhpExample.Criteria criteria = ex.createCriteria();
        criteria.andLanguageEqualTo("Php");
//        criteria.andNameLike("%"+name+"%");
        criteria.andNameEqualTo(name);
        return phpMapper.selectByExample(ex);
    }
}
