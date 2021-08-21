package com.zbg.secyun.service.impl;

import com.zbg.secyun.domain.OssComponentDotnet;
import com.zbg.secyun.domain.OssComponentDotnetExample;
import com.zbg.secyun.mapper.OssComponentDotnetMapper;
import com.zbg.secyun.service.OssComponentDotnetService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
public class OssComponentDotnetServiceImpl implements OssComponentDotnetService {

    @Autowired
    private OssComponentDotnetMapper dotnetMapper;

    @Override
    public List<OssComponentDotnet> selectByName(String name) {
        log.info("模糊查询.net信息");
        OssComponentDotnetExample ex = new OssComponentDotnetExample();
        OssComponentDotnetExample.Criteria criteria = ex.createCriteria();
        criteria.andLanguageEqualTo(".Net");
//        criteria.andNameLike("%"+name+"%");
        criteria.andNameEqualTo(name);
        return dotnetMapper.selectByExample(ex);
    }
}
