package com.zbg.secyun.service.impl;

import com.zbg.secyun.domain.OssOperationLog;
import com.zbg.secyun.mapper.OssOperationLogMapper;
import com.zbg.secyun.service.OssOperationLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class OssOperationLogServiceImpl implements OssOperationLogService {


    @Autowired
    private OssOperationLogMapper mapper;


    @Override
    public int insertLog(OssOperationLog log) {
        return mapper.insertSelective(log);
    }
}
