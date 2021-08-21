package com.zbg.secyun.service.impl;

import com.zbg.secyun.domain.VulnACpe;
import com.zbg.secyun.domain.VulnACpeExample;
import com.zbg.secyun.mapper.VulnACpeMapper;
import com.zbg.secyun.service.ACpeService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
public class ACpeServiceImpl implements ACpeService {


    @Autowired
    private VulnACpeMapper mapper;


    /**
     * 用于cpe解析，获取需要程序解析的所有cpe信息
     * @return
     */
    @Override
    public List<VulnACpe> getParsingCpes( ) {
        log.info("获取需要解析的cpe数据。。。。。。。。。。");
        VulnACpeExample ex = new VulnACpeExample();
        VulnACpeExample.Criteria criteria = ex.createCriteria();
        criteria.andReviewEqualTo(0);
//        criteria.andIdBetween(startId,startId+100000);
        return mapper.selectByExample(ex);
    }

    @Override
    public int deleteCpe(VulnACpe cpe) {
        return mapper.deleteByPrimaryKey(cpe.getId());
    }

    @Override
    public int updateReview(VulnACpe cpe) {
        return mapper.updateByPrimaryKeySelective(cpe);
    }

}
