package com.zbg.secyun.service.impl;

import com.zbg.secyun.domain.VulnACpe;
import com.zbg.secyun.domain.VulnOCpe;
import com.zbg.secyun.mapper.VulnOCpeMapper;
import com.zbg.secyun.service.OCpeService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class OCpeServiceImpl implements OCpeService {

    @Autowired
    private VulnOCpeMapper mapper;


    @Override
    public int insertCpe(VulnACpe aCpe) {
        VulnOCpe oCpe = new VulnOCpe();
        oCpe.setCpe(aCpe.getCpe());
        oCpe.setCnnvdNo(aCpe.getCnnvdNo());
        oCpe.setEdition(aCpe.getEdition());
        oCpe.setPart(aCpe.getPart());
        oCpe.setLanguage(aCpe.getLanguage());
        oCpe.setVersion(aCpe.getVersion());
        oCpe.setVendor(aCpe.getVendor());
        oCpe.setUpdate(aCpe.getUpdate());
        oCpe.setReview(aCpe.getReview());
        oCpe.setProduct(aCpe.getProduct());
        return mapper.insertSelective(oCpe);
    }
}
