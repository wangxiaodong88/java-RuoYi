package com.zbg.secyun.service;

import com.zbg.secyun.domain.VulnACpe;

import java.util.List;

public interface ACpeService {
    List<VulnACpe> getParsingCpes( );

    int deleteCpe(VulnACpe cpe);

    int updateReview(VulnACpe cpe);
}
