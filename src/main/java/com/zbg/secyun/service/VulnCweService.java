package com.zbg.secyun.service;

import com.zbg.secyun.domain.VulnCwe;

public interface VulnCweService {
    VulnCwe selectCweByCweNo(String cweNo);
}
