package com.zbg.secyun.service;

import com.zbg.secyun.domain.OssComponentCcpp;

import java.util.List;

public interface OssComponentCcppService {
    List<OssComponentCcpp> selectByName(String name);
}
