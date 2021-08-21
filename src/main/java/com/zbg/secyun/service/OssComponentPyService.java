package com.zbg.secyun.service;

import com.zbg.secyun.domain.OssComponentPy;

import java.util.List;

public interface OssComponentPyService {
    List<OssComponentPy> selectByName(String name);
}
