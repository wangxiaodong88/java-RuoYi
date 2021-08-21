package com.zbg.secyun.service;

import com.zbg.secyun.domain.OssComponentPhp;

import java.util.List;

public interface OssComponentPhpService {
    List<OssComponentPhp> selectByName(String name);
}
