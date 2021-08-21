package com.zbg.secyun.service;

import com.zbg.secyun.domain.OssComponentJs;

import java.util.List;

public interface OssComponentJsService {
    List<OssComponentJs> selectByName(String name);
}
