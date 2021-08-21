package com.zbg.secyun.service;

import com.zbg.secyun.domain.OssComponentJava;

import java.util.List;

public interface OssComponentJavaService {
    List<OssComponentJava> selectByName(String group, String name);
}
