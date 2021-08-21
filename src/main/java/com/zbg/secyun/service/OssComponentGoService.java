package com.zbg.secyun.service;

import com.zbg.secyun.domain.OssComponentGo;

import java.util.List;

public interface OssComponentGoService {
    List<OssComponentGo> selectByName(String name);
}
