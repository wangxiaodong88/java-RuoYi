package com.zbg.secyun.service;


import com.zbg.secyun.domain.OssComponentDotnet;

import java.util.List;

public interface OssComponentDotnetService {
    List<OssComponentDotnet> selectByName(String name);
}
