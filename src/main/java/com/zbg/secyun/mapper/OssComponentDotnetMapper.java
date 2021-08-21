package com.zbg.secyun.mapper;

import com.zbg.secyun.domain.OssComponentDotnet;
import com.zbg.secyun.domain.OssComponentDotnetExample;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface OssComponentDotnetMapper {
    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_dotnet
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int countByExample(OssComponentDotnetExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_dotnet
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int deleteByExample(OssComponentDotnetExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_dotnet
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int deleteByPrimaryKey(Integer id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_dotnet
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int insert(OssComponentDotnet record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_dotnet
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int insertSelective(OssComponentDotnet record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_dotnet
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    List<OssComponentDotnet> selectByExample(OssComponentDotnetExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_dotnet
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    OssComponentDotnet selectByPrimaryKey(Integer id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_dotnet
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int updateByExampleSelective(@Param("record") OssComponentDotnet record, @Param("example") OssComponentDotnetExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_dotnet
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int updateByExample(@Param("record") OssComponentDotnet record, @Param("example") OssComponentDotnetExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_dotnet
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int updateByPrimaryKeySelective(OssComponentDotnet record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_dotnet
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int updateByPrimaryKey(OssComponentDotnet record);
}