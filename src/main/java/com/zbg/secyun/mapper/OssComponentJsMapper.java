package com.zbg.secyun.mapper;

import com.zbg.secyun.domain.OssComponentJs;
import com.zbg.secyun.domain.OssComponentJsExample;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface OssComponentJsMapper {
    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_js
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int countByExample(OssComponentJsExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_js
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int deleteByExample(OssComponentJsExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_js
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int deleteByPrimaryKey(Integer id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_js
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int insert(OssComponentJs record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_js
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int insertSelective(OssComponentJs record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_js
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    List<OssComponentJs> selectByExample(OssComponentJsExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_js
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    OssComponentJs selectByPrimaryKey(Integer id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_js
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int updateByExampleSelective(@Param("record") OssComponentJs record, @Param("example") OssComponentJsExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_js
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int updateByExample(@Param("record") OssComponentJs record, @Param("example") OssComponentJsExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_js
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int updateByPrimaryKeySelective(OssComponentJs record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_component_js
     *
     * @mbggenerated Tue Aug 03 11:05:21 CST 2021
     */
    int updateByPrimaryKey(OssComponentJs record);
}