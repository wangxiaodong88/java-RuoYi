package com.zbg.secyun.mapper;

import com.zbg.secyun.domain.OssOperationLog;
import com.zbg.secyun.domain.OssOperationLogExample;
import java.util.List;
import org.apache.ibatis.annotations.Param;

public interface OssOperationLogMapper {
    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_operation_log
     *
     * @mbggenerated Mon Aug 02 18:16:02 CST 2021
     */
    int countByExample(OssOperationLogExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_operation_log
     *
     * @mbggenerated Mon Aug 02 18:16:02 CST 2021
     */
    int deleteByExample(OssOperationLogExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_operation_log
     *
     * @mbggenerated Mon Aug 02 18:16:02 CST 2021
     */
    int deleteByPrimaryKey(Integer id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_operation_log
     *
     * @mbggenerated Mon Aug 02 18:16:02 CST 2021
     */
    int insert(OssOperationLog record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_operation_log
     *
     * @mbggenerated Mon Aug 02 18:16:02 CST 2021
     */
    int insertSelective(OssOperationLog record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_operation_log
     *
     * @mbggenerated Mon Aug 02 18:16:02 CST 2021
     */
    List<OssOperationLog> selectByExample(OssOperationLogExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_operation_log
     *
     * @mbggenerated Mon Aug 02 18:16:02 CST 2021
     */
    OssOperationLog selectByPrimaryKey(Integer id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_operation_log
     *
     * @mbggenerated Mon Aug 02 18:16:02 CST 2021
     */
    int updateByExampleSelective(@Param("record") OssOperationLog record, @Param("example") OssOperationLogExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_operation_log
     *
     * @mbggenerated Mon Aug 02 18:16:02 CST 2021
     */
    int updateByExample(@Param("record") OssOperationLog record, @Param("example") OssOperationLogExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_operation_log
     *
     * @mbggenerated Mon Aug 02 18:16:02 CST 2021
     */
    int updateByPrimaryKeySelective(OssOperationLog record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table oss_operation_log
     *
     * @mbggenerated Mon Aug 02 18:16:02 CST 2021
     */
    int updateByPrimaryKey(OssOperationLog record);
}