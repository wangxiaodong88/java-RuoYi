package com.zbg.secyun.mapper;

import com.zbg.secyun.domain.VulnACpe;
import com.zbg.secyun.domain.VulnACpeExample;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface VulnACpeMapper {
    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table vuln_a_cpe
     *
     * @mbggenerated Thu Aug 05 09:28:27 CST 2021
     */
    int countByExample(VulnACpeExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table vuln_a_cpe
     *
     * @mbggenerated Thu Aug 05 09:28:27 CST 2021
     */
    int deleteByExample(VulnACpeExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table vuln_a_cpe
     *
     * @mbggenerated Thu Aug 05 09:28:27 CST 2021
     */
    int deleteByPrimaryKey(Integer id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table vuln_a_cpe
     *
     * @mbggenerated Thu Aug 05 09:28:27 CST 2021
     */
    int insert(VulnACpe record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table vuln_a_cpe
     *
     * @mbggenerated Thu Aug 05 09:28:27 CST 2021
     */
    int insertSelective(VulnACpe record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table vuln_a_cpe
     *
     * @mbggenerated Thu Aug 05 09:28:27 CST 2021
     */
    List<VulnACpe> selectByExample(VulnACpeExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table vuln_a_cpe
     *
     * @mbggenerated Thu Aug 05 09:28:27 CST 2021
     */
    VulnACpe selectByPrimaryKey(Integer id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table vuln_a_cpe
     *
     * @mbggenerated Thu Aug 05 09:28:27 CST 2021
     */
    int updateByExampleSelective(@Param("record") VulnACpe record, @Param("example") VulnACpeExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table vuln_a_cpe
     *
     * @mbggenerated Thu Aug 05 09:28:27 CST 2021
     */
    int updateByExample(@Param("record") VulnACpe record, @Param("example") VulnACpeExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table vuln_a_cpe
     *
     * @mbggenerated Thu Aug 05 09:28:27 CST 2021
     */
    int updateByPrimaryKeySelective(VulnACpe record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table vuln_a_cpe
     *
     * @mbggenerated Thu Aug 05 09:28:27 CST 2021
     */
    int updateByPrimaryKey(VulnACpe record);
}