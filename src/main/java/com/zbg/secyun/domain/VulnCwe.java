package com.zbg.secyun.domain;

import lombok.Data;

@Data
public class VulnCwe {
    /**
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column vuln_cwe.id
     *
     * @mbggenerated Sat Jul 31 13:53:33 CST 2021
     */
    private Integer id;

    /**
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column vuln_cwe.cwe_id
     *
     * @mbggenerated Sat Jul 31 13:53:33 CST 2021
     */
    private String cweId;

    /**
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column vuln_cwe.cwe_ref
     *
     * @mbggenerated Sat Jul 31 13:53:33 CST 2021
     */
    private String cweRef;

    /**
     * This field was generated by MyBatis Generator.
     * This field corresponds to the database column vuln_cwe.cwe_name
     *
     * @mbggenerated Sat Jul 31 13:53:33 CST 2021
     */
    private String cweName;

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column vuln_cwe.id
     *
     * @return the value of vuln_cwe.id
     *
     * @mbggenerated Sat Jul 31 13:53:33 CST 2021
     */
    public Integer getId() {
        return id;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column vuln_cwe.id
     *
     * @param id the value for vuln_cwe.id
     *
     * @mbggenerated Sat Jul 31 13:53:33 CST 2021
     */
    public void setId(Integer id) {
        this.id = id;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column vuln_cwe.cwe_id
     *
     * @return the value of vuln_cwe.cwe_id
     *
     * @mbggenerated Sat Jul 31 13:53:33 CST 2021
     */
    public String getCweId() {
        return cweId;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column vuln_cwe.cwe_id
     *
     * @param cweId the value for vuln_cwe.cwe_id
     *
     * @mbggenerated Sat Jul 31 13:53:33 CST 2021
     */
    public void setCweId(String cweId) {
        this.cweId = cweId == null ? null : cweId.trim();
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column vuln_cwe.cwe_ref
     *
     * @return the value of vuln_cwe.cwe_ref
     *
     * @mbggenerated Sat Jul 31 13:53:33 CST 2021
     */
    public String getCweRef() {
        return cweRef;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column vuln_cwe.cwe_ref
     *
     * @param cweRef the value for vuln_cwe.cwe_ref
     *
     * @mbggenerated Sat Jul 31 13:53:33 CST 2021
     */
    public void setCweRef(String cweRef) {
        this.cweRef = cweRef == null ? null : cweRef.trim();
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column vuln_cwe.cwe_name
     *
     * @return the value of vuln_cwe.cwe_name
     *
     * @mbggenerated Sat Jul 31 13:53:33 CST 2021
     */
    public String getCweName() {
        return cweName;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column vuln_cwe.cwe_name
     *
     * @param cweName the value for vuln_cwe.cwe_name
     *
     * @mbggenerated Sat Jul 31 13:53:33 CST 2021
     */
    public void setCweName(String cweName) {
        this.cweName = cweName == null ? null : cweName.trim();
    }
}