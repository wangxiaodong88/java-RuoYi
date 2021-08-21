package com.zbg.secyun.util;

import java.lang.management.ManagementFactory;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

/**
 * 时间工具类
 * 
 * @author ruoyi
 */
public class DateUtils
{
    public static String YYYY = "yyyy";

    public static String YYYY_MM = "yyyy-MM";

    public static String YYYY_MM_DD = "yyyy-MM-dd";

    public static String YYYYMMDDHHMMSS = "yyyyMMddHHmmss";

    public static String YYYY_MM_DD_HH_MM_SS = "yyyy-MM-dd HH:mm:ss";

    private static String[] parsePatterns = {
            "yyyy-MM-dd", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm", "yyyy-MM", 
            "yyyy/MM/dd", "yyyy/MM/dd HH:mm:ss", "yyyy/MM/dd HH:mm", "yyyy/MM",
            "yyyy.MM.dd", "yyyy.MM.dd HH:mm:ss", "yyyy.MM.dd HH:mm", "yyyy.MM"};

    /**
     * 获取当前Date型日期
     * 
     * @return Date() 当前日期
     */
    public static Date getNowDate()
    {
        return new Date();
    }

    /**
     * 获取当前日期, 默认格式为yyyy-MM-dd
     * 
     * @return String
     */
    public static String getDate()
    {
        return dateTimeNow(YYYY_MM_DD);
    }

    public static final String getTime()
    {
        return dateTimeNow(YYYY_MM_DD_HH_MM_SS);
    }

    public static final String dateTimeNow()
    {
        return dateTimeNow(YYYYMMDDHHMMSS);
    }

    public static final String dateTimeNow(final String format)
    {
        return parseDateToStr(format, new Date());
    }

    public static final String dateTime(final Date date)
    {
        return parseDateToStr(YYYY_MM_DD, date);
    }

    public static final String parseDateToStr(final String format, final Date date)
    {
        return new SimpleDateFormat(format).format(date);
    }

    public static final Date dateTime(final String format, final String ts)
    {
        try
        {
            return new SimpleDateFormat(format).parse(ts);
        }
        catch (ParseException e)
        {
            throw new RuntimeException(e);
        }
    }


    /**
     * 日期型字符串转化为日期 格式
     * @param str 需要转换的日期字符串
     * @param dateTypeStr 字符串对应的日期格式
     * @return  转换后的日期对象
     */
    public static Date parseDate(Object str, String dateTypeStr)
    {
        if (str == null)
        {
            return null;
        }
        try
        {
            return new SimpleDateFormat(dateTypeStr).parse(str.toString());
        }
        catch (ParseException e)
        {
            return null;
        }
    }

    /**
     * 获取服务器启动时间
     */
    public static Date getServerStartDate()
    {
        long time = ManagementFactory.getRuntimeMXBean().getStartTime();
        return new Date(time);
    }

    /**
     * 计算相差天数
     */
    public static int differentDaysByMillisecond(Date date1, Date date2)
    {
        return Math.abs((int) ((date2.getTime() - date1.getTime()) / (1000 * 3600 * 24)));
    }
    public static int differentDaysByYear(Date date1, Date date2)
    {
        return Math.abs((int) ((date2.getTime() - date1.getTime()) / (1000 * 3600 * 24)));
    }


    /**
     * 计算两个时间差
     */
    public static String getDatePoor(Date endDate, Date nowDate)
    {
        long nd = 1000 * 24 * 60 * 60;
        long nh = 1000 * 60 * 60;
        long nm = 1000 * 60;
        // long ns = 1000;
        // 获得两个时间的毫秒时间差异
        long diff = endDate.getTime() - nowDate.getTime();
        // 计算差多少天
        long day = diff / nd;
        // 计算差多少小时
        long hour = diff % nd / nh;
        // 计算差多少分钟
        long min = diff % nd % nh / nm;
        // 计算差多少秒//输出结果
        // long sec = diff % nd % nh % nm / ns;
        return day + "天" + hour + "小时" + min + "分钟";
    }

    public static String quarterName(String name){
        Date date = new Date();
        int year = date.getYear()+1900;
        int month = date.getMonth();
        StringBuffer buffer = new StringBuffer();
        buffer.append(year);
        buffer.append("年").append("第").append(month/3==0?(month/3+1):month/3).append("季度").append(name);
        return buffer.toString();
    }

    public static int[] getTimeIntervalArray(Calendar nextDate, Calendar previousDate) {
        int year = nextDate.get(Calendar.YEAR) - previousDate.get(Calendar.YEAR);
        int month = nextDate.get(Calendar.MONTH) - previousDate.get(Calendar.MONTH);
        int day = nextDate.get(Calendar.DAY_OF_MONTH) - previousDate.get(Calendar.DAY_OF_MONTH);
        int hour = nextDate.get(Calendar.HOUR_OF_DAY) - previousDate.get(Calendar.HOUR_OF_DAY);// 24小时制
        int min = nextDate.get(Calendar.MINUTE) - previousDate.get(Calendar.MINUTE);
        int second = nextDate.get(Calendar.SECOND) - previousDate.get(Calendar.SECOND);

        boolean hasBorrowDay = false;// "时"是否向"天"借过一位

        if (second < 0) {
            second += 60;
            min--;
        }

        if (min < 0) {
            min += 60;
            hour--;
        }

        if (hour < 0) {
            hour += 24;
            day--;

            hasBorrowDay = true;
        }

        if (day < 0) {
            // 计算截止日期的上一个月有多少天，补上去
            Calendar tempDate = (Calendar) nextDate.clone();
            tempDate.add(Calendar.MONTH, -1);// 获取截止日期的上一个月
            day += tempDate.getActualMaximum(Calendar.DAY_OF_MONTH);

            // nextDate是月底最后一天，且day=这个月的天数，即是刚好一整个月，比如20160131~20160229，day=29，实则为1个月
            if (!hasBorrowDay
                    && nextDate.get(Calendar.DAY_OF_MONTH) == nextDate.getActualMaximum(Calendar.DAY_OF_MONTH)// 日期为月底最后一天
                    && day >= nextDate.getActualMaximum(Calendar.DAY_OF_MONTH)) {// day刚好是nextDate一个月的天数，或大于nextDate月的天数（比如2月可能只有28天）
                day = 0;// 因为这样判断是相当于刚好是整月了，那么不用向 month 借位，只需将 day 置 0
            } else {// 向month借一位
                month--;
            }
        }

        if (month < 0) {
            month += 12;
            year--;
        }

        return new int[]{year, month, day, hour, min, second};
    }
}
