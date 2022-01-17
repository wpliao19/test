#!/bin/python3
# -*- coding:utf-8 -*-

# CTX Engine-874 : IP
# 1、查询ip样本 2、查看查询结�?# 2、返回正确的ioc信息

from maldium import *
import ctypes


def print_result(result, extra_res):
    if result is None:
        print("query failed")
        return
    if result.eMatchType == engine.NO_MATCH:
        print("result NO_MATCH")
        return
    elif result.eMatchType == engine.LOCAL_PTN_MATCHED:
        match_type = "LOCAL_PTN_MATCHED"
    elif result.eMatchType == engine.REMOTE_CACHE_MATCHED:
        match_type = "REMOTE_CACHE_MATCHED"
    elif result.eMatchType == engine.REMOTE_SERVER_MATCHED:
        match_type = "REMOTE_SERVER_MATCHED"
    else:
        match_type = "UNKNOWN_MATCH_TYPE:" + str(result.eMatchType)

    basic_info = result.basicInfo
    print("result %s %u/%u/%u %u/%u/%u/%u" %
          (match_type, basic_info.ui8Severity, basic_info.ui8Confidence, basic_info.ui8Activity,
           basic_info.aui8Categories[0], basic_info.aui8Categories[1], basic_info.aui8Categories[2],
           basic_info.aui8Categories[3]))

    for res in extra_res:
        print(res)


def test(engine):
    result = engine.lookup_url(ioc)
    extra_res = engine.get_all_detail(result)
    print_result(result, extra_res)
    return result


def get_decimal_num(bin_num):
    decimal_num = 0
    for index, num in enumerate(bin_num[::-1]):
        decimal_num += int(num) * (2 ** int(index))
    return decimal_num


def get_flag(category_num):
    tmp_num = format(ctypes.c_uint32(category_num).value, "#034b")
    first_bin_num = tmp_num[2:10]
    first_decimal_num = get_decimal_num(first_bin_num)

    second_bin_num = tmp_num[10:18]
    second_decimal_num = get_decimal_num(second_bin_num)

    third_bin_num = tmp_num[18:26]
    third_decimal_num = get_decimal_num(third_bin_num)

    fourth_bin_num = tmp_num[26:34]
    fourth_decimal_num = get_decimal_num(fourth_bin_num)

    decimal_num = [first_decimal_num, second_decimal_num, third_decimal_num, fourth_decimal_num]
    # print(decimal_num)
    return decimal_num


if __name__ == "__main__":
    mald_opts = mald_options()
    mald_opts.set_opt(mald_opts.MALD_OPT_PRODUCTID, "TEST_PRODUCT")
    mald_opts.set_opt(mald_opts.MALD_OPT_TOKEN, "TEST_TOKEN")
    mald_opts.set_opt(mald_opts.MALD_OPT_FPTN_DIR, "./ut_ptn")
    mald_opts.set_opt(mald_opts.MALD_OPT_DPTN_DIR, "./ut_ptn")
    # mald_opts.set_opt(mald_opts.MALD_OPT_RATING_TYPE, mald_opts.MALD_RATING_TYPE_LOCAL_DB)
    # mald_opts.set_opt(mald_opts.MALD_OPT_RATING_TYPE, mald_opts.MALD_RATING_TYPE_SERVER)
    mald_opts.set_opt(mald_opts.MALD_OPT_RATING_TYPE, mald_opts.MALD_RATING_TYPE_ALL)
    mald_opts.set_opt(mald_opts.MALD_OPT_WHITELIST_COMP_PATH, "./ut_ptn/whitelist")
    engine = mald_engine(mald_opts)

    globals = {
        'null': 0
    }
    with open("/root/auto_test/pattern_source/ptn.json") as fp:
        while True:
            line = fp.readline()
            if line:
                _line = eval(line.split("\n")[0], globals)
                ioc_type = _line.get("type")
                if ioc_type == "url":
                    _line = _line
                    ioc = _line.get("item")
                    break
            else:
                break
    print(ioc)

    result = test(engine)
    num = _line.get("category")
    decimal_num = get_flag(num)

    if _line['severity'] == result.basicInfo.ui8Severity and _line['confidence'] == result.basicInfo.ui8Confidence and \
            _line['activity'] == result.basicInfo.ui8Activity and decimal_num[0] == result.basicInfo.aui8Categories[
        0] and decimal_num[1] == result.basicInfo.aui8Categories[1] and decimal_num[2] == \
            result.basicInfo.aui8Categories[2] and decimal_num[3] == result.basicInfo.aui8Categories[3]:
        print('Success')
    else:
        print("Fail")
