import ida_bytes
import ida_nalt
import ida_segment
import idc

def get_strlit_len(ea):
    len = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C, 0)
    return len

def create_ins_to_string(ea, len):
    create_pass = ida_bytes.create_strlit(ea, len, ida_nalt.STRTYPE_C)
    if create_pass:
        print(f"创建成功 {hex(ea)},len:{len}")
    # else:
    #     print(f"创建失败 {hex(ea)},len:{len}")
    return create_pass

def is_import_symbol(ea):
    target_ea = ida_bytes.get_qword(ea)
    seg = ida_segment.getseg(target_ea)
    if seg is not None and seg.type == ida_segment.SEG_XTRN:
        return True
    else:
        return False

def del_items(ea,len):
    ida_bytes.del_items(ea, 0, len)

def is_printable_ascii(byte_val):
    """判断是否为可打印ASCII字符"""
    return 0x20 <= byte_val <= 0x7E

def find_string_boundary(start_ea, max_search=100000):
    """从start_ea开始，找到字符串的实际结束位置"""
    ea = start_ea
    end_ea = start_ea + max_search

    while ea < end_ea:
        # 检查当前字节
        try:
            byte_val = ida_bytes.get_byte(ea)
        except:
            break

        # 当传入的地址是终止符时直接返回
        if byte_val == 0 and (ea-start_ea == 0):
            return -1
        # 遇到NUL终止符，字符串结束
        elif byte_val == 0:
            return ea

        # 当传入的地址是非可打印字符时直接返回
        if not is_printable_ascii(byte_val) and (ea-start_ea == 0):
            return -1
        # 遇到非可打印字符，字符串结束
        elif not is_printable_ascii(byte_val):
            return ea

        ea += 1
    return -1

# 0xCA010
def main():
    data_seg = ida_segment.get_segm_by_name(".data")
    data_seg_start = data_seg.start_ea
    data_seg_end = data_seg.end_ea
    data_len = data_seg_end-data_seg_start
    print(f"data段地址:{hex(data_seg_start)}-{hex(data_seg_end)},size:{data_len}")

    ea = data_seg_start
    create_count = 0
    while ea < data_seg_end:
        # 如果该地址是导入符号就跳过
        is_symbol = is_import_symbol(ea)
        if not is_symbol:
            # 寻找字符串边界地址
            string_boundary_ea = find_string_boundary(ea,data_len)
            if string_boundary_ea == -1:
                ea += 1
                continue
            string_len = string_boundary_ea-ea
            print(f"ea: {hex(ea)},string_boundary_ea: {hex(string_boundary_ea)},string_len: {string_len}")

            # 取消指定大小的数据定义
            del_items(ea,string_len+1)

            # 创建字符串
            create_pass = create_ins_to_string(ea,string_len+1)
            if create_pass:
                ea = string_boundary_ea
                create_count += 1

            ea += 1
        else:
            ea = idc.next_head(ea)

    print(f"已创建 {create_count} 个string条目")
