from bitstring import *

def get_sps((width_in_samples, height_in_samples)):
    mb_width = (width_in_samples + 15) / 16
    mb_height = (height_in_samples + 15) / 16
    #start code
    d = BitStream('uint:32=1')
    #nal_unit: seq_parameter_set_data
    ref_idc = 3
    unit_type = 7
    d += pack('uint:1=0,uint:2,uint:5', ref_idc, unit_type)

    profile_idc = 100
    constraint_set0_flag = constraint_set1_flag = constraint_set2_flag = constraint_set3_flag = constraint_set4_flag = constraint_set5_flag = 0
    level_idc = 32
    seq_parameter_set_id = 0
    chroma_format_idc = 1
    bit_depth_luma_minus8 = 0
    bit_depth_chroma_minus8 = 0
    qpprime_y_zero_transform_bypass_flag = 0
    seq_scaling_matrix_present_flag = 0
    log2_max_frame_num_minus4 = 4
    pic_order_cnt_type = 2
    max_num_ref_frames = 1
    gaps_in_frame_num_value_allowed_flag = 0
    pic_width_in_mbs_minus1 = mb_width - 1
    pic_height_in_map_units_minus1 = mb_height - 1
    frame_mbs_only_flag = 1
    direct_8x8_inference_flag = 1
    frame_cropping_flag = 0
    frame_crop_left_offset, frame_crop_right_offset, frame_crop_top_offset, frame_crop_bottom_offset = 0, 0, 0, 0
    if width_in_samples % 16 or height_in_samples % 16:
        frame_cropping_flag = 1
        frame_crop_left_offset = 0
        frame_crop_right_offset = (mb_width * 16 - width_in_samples) / 2
        frame_crop_top_offset = 0
        frame_crop_bottom_offset = (mb_height * 16 - height_in_samples) / 2
    vui_parameters_present_flag = 0
    d += pack('uint:8,uint:1,uint:1,uint:1,uint:1,uint:1,uint:1,uint:2=0,uint:8,ue',
        profile_idc,
        constraint_set0_flag, constraint_set1_flag, constraint_set2_flag,
        constraint_set3_flag, constraint_set4_flag, constraint_set5_flag,
        level_idc, seq_parameter_set_id)
    if profile_idc in (100, 110, 122, 224, 44, 83, 86, 118, 128):
        d += pack('ue', chroma_format_idc)
        assert chroma_format_idc == 1
        d += pack('ue,ue,uint:1,uint:1',
            bit_depth_luma_minus8, bit_depth_chroma_minus8,
            qpprime_y_zero_transform_bypass_flag,
            seq_scaling_matrix_present_flag)
        assert seq_scaling_matrix_present_flag == 0
        d += pack('ue,ue', log2_max_frame_num_minus4, pic_order_cnt_type)
        assert pic_order_cnt_type == 2
    d += pack('ue,uint:1,ue,ue,uint:1', max_num_ref_frames,
        gaps_in_frame_num_value_allowed_flag, pic_width_in_mbs_minus1,
        pic_height_in_map_units_minus1, frame_mbs_only_flag)
    assert frame_mbs_only_flag != 0
    d += pack('uint:1,uint:1', direct_8x8_inference_flag, frame_cropping_flag)
    if frame_cropping_flag:
        d += pack('ue,ue,ue,ue',
            frame_crop_left_offset, frame_crop_right_offset,
            frame_crop_top_offset, frame_crop_bottom_offset)
    d += pack('uint:1', vui_parameters_present_flag)
    assert vui_parameters_present_flag == 0
    #rbsp_stop_bit
    d += BitStream('uint:1=1')
    #trailing
    if d.len & 7:
        d += BitStream(uint = 0, length = 8 - (d.len & 7))
    return d.bytes

def get_pps():
    #start code
    d = BitStream('uint:32=1')
    #nal_unit: pic_parameter_set_rbsp
    ref_idc = 3
    unit_type = 8
    d += pack('uint:1=0,uint:2,uint:5', ref_idc, unit_type)

    pic_parameter_set_id = 0
    seq_parameter_set_id = 0
    entropy_coding_mode_flag = 1
    bottom_field_pic_order_in_frame_present_flag = 0
    num_slice_groups_minus1 = 0
    num_ref_idx_l0_default_active_minus1 = 0
    num_ref_idx_l1_default_active_minus1 = 0
    weighted_pred_flag = 0
    weighted_bipred_idc = 0
    pic_init_qp_minus26 = 6
    pic_init_qs_minus26 = 6
    chroma_qp_index_offset = 0
    deblocking_filter_control_present_flag = 1
    constrained_intra_pred_flag = 1
    redundant_pic_cnt_present_flag = 0
    d += pack('ue,ue,uint:1,uint:1,ue', pic_parameter_set_id, seq_parameter_set_id, entropy_coding_mode_flag,
        bottom_field_pic_order_in_frame_present_flag, num_slice_groups_minus1)
    assert num_slice_groups_minus1 == 0
    d += pack('ue,ue,uint:1,uint:2,se,se,se,uint:1,uint:1,uint:1',
        num_ref_idx_l0_default_active_minus1, num_ref_idx_l1_default_active_minus1, weighted_pred_flag, weighted_bipred_idc,
        pic_init_qp_minus26, pic_init_qs_minus26, chroma_qp_index_offset, deblocking_filter_control_present_flag,
        constrained_intra_pred_flag, redundant_pic_cnt_present_flag)
    #rbsp_stop_bit
    d += BitStream('uint:1=1')
    #trailing
    if d.len & 7:
        d += BitStream(uint = 0, length = 8 - (d.len & 7))
    return d.bytes
