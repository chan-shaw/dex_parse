import mmap
from struct import unpack


class DexParser(object):
    """Dex file format parser class
    :param string filedir: Dexfile path
    """

    def __init__(self, filedir=None):
        with open(filedir, 'rb') as f:
            self.data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        # DexHeader总长度为0x70,112字节，8字节magci + 4字节signature + 20字节checksum
        # + 4个字节文件总大小 + 4个字节头部长度 + 4个字节大小端标签 + 8个字节link大小偏移
        # + 4个字节 mapitem 偏移
        # + 7个类型[大小+偏移]
        """
        u1  magic[8];       //取值必须是字符串 "dex\n035\0" 或者字节byte数组 {0x64 0x65 0x78 0x0a 0x30 0x33 0x35 0x00}
        u4  checksum;       //文件内容的校验和,不包括magic和自己,主要用于检查文件是否损坏
        u1  signature[kSHA1DigestLen];      //签名信息,不包括 magic\checksum和自己
        u4  fileSize;       //整个文件的长度,单位为字节,包括所有的内容
        u4  headerSize;     //默认是0x70个字节
        u4  endianTag;      //大小端标签，标准.dex文件为小端，此项一般固定为0x12345678常量
        u4  linkSize;       //链接数据的大小
        u4  linkOff;        //链接数据的偏移值
        u4  mapOff;         //map item的偏移地址，该item属于data区里的内容，值要大于等于dataOff的大小
        u4  stringIdsSize;      //DEX中用到的所有字符串内容的大小*
        u4  stringIdsOff;       //DEX中用到的所有字符串内容的偏移量
        u4  typeIdsSize;        //DEX中类型数据结构的大小
        u4  typeIdsOff;         //DEX中类型数据结构的偏移值
        u4  protoIdsSize;       //DEX中的元数据信息数据结构的大小
        u4  protoIdsOff;        //DEX中的元数据信息数据结构的偏移值
        u4  fieldIdsSize;       //DEX中字段信息数据结构的大小
        u4  fieldIdsOff;        //DEX中字段信息数据结构的偏移值
        u4  methodIdsSize;      //DEX中方法信息数据结构的大小
        u4  methodIdsOff;       //DEX中方法信息数据结构的偏移值
        u4  classDefsSize;      //DEX中的类信息数据结构的大小
        u4  classDefsOff;       //DEX中的类信息数据结构的偏移值
        u4  dataSize;           //DEX中数据区域的结构信息的大小
        u4  dataOff;            //DEX中数据区域的结构信息的偏移值
        """
        self.header_data = {
            'magic': self.data[0:8],  # Dex 版本标识,8个字节
            'checksum': unpack('<L', self.data[8:0xC])[0],  # 校验和，占4个字节
            'signature': self.data[0xC:0x20],  # SHA-1 散列值 20个字节 0x14
            'file_size': unpack('<L', self.data[0x20:0x24])[0],  # 总文件大小。占4个字节
            'header_size': unpack('<L', self.data[0x24:0x28])[0],  # DexHeader大小，占4个字节，目前恒为0x70,112个字节
            'endian_tag': unpack('<L', self.data[0x28:0x2C])[0],  # 字节序标记，占4个字节，目前值为 0x12345678,表示小端存储
            'link_size': unpack('<L', self.data[0x2C:0x30])[0],  # 链接段个数，占4个字节
            'link_off': unpack('<L', self.data[0x30:0x34])[0],  # 链接段起始偏移，占4个字节
            'map_off': unpack('<L', self.data[0x34:0x38])[0],  # DexMapList起始偏移，占4个字节
            'string_ids_size': unpack('<L', self.data[0x38:0x3C])[0],  # DexStringId 个数，占4个字节
            'string_ids_off': unpack('<L', self.data[0x3C:0x40])[0],  # DexStringId 起始偏移
            'type_ids_size': unpack('<L', self.data[0x40:0x44])[0],  # DexTypeId 个数
            'type_ids_off': unpack('<L', self.data[0x44:0x48])[0],  # DexTypeId 起始偏移
            'proto_ids_size': unpack('<L', self.data[0x48:0x4C])[0],  # DexProtoId 个数
            'proto_ids_off': unpack('<L', self.data[0x4C:0x50])[0],  # DexProtoId 起始偏移
            'field_ids_size': unpack('<L', self.data[0x50:0x54])[0],  # DexFieldId 个数
            'field_ids_off': unpack('<L', self.data[0x54:0x58])[0],  # DexFieldId 起始偏移
            'method_ids_size': unpack('<L', self.data[0x58:0x5C])[0],  # DexMethodId 个数
            'method_ids_off': unpack('<L', self.data[0x5C:0x60])[0],  # DexMethodId 起始偏移
            'class_defs_size': unpack('<L', self.data[0x60:0x64])[0],  # DexClassDef 个数
            'class_defs_off': unpack('<L', self.data[0x64:0x68])[0],  # DexClassDef 起始偏移
            'data_size': unpack('<L', self.data[0x68:0x6C])[0],  # 数据段大小
            'data_off': unpack('<L', self.data[0x6C:0x70])[0]  # 数据段起始偏移
        }

    # 返回 DexHeader
    @property
    def header(self):
        return self.header_data

    # 返回magic
    @property
    def magic(self):
        return self.header_data['magic']
    # 返回校验和
    @property
    def checksum(self):
        return hex(self.header_data['checksum'])

    # 返回SHA校验
    @property
    def signature(self):
        return self.header_data['signature']

    # 返回文件的总大小
    @property
    def file_size(self):
        return self.header_data['file_size']

    # 返回文件头大小
    @property
    def header_size(self):
        return self.header_data['header_size']

    # 返回字节序
    @property
    def endian_tag(self):
        return hex(self.header_data['endian_tag'])

    # 返回链接段大小以及偏移
    @property
    def link(self):
        return self.header_data['link_size'], hex(self.header_data['link_off'])

    # 对DexStringID的解析
    # DexStringId -> StringDataOff -> StringData:{size , data}
    def get_strings(self):
        strings = []
        strings_ids_size = self.header_data['string_ids_size']
        strings_ids_off = self.header_data['string_ids_off']  # 起始偏移
        for index in range(strings_ids_size):
            # 每一个字符串的起始偏移，从strings_id_off 开始，有连续strings_id_size个字符串的起始地址，大小为 u4
            offset = unpack('<L', self.data[strings_ids_off + (index * 4):strings_ids_off + (index * 4) + 4])[0]
            # 每个StringData是由MUTF-8编码，第一个字节表示字符串长度n，后面跟着n个字符 + "00"作为字符串的结尾
            c_size = self.data[offset]
            c_char = self.data[offset + 1:offset + 1 + c_size]
            strings.append(c_char)
        return strings_ids_size, hex(strings_ids_off), strings

    # 对DexTypeId 的解析
    # DexTypeId -> DescriptorIdx:存储了DexType在DexStringId种的索引
    def get_types(self):
        type_ids = []
        type_ids_size = self.header_data['type_ids_size']
        type_ids_off = self.header_data['type_ids_off']
        for index in range(type_ids_size):
            types_idx = unpack('<L', self.data[type_ids_off + (index * 4):type_ids_off + (index * 4) + 4])[0]
            type_ids.append(types_idx)
        return type_ids_size, hex(type_ids_off), type_ids

    # 对DexProtoId的解析
    # DexProtoId -> {shortyIdx, returnTypeIDx, parametersOff -> {size, DexTypeItem -> type_idx} }
    def get_proto_ids(self):
        proto_ids = []
        proto_ids_size = self.header_data['proto_ids_size']
        proto_ids_off = self.header_data['proto_ids_off']
        for index in range(proto_ids_size):
            # 每一个DexProtoId 大小都是12字节
            # 指向DexStringId列表索引
            shorty_idx = unpack('<L', self.data[proto_ids_off + (index * 12):proto_ids_off + (index * 12) + 4])[0]
            # 指向DexTypeId列表索引
            return_type_id = unpack('<L', self.data[proto_ids_off + 4 + (index * 12):proto_ids_off + 8 + (index * 12)])[
                0]
            # 指向DexTypeList的偏移量
            parameters_off = unpack('<L', self.data[proto_ids_off + 8 + (index * 12):proto_ids_off + 12 + (index * 12)])[0]
            type_ids = []
            dex_type_size = 0
            if parameters_off != 0:
                # parameters_off指向 DexTypeList结构
                # 前四个字节是DexTypeItem结构的个数
                dex_type_size = unpack('<L', self.data[parameters_off:parameters_off + 4])[0]
                # 后面有dex_type_size个DexTypeItem
                for i in range(dex_type_size):
                    type_idx = unpack('<H', self.data[parameters_off+4+(i*2):parameters_off+6+(i*2)])[0]
                    type_ids.append(type_idx)
            proto_ids.append({'shorty_idx': shorty_idx,
                              'return_type_id': return_type_id,
                              'parameters': {'parameters_off': hex(parameters_off),
                                             'dex_type_size': dex_type_size,
                                             'type_ids': type_ids
                                             }
                              })
        return proto_ids_size, hex(proto_ids_off), proto_ids

    # 对 DexFieldId的解析，字段
    # DexFieldId -> {classIdx, tyedIdx, nameIdx }
    def get_field_ids(self):
        field_ids = []
        field_ids_size = self.header_data['field_ids_size']
        field_ids_off = self.header_data['field_ids_off']

        for index in range(field_ids_size):
            # 类的类型，指向 DexTypeId 列表的索引
            class_idx = unpack('<H', self.data[field_ids_off + (index * 8):field_ids_off + (index * 8) + 2])[0]
            # 字段类型，指向 DexTypeId 列表的索引
            type_idx = unpack('<H', self.data[field_ids_off + (index * 8) + 2:field_ids_off + (index * 8) + 4])[0]
            # 字段名，指向 DexString 列表的索引
            name_idx = unpack('<L', self.data[field_ids_off + (index * 8) + 4:field_ids_off + (index * 8) + 8])[0]
            field_ids.append({'class_idx': class_idx, 'type_idx': type_idx, 'name_idx': name_idx})
        return field_ids_size, hex(field_ids_off), field_ids

    # 对 DexMethodId的解析
    # DexMethodIId -> {classIdx, protoIdx, nameIdx}
    def get_method_ids(self):
        methods = []
        method_ids_size = self.header_data['method_ids_size']
        method_ids_off = self.header_data['method_ids_off']

        for index in range(method_ids_size):
            class_idx = unpack('<L', self.data[method_ids_off+(index*12):method_ids_off+(index*12)+4])[0]
            proto_idx = unpack('<L', self.data[method_ids_off+(index*12)+4:method_ids_off+(index*12)+8])[0]
            name_idx = unpack('<L', self.data[method_ids_off+(index*12)+8:method_ids_off+(index*12)+12])[0]
            methods.append({'class_idx': class_idx, 'proto_idx': proto_idx, 'name_idx': name_idx})
        return method_ids_size, hex(method_ids_off), methods

    # 对 DexClassDef的解析

    def get_class_defs(self):
        class_defs = []
        class_defs_size = self.header_data['class_defs_size']
        class_defs_off = self.header_data['class_defs_off']
        for index in range(class_defs_size):
            class_idx = unpack('<L',self.data[class_defs_off+(index*32):class_defs_off+(index*32)+4])[0]
            access_flags = unpack('<L',self.data[class_defs_off+(index*32)+4:class_defs_off+(index*32)+8])[0]
            superclass_idx = unpack('<L',self.data[class_defs_off+(index*32)+8:class_defs_off+(index*32)+12])[0]
            interfaces_off = unpack('<L',self.data[class_defs_off+(index*32)+12:class_defs_off+(index*32)+16])[0]
            source_file_idx = unpack('<L',self.data[class_defs_off+(index*32)+16:class_defs_off+(index*32)+20])[0]
            annotations_off = unpack('<L',self.data[class_defs_off+(index*32)+20:class_defs_off+(index*32)+24])[0]
            class_data_off = unpack('<L',self.data[class_defs_off+(index*32)+24:class_defs_off+(index*32)+28])[0]
            static_values_off = unpack('<L',self.data[class_defs_off+(index*32)+28:class_defs_off+(index*32)+32])[0]
            class_defs.append({
                'class_idx': class_idx,
                'access': access_flags,
                'superclass_idx': superclass_idx,
                'interfaces_off': hex(interfaces_off),
                'source_file_idx': source_file_idx,
                'annotation_off': hex(annotations_off),
                'class_data_off': hex(class_data_off),
                'static_values_off': hex(static_values_off)
            })
        return class_defs_size,hex(class_defs_off), class_defs


if __name__ == '__main__':
    dex_parse = DexParser('Hello.dex')
    # print("DEXHeader为: {}".format(dex_parse.header))
    print("DEX版本标识为: {}".format(dex_parse.magic))
    print("DEX adler32校验为: {}".format(dex_parse.checksum))
    print("SHA1 校验为: {}".format(dex_parse.signature))
    print("总文件大小为: {}".format(dex_parse.file_size))
    print("DexHeader 大小为: {}".format(dex_parse.header_size))
    print("字节序为: {}".format(dex_parse.endian_tag))
    print("链接段大小为: {0}\t起始偏移为: {1}".format(dex_parse.link[0], dex_parse.link[1]))
    strings_ids_size, strings_ids_off, strings = dex_parse.get_strings()
    print("strings_id个数: {0} \t起始偏移: {1}\t 内容{2}".format(strings_ids_size, strings_ids_off, strings))
    type_ids_size, type_ids_off, type_ids = dex_parse.get_types()
    print("type_id个数: {0} \t 起始偏移: {1}\t 在strings_id中的索引: {2}".format(type_ids_size, type_ids_off, type_ids))
    proto_ids_size, proto_ids_off, proto_ids = dex_parse.get_proto_ids()
    print("proto_id个数为: {0}\t 起始偏移为: {1}\t内容为: {2}".format(proto_ids_size, proto_ids_off, proto_ids))
    field_ids_size, field_ids_off, field_ids = dex_parse.get_field_ids()
    print("Field_id个数为: {0}\t 起始偏移为: {1}\t 索引字段为: {2}".format(field_ids_size, field_ids_off, field_ids))
    method_ids_size, method_ids_off, methods = dex_parse.get_method_ids()
    print("Method 个数为{0}\t 起始偏移为:{1}\t 索引字段为: {2}".format(method_ids_size, method_ids_off, methods))
    class_defs_size, class_defs_off, class_defs = dex_parse.get_class_defs()
    print("class_def_id个数为: {0}\t 起始偏移为: {1}\t内容为:{2} ".format(class_defs_size, class_defs_off, class_defs))
