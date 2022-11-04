package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32 // 未使用
	TimeDateStamp         uint32 // 时间戳
	MajorVersion          uint16 // 未使用
	MinorVersion          uint16 // 未使用
	Name                  uint32 // 指向该导出表文件名字符串
	Base                  uint32 // 导出函数起始序号
	NumberOfFunctions     uint32 // 所有导出函数的个数
	NumberOfNames         uint32 // 以函数名字导出的函数个数
	AddressOfFunctions    uint32 // 导出函数地址表RVA
	AddressOfNames        uint32 // 导出函数名称表RVA
	AddressOfNameOrdinals uint32 // 导出函数序号表RVA
}

type _IMAGE_BASE_RELOCATION struct {
	VirtualAddress uint32 //每一个低12位的值+VirtualAddress 才是 真正数据的RVA
	SizeOfBlock    uint32 //当前BASE大小
}

type IMAGE_DOS_HEADER struct {
	E_magic    uint16     //[长度:02h] [Magic number.][DOS可执行文件标记"MZ"头,定义为"5A4Dh",定值.]
	E_cblp     uint16     //[长度:02h] [Bytes on last page of file.]
	E_cp       uint16     //[长度:02h] [Pages in file.]
	E_crlc     uint16     //[长度:02h] [Relocations.]
	E_cparhdr  uint16     //[长度:02h] [Size of header in paragraphs.]
	E_minalloc uint16     //[长度:02h] [Minimum extra paragraphs needed.]
	E_maxalloc uint16     //[长度:02h] [Maximum extra paragraphs needed.]
	E_ss       uint16     //[长度:02h] [Initial (relative) SS value.]
	E_sp       uint16     //[长度:02h] [Initial SP value.]
	E_csum     uint16     //[长度:02h] [Checksum.]
	E_ip       uint16     //[长度:02h] [Initial IP value.][DOS代码入口IP.]
	E_cs       uint16     //[长度:02h] [Initial (relative) CS value.][DOS代码的入口CS.]
	E_lfarlc   uint16     //[长度:02h] [File address of relocation table.]
	E_ovno     uint16     //[长度:02h] [Overlay number.]
	E_res      [4]uint16  //[长度:08h] [Reserved words.]
	E_oemid    uint16     //[长度:02h] [OEM identifier (for E_oeminfo).]
	E_oeminfo  uint16     //[长度:02h] [OEM information; E_oemid specific.]
	E_res2     [10]uint16 //[长度:14h] [Reserved words.] [长度为"20".]
	E_lfanew   uint32     //[长度:04h] [偏移量:0x3C] [File address of new exe header.][PE文件头地址.]
}
type IMAGE_NT_HEADERS32 struct {
	Signature      uint32                  //[长度:04h] [PE文件标志("PE",0,0),长度为"4".]
	FileHeader     IMAGE_FILE_HEADER       //[长度:14h] [IMAGE_FILE_HEADER结构,长度为"20".]
	OptionalHeader IMAGE_OPTIONAL_HEADER32 //[长度:e0h] [IMAGE_OPTIONAL_HEADER32结构,默认长度为"e0h"(224).]

}

type IMAGE_FILE_HEADER struct {
	Machine              uint16 //[长度:02h] [偏移量:E_lfanew+0x04] [Intel 386.] [运行平台(可执行文件的CPU类型,常值为:"014Ch").]
	NumberOfSections     uint16 //[长度:02h] [偏移量:E_lfanew+0x06] [区段/节/块(Section)的数目.]
	TimeDateStamp        uint32 //[长度:04h] [偏移量:E_lfanew+0x08] [文件创建时的时间戳(日历时间为:2004.11.15 23:16:32).]
	PointerOfSymbolTable uint32 //[长度:04h] [偏移量:E_lfanew+0x0C] [COFF符号指针,指向符号表(用于调试).]
	NumberOfSymbols      uint32 //[长度:04h] [偏移量:E_lfanew+0x10] [符号表(即上一字段)中的符号个数(用于调试).]
	SizeOfOptionalHeader uint16 //[长度:02h] [偏移量:E_lfanew+0x14] [可选首部长度(可选头大小).在OBJ中,该字段为0;在可执行文件中,是指IMAGE_OPTIONAL_HEADER结构的长度.]
	Characteristics      uint16 //[长度:02h] [偏移量:E_lfanew+0x16] [特征值:100h 1h 2h 4h 8h] [文件属性/特性(文件信息标志).]
}

type IMAGE_OPTIONAL_HEADER32 struct {
	Magic                       uint16                   //[长度:02h] [偏移量:E_lfanew+0x18] [标志字(幻数),常值为"010Bh".用来说明文件是ROM映像,还是普通可执行的映像.]
	MajorLinkerVersion          uint8                    //[长度:01h] [偏移量:E_lfanew+0x1A] [链接器主(首)版本号.]
	MinorLinkerVersion          uint8                    //[长度:01h] [偏移量:E_lfanew+0x1B] [链接器次(副)版本号.]
	SizeOfCode                  uint32                   //[长度:04h] [偏移量:E_lfanew+0x1C] [代码段(块)大小,所有Code Section总共的大小(只入不舍),这个值是向上对齐某一个值的整数倍.]
	SizeOfInitializedData       uint32                   //[长度:04h] [偏移量:E_lfanew+0x20] [已初始化数据块大小.即在编译时所构成的块的大小(不包括代码段),但这个数据并不太准确.]
	SizeOfUninitializedData     uint32                   //[长度:04h] [偏移量:E_lfanew+0x24] [未初始化数据块大小.装载程序要在虚拟地址空间中为这些数据约定空间.未初始化数据通常在.bbs块中.]
	AddressOfEntryPoint         uint32                   //[长度:04h] [偏移量:E_lfanew+0x28] [程序开始执行的入口地址/入口点EP(RVA).这是一个"相对虚拟地址".]
	BaseOfCode                  uint32                   //[长度:04h] [偏移量:E_lfanew+0x2C] [代码段(块)起始地址.]
	BaseOfData                  uint32                   //[长度:04h] [偏移量:E_lfanew+0x30] [数据段(块)起始地址.]
	ImageBase                   uint32                   //[长度:04h] [偏移量:E_lfanew+0x34] [基址,程序默认装入的基地址.]
	SectionAlignment            uint32                   //[长度:04h] [偏移量:E_lfanew+0x38] [内存中的节(块"Section")的对齐值,常为:0x1000或0x04.]
	FileAlignment               uint32                   //[长度:04h] [偏移量:E_lfanew+0x3C] [文件中的节(块"Section")的对齐值,常为:0x1000或0x200或0x04.]
	MajorOperatingSystemVersion uint16                   //[长度:02h] [偏移量:E_lfanew+0x40] [操作系统主(首)版本号.]
	MinorOperatingSystemVersion uint16                   //[长度:02h] [偏移量:E_lfanew+0x42] [操作系统次(副)版本号.]
	MajorImageVersion           uint16                   //[长度:02h] [偏移量:E_lfanew+0x44] [该可执行文件的主(首)版本号,由程序员自定义.]
	MinorImageVersion           uint16                   //[长度:02h] [偏移量:E_lfanew+0x46] [该可执行文件的次(副)版本号,由程序员自定义.]
	MajorSubsystemVersion       uint16                   //[长度:02h] [偏移量:E_lfanew+0x48] [所需子系统主(首)版本号.]
	MinorSubsystemVersion       uint16                   //[长度:02h] [偏移量:E_lfanew+0x4A] [所需子系统次(副)版本号.]
	Win32VersionValue           uint32                   //[长度:04h] [偏移量:E_lfanew+0x4C] [保留.总是"00000000".]
	SizeOfImage                 uint32                   //[长度:04h] [偏移量:E_lfanew+0x50] [映像大小(映像装入内存后的总尺寸/内存中整个PE映像的尺寸).]
	SizeOfHeaders               uint32                   //[长度:04h] [偏移量:E_lfanew+0x54] [首部及块表(首部+块表)的大小.]
	CheckSum                    uint32                   //[长度:04h] [偏移量:E_lfanew+0x58] [CRC校验和.]
	Subsystem                   uint16                   //[长度:02h] [偏移量:E_lfanew+0x5C] [子系统:Windows 图形用户界面/图形接口子系统(Image runs in the Windows GUI subsystem.).]
	DllCharacteristics          uint16                   //[长度:02h] [偏移量:E_lfanew+0x5E] [DLLMain()函数何时被调用.当文件为DLL程序时使用,默认值为"0".]
	SizeOfStackReserve          uint32                   //[长度:04h] [偏移量:E_lfanew+0x60] [初始化时为线程保留的栈大小.]
	SizeOfStackCommit           uint32                   //[长度:04h] [偏移量:E_lfanew+0x64] [初始化时线程实际使用的栈大小.这个值总比"SizeOfStackReserve"要小一些.]
	SizeOfHeapReserve           uint32                   //[长度:04h] [偏移量:E_lfanew+0x68] [初始化时为进程保留的堆大小.]
	SizeOfHeapCommit            uint32                   //[长度:04h] [偏移量:E_lfanew+0x6C] [初始化时进程实际使用的堆大小.这个值总比"SizeOfHeapReserve"要小一些.]
	LoaderFlags                 uint32                   //[长度:04h] [偏移量:E_lfanew+0x70] [设置自动调用断点或调试器.与调试有关,默认值为"0".]
	NumberOfRvaAndSizes         uint32                   //[长度:04h] [偏移量:E_lfanew+0x74] [数据目录结构的数量(项数).值总为"00000010h"(16项).]
	DataDirectory               [16]IMAGE_DATA_DIRECTORY //[长度:80h] [数据目录表(16项,每个成员占8字节).]
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_SECTION_HEADER struct {
	Name                 uint64 //[长度:08h] [名称,长度:8位(16字节)的ASCII码.]
	VirtualSize          uint32 //[长度:04h] [V(VS),内存中大小(对齐前的长度).]
	VirtualAddress       uint32 //[长度:04h] [V(VO),内存中偏移(该块的RVA).]
	SizeOfRawData        uint32 //[长度:04h] [R(RS),文件中大小(对齐后的长度).]
	PointerToRawData     uint32 //[长度:04h] [R(RO),文件中偏移.]
	PointerToRelocation  uint32 //[长度:04h] [在OBJ文件中使用,重定位的偏移.]
	PointerToLinenumbers uint32 //[长度:04h] [行号表的偏移,提供调试.]
	NumberOfRelocations  uint16 //[长度:02h] [在OBJ文件中使用,重定位项数目.]
	NumberOfLinenumbers  uint16 //[长度:02h] [行号表中行号的数目.]
	Characteristics      uint32 //[长度:04h] [标志(块属性):20000000h 40000000h 00000020h ]
}

type PortableExecutable struct {
	DOS     IMAGE_DOS_HEADER
	Rubbish []byte
	NT      IMAGE_NT_HEADERS32
	SECTION []IMAGE_SECTION_HEADER
	Source  []byte
}

func (pe *PortableExecutable) ReadAt(bs []byte, off int64) {
	SByte, err := pe.GetByte()
	if err != nil {
		panic(err)
	}
	for i, _ := range bs {
		if off+int64(i) >= int64(len(SByte)) {
			break
		}
		bs[i] = SByte[off+int64(i)]
	}
}
func (pe *PortableExecutable) WriteAt(bs []byte, off int64) {
	SByte, err := pe.GetByte()
	if err != nil {
		panic(err)
	}
	for i, v := range bs {
		if off+int64(i) >= int64(len(SByte)) {
			break
		}
		SByte[off+int64(i)] = v
	}
}
func (pe *PortableExecutable) update(f *os.File) {
	pe.readDOS(f)
	pe.readNT(f)
	pe.readSection(f)
}

//解析PE并返回pe对象
func (pe *PortableExecutable) NEW(f *os.File) {
	pe.readDOS(f)
	pe.readNT(f)
	pe.readSection(f)

	//剩下的写入Source
	se := pe.SECTION[len(pe.SECTION)-1]
	size := se.PointerToRawData + se.SizeOfRawData
	peSize := pe.DOS.E_lfanew + uint32(24) + uint32(pe.NT.FileHeader.SizeOfOptionalHeader) + (uint32(pe.NT.FileHeader.NumberOfSections) * uint32(40))
	newMemory := make([]byte, size-peSize)
	f.ReadAt(newMemory, int64(peSize))
	pe.Source = newMemory
}

//读取DOS头
func (pe *PortableExecutable) readDOS(f *os.File) IMAGE_DOS_HEADER {
	var dos IMAGE_DOS_HEADER
	dosHeader := make([]byte, 64)
	//读取64个字节
	_, err := f.ReadAt(dosHeader, 0)
	if err != nil {
		panic(err)
	}
	ByteToStruct(dosHeader, &dos)
	pe.DOS = dos
	//读取DOS后面的垃圾信息
	rubbishHeader := make([]byte, dos.E_lfanew-64)
	_, err = f.ReadAt(rubbishHeader, 64)
	if err != nil {
		panic(err)
	}
	pe.Rubbish = rubbishHeader

	return dos
}

//读取NT头
func (pe *PortableExecutable) readNT(f *os.File) IMAGE_NT_HEADERS32 {
	var nt IMAGE_NT_HEADERS32
	var SizeOfOptional int16
	//获取可选PE头长度
	SizeOfOptionalHeader := make([]byte, 2)
	_, err := f.ReadAt(SizeOfOptionalHeader, int64(pe.DOS.E_lfanew)+20)
	if err != nil {
		panic(err)
	}
	SizeOfOptionalReader := bytes.NewReader(SizeOfOptionalHeader)
	binary.Read(SizeOfOptionalReader, binary.LittleEndian, &SizeOfOptional)
	//读取NT部分
	ntHeader := make([]byte, 4+20+SizeOfOptional)
	_, err = f.ReadAt(ntHeader, int64(pe.DOS.E_lfanew))
	if err != nil {
		panic(err)
	}
	ByteToStruct(ntHeader, &nt)
	pe.NT = nt
	return nt
}

//读取节表
func (pe *PortableExecutable) readSection(f *os.File) []IMAGE_SECTION_HEADER {

	var sections []IMAGE_SECTION_HEADER
	//获取节表数量
	sectionNum := int(pe.NT.FileHeader.NumberOfSections)
	sectionsHeader := make([]byte, 40)
	sk := int(pe.DOS.E_lfanew) + binary.Size(pe.NT)

	for i := 0; i < sectionNum; i++ {

		var section IMAGE_SECTION_HEADER
		_, err := f.ReadAt(sectionsHeader, int64(sk+(40*i)))
		if err != nil {
			panic(err)
		}
		ByteToStruct(sectionsHeader, &section)
		sections = append(sections, section)
	}

	pe.SECTION = sections
	return sections

}

//内存偏移转文件偏移
func (pe *PortableExecutable) RVAtoFOA(RVA uint32) int64 {
	if uint64(RVA) < uint64(binary.Size(pe.SECTION[0].VirtualAddress)) {
		return int64(RVA)
	}
	//通过循环判断是在哪个节区
	for _, v := range pe.SECTION {
		//偏移是否大于第n个节表VirtualAddress并且,偏移是否小于第n+1个节表VirtualAddress+misc.VirtualSize，不是就n+1继续循环
		if RVA >= v.VirtualAddress && RVA < v.VirtualAddress+v.SizeOfRawData {
			//获取距离节区起始地址的偏移：偏移-当前节表VirtualAddress+当前节表PointerToRawData
			return int64((RVA - v.VirtualAddress) + v.PointerToRawData)
		}
	}
	return 0
}

//文件偏移转内存偏移
func (pe *PortableExecutable) FOAtoRVA(FOA uint32) int64 {
	if uint64(FOA) < uint64(binary.Size(pe.SECTION[0].PointerToRawData)) {
		return int64(FOA)
	}
	//通过循环判断是在哪个节区
	for _, v := range pe.SECTION {
		//PointerToRawData,偏移是否小于第n个节表PointerToRawData+SizeOfRawData，不是就n+1继续循环
		if FOA >= v.PointerToRawData && FOA < v.PointerToRawData+v.SizeOfRawData {
			//获取距离节区起始地址的偏移：偏移-当前节表PointerToRawData+当前节表VirtualAddress
			return int64((FOA - v.PointerToRawData) + v.VirtualAddress)
		}
	}
	return 0
}

//byte转结构体
func ByteToStruct(be []byte, obj any) {
	//转为io.Reader类型
	reader := bytes.NewReader(be)
	//[]byte转section结构体
	err := binary.Read(reader, binary.LittleEndian, obj)
	if err != nil {
		panic(err)
	}
}

//byte转结构体
func StructToByte(obj any) ([]byte, error) {
	sourceBuf := new(bytes.Buffer)
	if err := binary.Write(sourceBuf, binary.BigEndian, obj); err != nil {
		return nil, err
	}
	return sourceBuf.Bytes(), nil

}

//PE转byte
func (pe *PortableExecutable) GetByte() ([]byte, error) {
	dosBuf := new(bytes.Buffer)
	if err := binary.Write(dosBuf, binary.LittleEndian, pe.DOS); err != nil {
		return nil, err
	}

	rubbishBuf := new(bytes.Buffer)
	if err := binary.Write(rubbishBuf, binary.LittleEndian, pe.Rubbish); err != nil {
		return nil, err
	}

	NTBuf := new(bytes.Buffer)
	if err := binary.Write(NTBuf, binary.LittleEndian, pe.NT); err != nil {
		return nil, err
	}

	SECTIONBuf := new(bytes.Buffer)
	if err := binary.Write(SECTIONBuf, binary.LittleEndian, pe.SECTION); err != nil {
		return nil, err
	}

	sourceBuf := new(bytes.Buffer)
	if err := binary.Write(sourceBuf, binary.LittleEndian, pe.Source); err != nil {
		return nil, err
	}

	result := make([]byte, dosBuf.Len()+rubbishBuf.Len()+NTBuf.Len()+SECTIONBuf.Len()+sourceBuf.Len())

	copy(result, dosBuf.Bytes())
	copy(result[dosBuf.Len():], rubbishBuf.Bytes())
	copy(result[dosBuf.Len()+rubbishBuf.Len():], NTBuf.Bytes())
	copy(result[dosBuf.Len()+rubbishBuf.Len()+NTBuf.Len():], SECTIONBuf.Bytes())
	copy(result[dosBuf.Len()+rubbishBuf.Len()+NTBuf.Len()+SECTIONBuf.Len():], sourceBuf.Bytes())
	return result, nil
}

//读取导出表
func (pe *PortableExecutable) readExportTable() {
	rva := pe.NT.OptionalHeader.DataDirectory[0].VirtualAddress
	if rva == 0 {
		return
	}
	foa := pe.RVAtoFOA(rva)
	mk := make([]byte, 64)
	pe.ReadAt(mk, foa)
	var ex IMAGE_EXPORT_DIRECTORY
	ByteToStruct(mk, &ex)

	fmt.Printf("rva:%x\n", rva)
	fmt.Printf("foa:%x\n", foa)
	fmt.Printf("ex:%x\n", ex)

	//函数地址内存空间
	addressOfFunctions := make([]byte, ex.NumberOfFunctions*4)
	//函数名内存空间
	AddressOfNames := make([]byte, ex.NumberOfNames*4)
	//函数序号内存空间
	AddressOfNameOrdinals := make([]byte, ex.NumberOfFunctions*2)

	//函数地址表
	afFOA := pe.RVAtoFOA(ex.AddressOfFunctions)
	pe.ReadAt(addressOfFunctions, afFOA)
	fmt.Printf("函数地址表:%x\n", addressOfFunctions)

	//函数名表
	anFOA := pe.RVAtoFOA(ex.AddressOfNames)
	pe.ReadAt(AddressOfNames, anFOA)
	fmt.Printf("函数名表:%x\n", AddressOfNames)

	//函数序号表
	aoFOA := pe.RVAtoFOA(ex.AddressOfNameOrdinals)
	pe.ReadAt(AddressOfNameOrdinals, aoFOA)
	fmt.Printf("函数序号表:%x\n", AddressOfNameOrdinals)

}

//读取重定向表
func (pe PortableExecutable) readRelocation() {
	rva := pe.NT.OptionalHeader.DataDirectory[5].VirtualAddress
	foa := pe.RVAtoFOA(rva)
	if rva == 0 {
		return
	}
	for {
		//BASE内存空间
		mk := make([]byte, 8)
		pe.ReadAt(mk, foa)
		var ba _IMAGE_BASE_RELOCATION
		ByteToStruct(mk, &ba)
		if ba.VirtualAddress+ba.SizeOfBlock == 0 {
			fmt.Println("重定向表结束")
			break
		}
		fmt.Printf("%x\n", ba)
		//具体项内存空间
		baseSize := make([]byte, ba.SizeOfBlock-8)
		pe.ReadAt(baseSize, foa+8)
		fmt.Printf("%x\n", baseSize)
		foa += int64(ba.SizeOfBlock)
	}
}

//插入新节表+区段
func (pe *PortableExecutable) addSection(newSize int) bool {
	//内存对齐
	y := newSize % int(pe.NT.OptionalHeader.SectionAlignment)
	if y != 0 {
		newSize = newSize + (int(pe.NT.OptionalHeader.SectionAlignment) - y)
	}
	is := true
	sesize := 80
	//判断空间是否还够加入两给节表的大小
	//SizeOfHeader - (DOS + 垃圾数据 + PE标记 + 标准PE头 + 可选PE头 + 已存在节表) >= 2个节表的大小
	peSize := pe.DOS.E_lfanew + uint32(24) + uint32(pe.NT.FileHeader.SizeOfOptionalHeader) + (uint32(pe.NT.FileHeader.NumberOfSections) * uint32(40))
	if pe.NT.OptionalHeader.SizeOfHeaders-peSize >= uint32(80) {
		fmt.Println("该文件可以添加节表")
		is = true
		newSectionTest := make([]byte, sesize)
		pe.ReadAt(newSectionTest, int64(peSize))
		for _, v := range newSectionTest {
			if v != 0 {
				fmt.Printf("节表位置有非0数据\n")
				is = false
			}
		}

	} else {
		fmt.Printf("剩余空间不足，节表结束地址:%x，节表对齐后地址：%x\n", peSize, pe.NT.OptionalHeader.SizeOfHeaders)
		is = false

	}
	rsize := pe.DOS.E_lfanew - 64
	if !is && (rsize > 80 || rsize+(pe.NT.OptionalHeader.SizeOfHeaders-peSize) > 80) {
		fmt.Printf("DOS后的垃圾数据区空间足够\n")
		peSize -= rsize
		pe.Rubbish = nil
		pe.DOS.E_lfanew = pe.DOS.E_lfanew - rsize
		newSource := make([]byte, binary.Size(pe.Source)+int(rsize))
		copy(newSource[rsize:], pe.Source)
		pe.Source = newSource
		newSectionTest := make([]byte, sesize)
		pe.ReadAt(newSectionTest, int64(peSize))
		is = true
		for _, v := range newSectionTest {
			if v != 0 {
				fmt.Printf("节表位置有非0数据\n")
				is = false
			}
		}
		if !is {
			fmt.Printf("DOS后的垃圾数据区空间也不够，垃圾数据区size:%x\n", rsize)
			if rsize > 40 {
				fmt.Printf("尝试不安全的添加方式\n")
				sesize = 40
				is = true
			} else {
				return false
			}
		}
	} else if !is {
		fmt.Printf("DOS后的垃圾数据区空间也不够，垃圾数据区size:%x\n", rsize)
		if rsize > 40 {
			fmt.Printf("尝试不安全的添加方式\n")
			peSize -= rsize
			sesize = 40
			pe.Rubbish = nil
			pe.DOS.E_lfanew = pe.DOS.E_lfanew - rsize
			newSource := make([]byte, binary.Size(pe.Source)+int(rsize))
			copy(newSource[rsize:], pe.Source)
			pe.Source = newSource
		} else {
			return false
		}
	}

	getByte, _ := pe.GetByte()
	fmt.Printf("添加前size:%x\n", binary.Size(getByte))

	//复制一份代码节表
	newSection := make([]byte, 40)
	pe.ReadAt(newSection, int64(peSize-uint32((40*pe.NT.FileHeader.NumberOfSections))))
	for i, v := range []byte{112, 101, 95, 116, 111, 111, 115} {
		newSection[i] = v
	}
	var se IMAGE_SECTION_HEADER
	ByteToStruct(newSection, &se)
	//VirtualSize	填写节区没有对齐前的大小，可以不准
	se.VirtualSize = uint32(newSize)
	//VirtualAddress 前面一个节表的VirtualAddress +(VirtualSize或SizeOfRawData 谁大就谁)  内存对齐
	SE := pe.SECTION[len(pe.SECTION)-1]
	if SE.VirtualSize > SE.SizeOfRawData {
		//内存对齐
		y = int(SE.VirtualSize) % int(pe.NT.OptionalHeader.SectionAlignment)
		if y != 0 {
			virtualSize := SE.VirtualSize + uint32(int(pe.NT.OptionalHeader.SectionAlignment)-y)
			se.VirtualAddress = SE.VirtualAddress + virtualSize

		} else {
			se.VirtualAddress = SE.VirtualAddress + SE.VirtualSize
		}
	} else {
		//内存对齐
		y = int(SE.VirtualSize) % int(pe.NT.OptionalHeader.SectionAlignment)
		if y != 0 {
			sizeOfRawData := SE.VirtualSize + uint32(int(pe.NT.OptionalHeader.SectionAlignment)-y)
			se.VirtualAddress = SE.VirtualAddress + sizeOfRawData

		} else {
			se.VirtualAddress = SE.VirtualAddress + SE.SizeOfRawData
		}
	}
	//SizeOfRawData  	节区在文件中对齐后的尺寸
	se.SizeOfRawData = uint32(newSize)
	//PointerToRawData 前面一个节表的SizeOfRawData + PointerToRawData
	se.PointerToRawData = SE.SizeOfRawData + SE.PointerToRawData
	pe.SECTION = append(pe.SECTION, se)
	//写入节表
	pe.WriteAt(newSection, int64(peSize))
	//必修改项
	pe.NT.FileHeader.NumberOfSections = pe.NT.FileHeader.NumberOfSections + 1
	pe.NT.OptionalHeader.SizeOfImage = pe.NT.OptionalHeader.SizeOfImage + uint32(newSize)
	//开辟新内存，需要减去新增的节表空间
	newMemory := make([]byte, binary.Size(pe.Source)+newSize-40)
	//读取旧内存到新内存
	copy(newMemory, pe.Source[40:])
	pe.Source = newMemory

	getByt1e, _ := pe.GetByte()
	fmt.Printf("添加后size:%x\n", binary.Size(getByt1e))

	//替换PE内存
	return true

}

func IntToBytes(n int) []byte {
	data := int64(n)
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, data)
	return bytebuf.Bytes()
}

func IntToString(n int) string {
	data := uint64(n)
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, data)
	b2 := bytebuf.Bytes()
	a_len := len(b2)
	var byteo []byte
	for i := 0; i < a_len; i++ {
		if (i > 0 && b2[i-1] == b2[i]) || b2[i] == 0 {
			continue
		}
		byteo = append(byteo, b2[i])
	}
	return string(byteo)
}

func ByteToString(n []byte) string {
	a_len := len(n)
	var byteo []byte
	for i := 0; i < a_len; i++ {
		if (i > 0 && n[i-1] == n[i]) || n[i] == 0 {
			continue
		}
		byteo = append(byteo, n[i])
	}
	return string(byteo)
}
