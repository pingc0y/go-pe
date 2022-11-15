package main

import (
	"encoding/binary"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/flopp/go-findfont"
	"log"
	"os"
	"reflect"
	"strings"
	"time"
)

var (
	myApp fyne.App
	PE    *PortableExecutable
)

func init() {
	fontPaths := findfont.List()
	for _, fontPath := range fontPaths {
		//楷体:simkai.ttf
		//黑体:simhei.ttf
		if strings.Contains(fontPath, "simhei.ttf") {
			err := os.Setenv("FYNE_FONT", fontPath)
			if err != nil {
				return
			}
			break
		}
	}
}

var tab *fyne.Container

func main() {
	PE = &PortableExecutable{}

	defer func() {
		err := os.Unsetenv("FYNE_FONT")
		if err != nil {
			return
		}
	}()

	myApp = app.New()
	myWindow := myApp.NewWindow("GO_PE")

	show := showButton(myWindow)
	fun := funwButton(myWindow)

	//left := canvas.NewText("left", color.Black)
	//middle := canvas.NewText("content", color.Black)
	tab = container.NewVBox()
	content := container.NewBorder(show, nil, fun, nil, tab)
	myWindow.SetContent(content)

	myWindow.Resize(fyne.NewSize(400, 400))
	//居中显示
	myWindow.CenterOnScreen()
	myWindow.ShowAndRun()

}

func showtab() *fyne.Container {
	if PE.DOS.E_magic != 23117 {
		tab.Add(widget.NewLabel("是否PE文件: 否"))
	} else {
		tab.Add(widget.NewLabel("是否PE文件: 是"))
	}

	size := fmt.Sprintf("文件大小: %d字节", binary.Size(PE.Source))
	tab.Add(widget.NewLabel(size))

	t := time.Unix(int64(PE.NT.FileHeader.TimeDateStamp), 0)
	dateStr := t.Format("2006/01/02 15:04:05")
	//返回string
	ctime := fmt.Sprintf("创建时间: %s", dateStr)
	tab.Add(widget.NewLabel(ctime))

	if PE.NT.OptionalHeader.Magic == 267 {
		tab.Add(widget.NewLabel("运行平台: win32位"))
	} else {
		tab.Add(widget.NewLabel("运行平台: win64位"))
	}

	tab.Add(widget.NewLabel(fmt.Sprintf("程序入口EP(RVA): %#X", PE.NT.OptionalHeader.AddressOfEntryPoint)))

	tab.Add(widget.NewLabel(fmt.Sprintf("区段数量: %d", len(PE.SECTION))))

	return tab
}

//功能按钮
func funwButton(myWindow fyne.Window) *fyne.Container {
	addSection := widget.NewButton("新增区段", func() {
		if len(PE.Source) == 0 {
			dialog.ShowInformation("提示", "请先打开一个文件", myWindow)
			return
		}
		if PE.addSection(8000) {
			dialog.ShowInformation("提示", "添加成功", myWindow)
		} else {
			dialog.ShowInformation("提示", "添加失败", myWindow)
		}
	})
	save := widget.NewButton("保存", func() {
		if len(PE.Source) == 0 {
			dialog.ShowInformation("提示", "请先打开一个文件", myWindow)
			return
		}
		f, _ := os.Create("./pe_tools.exe") //创建文件
		defer f.Close()
		getByte, _ := PE.GetByte()
		_, err := f.Write(getByte) //写入文件(字节数组)
		if err != nil {
			panic(err)
		}
		f.Sync()
		dialog.ShowInformation("提示", "已保存到当前目录下", myWindow)
	})

	containe := container.NewVBox(addSection, save, layout.NewSpacer())
	return containe
}

//查看按钮
func showButton(myWindow fyne.Window) *fyne.Container {

	buttonOpen := widget.NewButton("打开文件", func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, myWindow)
				return
			}
			if reader == nil {
				log.Println("Cancelled")
				return
			}
			file, _ := os.Open(reader.URI().Path())
			PE.NEW(file)
			showtab()
		}, myWindow)

		//过滤类型 fd.SetFilter(storage.NewExtensionFileFilter([]string{".exe"}))
		fd.Resize(fyne.NewSize(500, 500))
		fd.Show()
	})

	buttonDOS := widget.NewButton("DOS头", func() {
		if len(PE.Source) == 0 {
			dialog.ShowInformation("提示", "请先打开一个文件", myWindow)
			return
		}
		dos(myApp)
	})
	buttonPE := widget.NewButton("标准PE头", func() {
		if len(PE.Source) == 0 {
			dialog.ShowInformation("提示", "请先打开一个文件", myWindow)
			return
		}
		filePE(myApp)
	})
	buttonOpPE := widget.NewButton("可选PE头", func() {
		if len(PE.Source) == 0 {
			dialog.ShowInformation("提示", "请先打开一个文件", myWindow)
			return
		}
		optionalHeader(myApp)
	})
	buttonDataDir := widget.NewButton("数据目录表", func() {
		if len(PE.Source) == 0 {
			dialog.ShowInformation("提示", "请先打开一个文件", myWindow)
			return
		}
		dataDirectory(myApp)
	})
	buttonSection := widget.NewButton("节表", func() {
		if len(PE.Source) == 0 {
			dialog.ShowInformation("提示", "请先打开一个文件", myWindow)
			return
		}
		section(myApp)
	})

	//创建功能行
	containe := container.New(layout.NewHBoxLayout(), buttonOpen, buttonDOS, buttonPE, buttonOpPE, buttonDataDir, buttonSection, layout.NewSpacer())
	return containe
}

func dos(myApp fyne.App) {
	//创建一个窗口并设置名称
	wDos := myApp.NewWindow("DOS")
	retH := reflect.TypeOf(PE.DOS)
	retV := reflect.ValueOf(PE.DOS)
	content := container.NewVBox()
	//获取结构体里的名称
	for i := 0; i < retH.NumField(); i++ {
		field := retH.Field(i)
		name := widget.NewLabel(strings.ToLower(field.Name))
		input := widget.NewEntry()
		value0 := fmt.Sprintf("%X", retV.Field(i).Interface())
		value := value0
		if intSize(retV.Field(i).Interface()) > len(value0) {
			value = strings.Repeat("0", intSize(retV.Field(i).Interface())-len(value0)) + value0
		}
		input.SetText(value)
		content.Add(container.New(layout.NewGridLayout(2), name, input))
	}
	save := widget.NewButton("保存", func() {
		log.Println("tapped home")
	})
	content.Add(save)
	//layout.NewGridWrapLayout(fyne.NewSize(80, 35))
	wDos.SetContent(content)

	wDos.Resize(fyne.NewSize(300, 500))

	wDos.CenterOnScreen()
	//显示该窗口
	wDos.Show()
}

func filePE(myApp fyne.App) {
	//创建一个窗口并设置名称
	wDos := myApp.NewWindow("FilePE")

	retH := reflect.TypeOf(PE.NT.FileHeader)
	retV := reflect.ValueOf(PE.NT.FileHeader)
	content := container.NewVBox()
	//获取结构体里的名称
	for i := 0; i < retH.NumField(); i++ {
		field := retH.Field(i)
		name := widget.NewLabel(field.Name)
		input := widget.NewEntry()
		value0 := fmt.Sprintf("%X", retV.Field(i).Interface())
		value := strings.Repeat("0", intSize(retV.Field(i).Interface())-len(value0)) + value0
		input.SetText(value)
		content.Add(container.New(layout.NewGridLayout(2), name, input))
	}
	save := widget.NewButton("保存", func() {
		log.Println("tapped home")
	})
	content.Add(save)
	//layout.NewGridWrapLayout(fyne.NewSize(80, 35))
	wDos.SetContent(content)

	wDos.Resize(fyne.NewSize(300, 300))

	wDos.CenterOnScreen()
	//显示该窗口
	wDos.Show()
}

func optionalHeader(myApp fyne.App) {
	//创建一个窗口并设置名称
	wDos := myApp.NewWindow("OptionalPE")

	retH := reflect.TypeOf(PE.NT.OptionalHeader)
	retV := reflect.ValueOf(PE.NT.OptionalHeader)
	content := container.NewVBox()
	//获取结构体里的名称
	for i := 0; i < retH.NumField(); i += 2 {
		field := retH.Field(i)
		name := widget.NewLabel(field.Name)
		input := widget.NewEntry()
		value0 := fmt.Sprintf("%X", retV.Field(i).Interface())
		value := value0
		if intSize(retV.Field(i).Interface()) > len(value0) {
			value = strings.Repeat("0", intSize(retV.Field(i).Interface())-len(value0)) + value0
		}
		input.SetText(value)
		if i+1 < retH.NumField() {
			field2 := retH.Field(i + 1)
			name2 := widget.NewLabel(field2.Name)
			input2 := widget.NewEntry()
			value20 := fmt.Sprintf("%X", retV.Field(i+1).Interface())
			value2 := value20
			if intSize(retV.Field(i+1).Interface()) > len(value20) {
				value2 = strings.Repeat("0", intSize(retV.Field(i+1).Interface())-len(value20)) + value20
			}
			input2.SetText(value2)
			content.Add(container.New(layout.NewGridLayout(5), name, input, layout.NewSpacer(), name2, input2))
		} else {
			content.Add(container.New(layout.NewGridLayout(5), name, input, layout.NewSpacer(), layout.NewSpacer(), layout.NewSpacer()))
		}
	}
	save := widget.NewButton("保存", func() {
		log.Println("tapped home")
	})
	content.Add(save)

	wDos.SetContent(content)

	wDos.Resize(fyne.NewSize(300, 500))

	wDos.CenterOnScreen()
	//显示该窗口
	wDos.Show()
}

//数据目录表
func dataDirectory(myApp fyne.App) {
	//创建一个窗口并设置名称
	wDos := myApp.NewWindow("数据目录表")

	datas := PE.NT.OptionalHeader.DataDirectory

	content := container.NewVBox()
	//获取结构体里的名称
	for i, v := range datas {
		var na string
		var show *widget.Button
		switch i {
		case 1:
			show = widget.NewButton("查看", func() {
				importTable(myApp)
			})
		case 11:
			show = widget.NewButton("查看", func() {
				bindImportTable(myApp)
			})

		default:
			show = widget.NewButton("查看", func() {

			})
		}

		switch i {
		case 0:
			na = "导出表"
			show.Disable()
		case 1:
			na = "导入表"
		case 2:
			na = "资源"
			show.Disable()
		case 3:
			na = "异常"
			show.Disable()
		case 4:
			na = "安全证书"
			show.Disable()
		case 5:
			na = "重定位表"
			show.Disable()
		case 6:
			na = "调试信息"
			show.Disable()
		case 7:
			na = "版权所有"
			show.Disable()
		case 8:
			na = "全局指针"
			show.Disable()
		case 9:
			na = "TLS表"
			show.Disable()
		case 10:
			na = "加载配置"
			show.Disable()
		case 11:
			na = "绑定导入"
		case 12:
			na = "IAT表"
			show.Disable()
		case 13:
			na = "延迟导入"
			show.Disable()
		case 14:
			na = "COM"
			show.Disable()
		case 15:
			na = "保留"
			show.Disable()
		}
		name := widget.NewLabel(na)
		inputRVA := widget.NewEntry()
		inputRVA.SetText(fmt.Sprintf("%08x", v.VirtualAddress))
		inputSize := widget.NewEntry()
		inputSize.SetText(fmt.Sprintf("%08x", v.Size))

		content.Add(container.New(layout.NewGridLayout(4), name, inputRVA, inputSize, show))
	}
	save := widget.NewButton("保存", func() {
		log.Println("tapped home")
	})
	content.Add(save)
	//layout.NewGridWrapLayout(fyne.NewSize(80, 35))
	wDos.SetContent(content)

	wDos.Resize(fyne.NewSize(350, 300))

	wDos.CenterOnScreen()
	//显示该窗口
	wDos.Show()
}

func section(myApp fyne.App) {
	//创建一个窗口并设置名称
	wDos := myApp.NewWindow("section")
	content := container.NewVBox()
	line := widget.NewLabel("——————————————————————————————————————————————————————")
	content.Add(container.New(layout.NewGridLayout(1), line))
	for _, v := range PE.SECTION {
		retH := reflect.TypeOf(v)
		retV := reflect.ValueOf(v)
		//获取结构体里的名称
		for i := 0; i < retH.NumField(); i += 2 {
			field := retH.Field(i)

			name := widget.NewLabel(strings.ToLower(field.Name))
			input := widget.NewEntry()
			value0 := fmt.Sprintf("%X", retV.Field(i).Interface())
			value := strings.Repeat("0", intSize(retV.Field(i).Interface())-len(value0)) + value0

			input.SetText(value)
			field2 := retH.Field(i + 1)

			name2 := widget.NewLabel(strings.ToLower(field2.Name))
			input2 := widget.NewEntry()

			value20 := fmt.Sprintf("%X", retV.Field(i+1).Interface())
			value2 := strings.Repeat("0", intSize(retV.Field(i+1).Interface())-len(value20)) + value20
			input2.SetText(value2)
			content.Add(container.New(layout.NewGridLayout(4), name, input, name2, input2))
		}
		line := widget.NewLabel("——————————————————————————————————————————————————————")
		content.Add(container.New(layout.NewGridLayout(1), line))
	}

	save := widget.NewButton("保存", func() {
		log.Println("tapped home")
	})
	content.Add(save)
	//layout.NewGridWrapLayout(fyne.NewSize(80, 35))
	wDos.SetContent(content)

	wDos.Resize(fyne.NewSize(300, 500))

	wDos.CenterOnScreen()
	//显示该窗口
	wDos.Show()
}

func importTable(myApp fyne.App) {

	wDos := myApp.NewWindow("导入表")

	tables := PE.readImportTable()

	t := widget.NewTable(
		func() (int, int) { return len(tables) + 1, 5 },
		func() fyne.CanvasObject {
			return widget.NewLabel("OriginalFirstThunk")
		},
		func(id widget.TableCellID, cell fyne.CanvasObject) {
			label := cell.(*widget.Label)
			if id.Row == 0 {
				switch id.Col {
				case 0:
					label.SetText(fmt.Sprintf("Name"))
				case 1:
					label.SetText(fmt.Sprintf("OriginalFirstThunk"))
				case 2:
					label.SetText(fmt.Sprintf("TimeDateStamp"))
				case 3:
					label.SetText(fmt.Sprintf("ForwarderChain"))
				case 4:
					label.SetText(fmt.Sprintf("FirstThunk"))
				}
			} else {
				switch id.Col {
				case 0:
					label.SetText(fmt.Sprintf("%08s", PE.ReadAtString(PE.RVAtoFOA(tables[id.Row-1].Name))))
				case 1:
					label.SetText(fmt.Sprintf("%08x", tables[id.Row-1].OriginalFirstThunk))
				case 2:
					label.SetText(fmt.Sprintf("%08x", tables[id.Row-1].TimeDateStamp))
				case 3:
					label.SetText(fmt.Sprintf("%08x", tables[id.Row-1].ForwarderChain))
				case 4:
					label.SetText(fmt.Sprintf("%08x", tables[id.Row-1].FirstThunk))
				}
			}

		})

	t.OnSelected = func(id widget.TableCellID) {
		thunkTable(myApp, PE.RVAtoFOA(tables[id.Row-1].OriginalFirstThunk))
	}

	wDos.SetContent(t)
	wDos.Resize(fyne.NewSize(750, 500))

	wDos.CenterOnScreen()
	//显示该窗口
	wDos.Show()
}

func thunkTable(myApp fyne.App, foa int64) {
	//创建一个窗口并设置名称
	wDos := myApp.NewWindow("thunk")
	thunks := PE.readThunk(foa)

	t := widget.NewTable(
		func() (int, int) { return len(thunks) + 1, 2 },
		func() fyne.CanvasObject {
			return widget.NewLabel("00000000")
		},
		func(id widget.TableCellID, cell fyne.CanvasObject) {
			label := cell.(*widget.Label)
			if id.Row == 0 {
				switch id.Col {
				case 0:
					label.SetText(fmt.Sprintf("Hint"))
				case 1:
					label.SetText(fmt.Sprintf("Name"))
				}

			} else {
				switch id.Col {
				case 0:
					if thunks[id.Row-1].Data >= 2147483648 {
						label.SetText(fmt.Sprintf("%x", thunks[id.Row-1].Data-2147483648))
					} else {
						var i uint16
						h := make([]byte, 2)
						hFOA := PE.RVAtoFOA(thunks[id.Row-1].Data)
						PE.ReadAt(h, hFOA)
						ByteToStruct(h, &i)
						label.SetText(fmt.Sprintf("%x", i))
					}

				case 1:
					var str string
					if thunks[id.Row-1].Data >= 2147483648 {
						str = fmt.Sprintf("无名称")
					} else {
						nameFOA := PE.RVAtoFOA(thunks[id.Row-1].Data)
						name := PE.ReadAtString(nameFOA + 2)
						str = fmt.Sprintf("%s", name)
					}
					label.SetText(str)

				}
			}

		})
	wDos.SetContent(t)
	wDos.Resize(fyne.NewSize(600, 500))

	wDos.CenterOnScreen()
	//显示该窗口
	wDos.Show()
}

func bindImportTable(myApp fyne.App) {
	//创建一个窗口并设置名称
	wDos := myApp.NewWindow("绑定导入表")
	lists := PE.readBindImportTable()
	foa := PE.RVAtoFOA(PE.NT.OptionalHeader.DataDirectory[11].VirtualAddress)
	data := make(map[string][]string)
	for _, v := range lists {
		imp := v[0].(IMAGE_BOUND_IMPORT_DESCRIPTOR)
		var refs []string
		for i := 1; i < len(v); i++ {
			ref := v[i].(IMAGE_BOUND_FORWARDER_REF)
			t := time.Unix(int64(ref.TimeDateStamp), 0)
			dateStr := t.Format("2006/01/02 15:04:05")
			refs = append(refs, fmt.Sprintf("%s   %s", PE.ReadAtString(int64(ref.OffsetModuleName)+foa), dateStr))
		}
		t := time.Unix(int64(imp.TimeDateStamp), 0)
		dateStr := t.Format("2006/01/02 15:04:05")
		data[fmt.Sprintf("%s  %s  %d", PE.ReadAtString(int64(imp.OffsetModuleName)+foa), dateStr, imp.NumberOfModuleForwarderRefs)] = refs
		data[""] = append(data[""],fmt.Sprintf("%s  %s  %d", PE.ReadAtString(int64(imp.OffsetModuleName)+foa), dateStr, imp.NumberOfModuleForwarderRefs))
	}

	tree := widget.NewTreeWithStrings(data)
	tree.OnSelected = func(id string) {
		fmt.Println("Tree node selected:", id)
	}
	tree.OnUnselected = func(id string) {
		fmt.Println("Tree node unselected:", id)
	}
	tree.OpenBranch("A")
	tree.OpenBranch("D")
	tree.OpenBranch("E")
	tree.OpenBranch("L")
	tree.OpenBranch("M")
	wDos.SetContent(tree)
	wDos.Resize(fyne.NewSize(500, 500))

	wDos.CenterOnScreen()
	//显示该窗口
	wDos.Show()
}

func intSize(data interface{}) int {
	switch data.(type) {
	case uint8, *uint8:
		return 2
	case uint16, *uint16:
		return 4
	case uint32, *uint32:
		return 8
	case uint64, *uint64:
		return 16
	}
	return 0
}
