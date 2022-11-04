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
var data = []string{"a", "string", "list"}

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

	str := ".go_pe"
	fmt.Printf("%x\n", str)

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

func showtab() *fyne.Container  {
	if PE.DOS.E_magic != 23117{
		tab.Add( widget.NewLabel("是否PE文件: 否"))
	}else{
		tab.Add( widget.NewLabel("是否PE文件: 是"))
	}

	size:=fmt.Sprintf("文件大小: %d字节", binary.Size(PE.Source))
	tab.Add(widget.NewLabel(size))

	t := time.Unix(int64(PE.NT.FileHeader.TimeDateStamp), 0)
	dateStr := t.Format("2006/01/02 15:04:05")
	//返回string
	ctime:=fmt.Sprintf("创建时间: %s", dateStr)
	tab.Add(widget.NewLabel(ctime))


	if PE.NT.OptionalHeader.Magic == 267{
		tab.Add(widget.NewLabel("运行平台: win32位"))
	}else{
		tab.Add(widget.NewLabel("运行平台: win64位"))
	}

	tab.Add(widget.NewLabel(fmt.Sprintf("程序入口OEP(RVA): %#X",PE.NT.OptionalHeader.AddressOfEntryPoint)))

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
		if PE.addSection(8000){
			dialog.ShowInformation("提示", "添加成功", myWindow)
		}else{
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
	buttonSection := widget.NewButton("节表", func() {
		if len(PE.Source) == 0 {
			dialog.ShowInformation("提示", "请先打开一个文件", myWindow)
			return
		}
		section(myApp)
	})

	//创建功能行
	containe := container.New(layout.NewHBoxLayout(),buttonOpen, buttonDOS, buttonPE, buttonOpPE, buttonSection, layout.NewSpacer())
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
		if  intSize(retV.Field(i).Interface()) > len(value0) {
			value = strings.Repeat("0", intSize(retV.Field(i).Interface())-len(value0))+value0
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
		value := strings.Repeat("0", intSize(retV.Field(i).Interface())-len(value0))+value0
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
		if  intSize(retV.Field(i).Interface()) > len(value0) {
			value = strings.Repeat("0", intSize(retV.Field(i).Interface())-len(value0))+value0
		}
		input.SetText(value)
		if i+1 < retH.NumField() {
			field2 := retH.Field(i + 1)
			name2 := widget.NewLabel(field2.Name)
			input2 := widget.NewEntry()
			value20 := fmt.Sprintf("%X", retV.Field(i+1).Interface())
			value2 := value20
			if  intSize(retV.Field(i+1).Interface()) > len(value20) {
				value2 = strings.Repeat("0", intSize(retV.Field(i+1).Interface())-len(value20))+value20
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
			value := strings.Repeat("0", intSize(retV.Field(i).Interface())-len(value0))+value0

			input.SetText(value)
			field2 := retH.Field(i + 1)

			name2 := widget.NewLabel(strings.ToLower(field2.Name))
			input2 := widget.NewEntry()

			value20 := fmt.Sprintf("%X", retV.Field(i+1).Interface())
			value2 := strings.Repeat("0", intSize(retV.Field(i+1).Interface())-len(value20))+value20
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

func intSize(data interface{}) int {
	switch  data.(type) {
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
