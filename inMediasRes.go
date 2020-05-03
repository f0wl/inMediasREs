// Marius Genheimer 2019-2020, https://dissectingmalwa.re

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"time"

	utilimr "./utilities"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/glaslos/ssdeep"
	"github.com/h2non/filetype"
	"github.com/pkg/browser"
	"github.com/weldpua2008/go-dialog"
)

func processCommand(cmd string, sha256h string) {

	switch cmd {
	case ": vt":
		{
			vtURL := "https://virustotal.com/gui/file/" + sha256h
			browser.OpenURL(vtURL)
		}

	case ": ha":
		{
			haURL := "https://www.hybrid-analysis.com/search?query=" + sha256h
			browser.OpenURL(haURL)
		}

	case ": ms":
		{
			msURL := "https://malshare.com/search.php?query=" + sha256h
			browser.OpenURL(msURL)
		}

	default:
		{
			d := dialog.New(dialog.AUTO, 0)
			d.Msgbox("Command not recognized. Type \"help\" to see available commands")
		}
	}
}

func main() {
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	filename := os.Args[1]

	// Header Paragraph
	headerBox := widgets.NewParagraph()
	headerBox.Title = "Filename: " + filename
	headerBox.Text = "    ____     __  ___       ___          ___  ____\n"
	headerBox.Text += "   /  _/__  /  |/  /__ ___/ (_)__ ____ / _ \\/ __/__             Kickstart your static analysis process             | Press CTRL+q to quit\n"
	headerBox.Text += "  _/ // _ \\/ /|_/ / -_) _  / / _ `(_-</ , _/ _/(_-<             Marius Genheimer (@f0wlsec), 2019-2020             | Press CTRL+r for a report\n"
	headerBox.Text += " /___/_//_/_/  /_/\\__/\\_,_/_/\\_,_/___/_/|_/___/___/                   https://dissectingmalwa.re\n"

	headerBox.SetRect(0, 0, 150, 7)
	headerBox.TextStyle.Fg = ui.ColorCyan
	headerBox.BorderStyle.Fg = ui.ColorCyan

	hashBox := widgets.NewParagraph()
	hashBox.SetRect(0, 7, 95, 13)
	hashBox.Title = "Hashes"
	hashBox.TextStyle.Fg = ui.ColorWhite
	hashBox.BorderStyle.Fg = ui.ColorCyan

	// generate file hashes
	md5hash, err := utilimr.Hashfilemd5(filename)
	sha1hash, err := utilimr.Hashfilesha1(filename)
	sha256hash, err := utilimr.Hashfilesha256(filename)
	ssdeephash, err := ssdeep.FuzzyFilename(filename)

	if err == nil {
		hashBox.Text = "MD5: " + "    " + md5hash + "\n"
		hashBox.Text += "SHA1: " + "   " + sha1hash + "\n"
		hashBox.Text += "SHA256: " + " " + sha256hash + "\n"
		hashBox.Text += "SSDEEP: " + " " + ssdeephash + "\n"
	}

	fileInfoBox := widgets.NewParagraph()
	fileInfoBox.SetRect(95, 7, 150, 13)
	fileInfoBox.Title = "File"
	fileInfoBox.TextStyle.Fg = ui.ColorWhite
	fileInfoBox.BorderStyle.Fg = ui.ColorCyan

	filestat, err := os.Stat(filename)
	filesize := filestat.Size()
	filemodtime := filestat.ModTime()

	buf, err := ioutil.ReadFile(filename)
	kind, err := filetype.Match(buf)
	if kind == filetype.Unknown {
		fmt.Println("Unknown file type")
		return
	}

	fileInfoBox.Text = "Size: " + "              " + strconv.FormatInt(filesize, 10) + " (" + strconv.FormatInt(filesize/1024.0, 10) + " KiB)" + "\n"
	fileInfoBox.Text += "Type: " + "              " + kind.MIME.Type + " / " + "\n"
	fileInfoBox.Text += "Compiler/Linker: " + "\n"
	fileInfoBox.Text += "Date modified: " + "     " + filemodtime.Format("2006-01-02 15:04:05") + "\n"

	sectionBox := widgets.NewList()
	sectionBox.SetRect(0, 13, 30, 23)
	sectionBox.Title = "Sections"
	sectionBox.TextStyle.Fg = ui.ColorWhite
	sectionBox.BorderStyle.Fg = ui.ColorCyan

	stringsBox := widgets.NewList()
	stringsBox.SetRect(30, 13, 100, 23)
	stringsBox.Title = "Strings"
	stringsBox.TextStyle.Fg = ui.ColorWhite
	stringsBox.BorderStyle.Fg = ui.ColorCyan

	urlBox := widgets.NewList()
	urlBox.SetRect(100, 13, 150, 23)
	urlBox.Title = "URLs/IPs"
	urlBox.TextStyle.Fg = ui.ColorWhite
	urlBox.BorderStyle.Fg = ui.ColorCyan

	entropyBox := widgets.NewPlot()
	entropyBox.SetRect(0, 23, 50, 36)
	entropyBox.Title = "Entropy"
	entropyBox.BorderStyle.Fg = ui.ColorCyan

	sandBox := widgets.NewList()

	services := []string{
		"\n\n     VirusTotal [vt]\n",
		"     Hybrid-Analysis [ha]\n",
		"     Malshare [ms]\n",
		"     VirusShare [vs]\n",
	}

	sandBox.SetRect(50, 23, 80, 36)
	sandBox.Title = "Analysis Services"
	sandBox.Rows = services
	sandBox.TextStyle.Fg = ui.ColorWhite
	sandBox.BorderStyle.Fg = ui.ColorCyan

	yaraBox := widgets.NewList()
	yaraBox.SetRect(80, 23, 125, 36)
	yaraBox.Title = "YARA Matches"
	yaraBox.TextStyle.Fg = ui.ColorWhite
	yaraBox.BorderStyle.Fg = ui.ColorCyan

	extrasBox := widgets.NewParagraph()
	extrasBox.SetRect(125, 23, 150, 36)
	extrasBox.Title = "Extras"
	extrasBox.TextStyle.Fg = ui.ColorWhite
	extrasBox.BorderStyle.Fg = ui.ColorCyan

	fileHeaderBox := widgets.NewParagraph()
	fileHeaderBox.SetRect(0, 36, 50, 47)
	fileHeaderBox.Title = "Executable Header"
	fileHeaderBox.TextStyle.Fg = ui.ColorWhite
	fileHeaderBox.BorderStyle.Fg = ui.ColorCyan

	importsBox := widgets.NewList()
	importsBox.SetRect(50, 36, 100, 47)
	importsBox.Title = "Imports"
	//importsBox.Rows = impList
	importsBox.TextStyle.Fg = ui.ColorWhite
	importsBox.BorderStyle.Fg = ui.ColorCyan

	symbolsBox := widgets.NewList()
	symbolsBox.SetRect(100, 36, 150, 47)
	symbolsBox.Title = "Symbols"
	//symbolsBox.Rows =
	symbolsBox.TextStyle.Fg = ui.ColorWhite
	symbolsBox.BorderStyle.Fg = ui.ColorCyan

	cmdBox := widgets.NewParagraph()
	cmdBox.SetRect(0, 47, 150, 50)
	cmdBox.Title = "Commandline"
	cmdBox.Text = ": "
	cmdBox.TextStyle.Fg = ui.ColorWhite
	cmdBox.BorderStyle.Fg = ui.ColorCyan

	//Render Boxes
	ui.Render(headerBox, hashBox, fileInfoBox, sectionBox, stringsBox, urlBox, entropyBox, sandBox, yaraBox, fileHeaderBox, importsBox, symbolsBox, extrasBox, cmdBox)

	tickerCount := 1
	tickerCount++
	uiEvents := ui.PollEvents()
	ticker := time.NewTicker(time.Second).C
	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "<MouseLeft>":
			case "<MouseRelease>":
			case "<MouseRight>":
			case "<MouseMiddle>":
			case "<MouseWheelUp>":
			case "<MouseWheelDown>":
			case "<C-q>":
				return
			case "<Escape>":
				ui.Render(headerBox, hashBox, fileInfoBox, sectionBox, stringsBox, urlBox, entropyBox, sandBox, yaraBox, fileHeaderBox, importsBox, symbolsBox, extrasBox, cmdBox)
			case "<Space>":
				cmdBox.Text += " "
				ui.Render(cmdBox)
			case "<Backspace>":
				sz := len(cmdBox.Text)
				if sz > 2 {
					cmdBox.Text = cmdBox.Text[:sz-1]
				}
				ui.Render(cmdBox)
			case "<Enter>":
				processCommand(cmdBox.Text, sha256hash)
				cmdBox.Text = ": "
				ui.Render(cmdBox)
			default:
				if (e.ID != "<MouseLeft>") && (e.ID != "<MouseRight>") && (e.ID != "<MouseMiddle>") && (e.ID != "<MouseRelease>") {
					cmdBox.Text += e.ID
					ui.Render(cmdBox)
				}
			}
		case <-ticker:
			tickerCount++
		}
	}
}
