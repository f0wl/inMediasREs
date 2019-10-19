// Marius Genheimer 2019, https://dissectingmalwa.re

package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/glaslos/ssdeep"
	"github.com/h2non/filetype"
	"github.com/pkg/browser"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func ioReader(file string) io.ReaderAt {
	r, err := os.Open(file)
	check(err)
	return r
}

//func elfAnalysis() (imp []string, sym []elf.ImportedSymbol) {
//
//	f := ioReader(os.Args[1])
//	_elf, err := elf.NewFile(f)
//	check(err)
//
//	// Read and decode ELF identifier
//	var ident [16]uint8
//	f.ReadAt(ident[0:], 0)
//	check(err)
//
//	if ident[0] != '\x7f' || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F' {

//		if ident[0] != '\x4D' || ident[1] != 'M' || ident[2] != 'Z'{
//			PEAnalysis()
//		}
//
//		else {
//			os.Exit(1)
//		}
//	}
//
//	imp, err = _elf.ImportedLibraries()
//	sym, err = _elf.ImportedSymbols()
//
//	return imp, sym
//
//}

//func PEAnalysis() {
//}

func processCommand(cmd string, sha256h string, hnk *widgets.Paragraph) {

	if cmd == ": vt" {
		vtURL := "https://virustotal.com/gui/file/" + sha256h
		browser.OpenURL(vtURL)
	}

	if cmd == ": ha" {
		haURL := "https://www.hybrid-analysis.com/search?query=" + sha256h
		browser.OpenURL(haURL)
	}

	if cmd == ": ms" {
		msURL := "https://malshare.com/search.php?query=" + sha256h
		browser.OpenURL(msURL)
	}

	if cmd == ": honk" {
		ui.Render(hnk)
	}

}

func hashfilemd5(filePath string) (string, error) {
	var returnMD5String string

	file, err := os.Open(filePath)
	if err != nil {
		return returnMD5String, err
	}

	defer file.Close()

	hash := md5.New()

	if _, err := io.Copy(hash, file); err != nil {
		return returnMD5String, err
	}

	hashInBytes := hash.Sum(nil)[:16]

	returnMD5String = hex.EncodeToString(hashInBytes)

	return returnMD5String, nil

}

func hashfilesha1(filePath string) (string, error) {
	var returnSHA1String string

	file, err := os.Open(filePath)
	if err != nil {
		return returnSHA1String, err
	}

	defer file.Close()

	hash := sha1.New()

	if _, err := io.Copy(hash, file); err != nil {
		return returnSHA1String, err
	}

	hashInBytes := hash.Sum(nil)[:20]

	returnSHA1String = hex.EncodeToString(hashInBytes)

	return returnSHA1String, nil

}

func hashfilesha256(filePath string) (string, error) {
	var returnSHA256String string

	file, err := os.Open(filePath)
	if err != nil {
		return returnSHA256String, err
	}

	defer file.Close()

	hash := sha256.New()

	if _, err := io.Copy(hash, file); err != nil {
		return returnSHA256String, err
	}

	hashInBytes := hash.Sum(nil)[:32]

	returnSHA256String = hex.EncodeToString(hashInBytes)

	return returnSHA256String, nil

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
	headerBox.Text += "   /  _/__  /  |/  /__ ___/ (_)__ ____ / _ \\/ __/__             Kickstart your static analysis process             | Press q to quit\n"
	headerBox.Text += "  _/ // _ \\/ /|_/ / -_) _  / / _ `(_-</ , _/ _/(_-<               Marius Genheimer (@f0wlsec), 2019                | Press r to create a report\n"
	headerBox.Text += " /___/_//_/_/  /_/\\__/\\_,_/_/\\_,_/___/_/|_/___/___/                   https://dissectingmalwa.re                   | Don't forget to honk\n"

	headerBox.SetRect(0, 0, 150, 7)
	headerBox.TextStyle.Fg = ui.ColorCyan
	headerBox.BorderStyle.Fg = ui.ColorCyan

	hashBox := widgets.NewParagraph()
	hashBox.SetRect(0, 7, 95, 13)
	hashBox.Title = "Hashes"
	hashBox.TextStyle.Fg = ui.ColorWhite
	hashBox.BorderStyle.Fg = ui.ColorCyan

	// generate file hashes
	md5hash, err := hashfilemd5(filename)
	sha1hash, err := hashfilesha1(filename)
	sha256hash, err := hashfilesha256(filename)
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

	//var impList []string
	//var symList []elf.ImportedSymbol
	//impList, symList = elfAnalysis()

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

	honk := widgets.NewParagraph()
	honk.SetRect(0, 0, 150, 50)
	honk.Title = "InMediasREs - Honk!"
	honk.Text = "Press ESC to quit\n\n\n\n\n\n\n\n\n\n\n\n\n                                                                                          _...--.\n"
	honk.Text += "                                                                         _____......----'     .'\n"
	honk.Text += "                                                                   _..-''                   .'\n"
	honk.Text += "                                                                 .'                       ./\n"
	honk.Text += "                                                          _.--._.'                       .' |\n"
	honk.Text += "                                                       .-'                           .-.'  /\n"
	honk.Text += "                                                     .'   _.-.                     .  \\   '    \n"
	honk.Text += "                                                   .'  .'   .'    _    .-.        / `./  :    _  _  ___  _  _ _  __\n"
	honk.Text += "                                                 .'  .'   .'    _    .-.        / `./  :     | || |/ _ \\| \\| | |/ /\n"
	honk.Text += "                                               .'  .'   .'    _    .-.        / `./  :       | __ | (_) | .` | ' < \n"
	honk.Text += "                                             .'  .'   .'  .--' `.  |  \\  |`. |     .'        |_||_|\\___/|_|\\_|_|\\_\\ \n"
	honk.Text += "                                          _.'  .'   .' `.'       `-'   \\ / |.'   .'\n"
	honk.Text += "                                       _.'  .-'   .'     `-.            `      .'\n"
	honk.Text += "                                     .'   .'    .'          `-.._ _ _ _ .-.    :\n"
	honk.Text += "                                    /    /o _.-'               .--'   .'   \\   |\n"
	honk.Text += "                                  .'-.__..-'                  /..    .`    / .'\n"
	honk.Text += "                                .'   . '                       /.'/.'     /  |\n"
	honk.Text += "                               `---'                                   _.'   '\n"
	honk.Text += "                                                                     /.'    .'\n"
	honk.Text += "                                                                      /.'/.'\n"
	honk.TextStyle.Fg = ui.ColorCyan
	honk.BorderStyle.Fg = ui.ColorCyan

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
				processCommand(cmdBox.Text, sha256hash, honk)
				cmdBox.Text = ": "
				ui.Render(cmdBox)
			// TODO: I think I can grab the mouseevents here
			default:
				cmdBox.Text += e.ID
				ui.Render(cmdBox)
			}
		case <-ticker:
			tickerCount++
		}
	}
}
