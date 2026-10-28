package i18n

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestTextFollowsProcessLang(t *testing.T) {
	defer SetProcessLang(ZH)
	SetProcessLang(EN)
	if got := Text("收到退出信号，正在关闭 HTTP 服务"); got != "shutdown signal received, closing the HTTP server" {
		t.Errorf("英文进程语言下应翻译，得到 %q", got)
	}
	if got := Text("这条日志故意没有翻译"); got != "这条日志故意没有翻译" {
		t.Errorf("未收录的文案应原样返回中文，得到 %q", got)
	}
	SetProcessLang(ZH)
	if got := Text("收到退出信号，正在关闭 HTTP 服务"); got != "收到退出信号，正在关闭 HTTP 服务" {
		t.Errorf("中文进程语言下应原样返回，得到 %q", got)
	}
}

func TestCodedCarriesBothLanguages(t *testing.T) {
	err := NewCoded(Msg{ZH: "创建链 %s 失败: %v", EN: "failed to create chain %s: %v"}, "nat/X", "boom")
	if got := err.Error(); got != "创建链 nat/X 失败: boom" {
		t.Errorf("Error() 中文 = %q", got)
	}
	if got := err.S(EN); got != "failed to create chain nat/X: boom" {
		t.Errorf("S(EN) = %q", got)
	}
	zh, en := Bilingual(err)
	if zh != err.Error() || en != "failed to create chain nat/X: boom" {
		t.Errorf("Bilingual() = (%q, %q)", zh, en)
	}
	if zh, en := Bilingual(os.ErrNotExist); zh == "" || en != "" {
		t.Errorf("非双语错误应只有中文文本: (%q, %q)", zh, en)
	}
}

// 源码里出现的每一条日志 / CLI 帮助 / i18n.Text 文案，都必须在词典里有英文。
var (
	hanLiteral  = regexp.MustCompile(`[\p{Han}]`)
	reLogMsg    = regexp.MustCompile(`log(?:ger)?\.(?:Debug|Info|Warn|Error)\(\s*"((?:[^"\\]|\\.)*)"`)
	reTextMsg   = regexp.MustCompile(`i18n\.Text\(\s*"((?:[^"\\]|\\.)*)"`)
	reFlagHelp  = regexp.MustCompile(`flag\.(?:String|Bool|Duration|Int)\(\s*"[^"]*"\s*,\s*[^,\n]+,\s*(?:\n\s*)?"((?:[^"\\]|\\.)*)"`)
	reLineComme = regexp.MustCompile(`(?m)^\s*//.*$`)
)

// TestLogDictionaryCoversSources 是「彻底全球化」的护栏：
// 只要有人新写一条中文日志或 CLI 帮助却忘了加英文，这个测试就会失败。
func TestLogDictionaryCoversSources(t *testing.T) {
	root := filepath.Join("..", "..")
	scanned := 0
	var missing []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", ".git", "node_modules", "assets":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// 去掉整行注释，避免注释里的中文误报
		src := reLineComme.ReplaceAllString(string(raw), "")
		rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		for _, rx := range []*regexp.Regexp{reLogMsg, reTextMsg, reFlagHelp} {
			for _, m := range rx.FindAllStringSubmatch(src, -1) {
				literal, err := strconv.Unquote(`"` + m[1] + `"`)
				if err != nil {
					continue
				}
				if !hanLiteral.MatchString(literal) {
					continue
				}
				scanned++
				if _, ok := logText[literal]; !ok {
					missing = append(missing, rel+": "+literal)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("扫描源码失败: %v", err)
	}
	if scanned == 0 {
		t.Fatal("没有扫描到任何中文日志/CLI 文案，扫描规则可能失效了")
	}
	if len(missing) > 0 {
		t.Fatalf("有 %d 条文案缺英文翻译（请补到 internal/i18n/logs.go 或 logs_packages.go）:\n  - %s",
			len(missing), strings.Join(missing, "\n  - "))
	}
	t.Logf("已校验 %d 条中文日志/CLI 文案", scanned)
}
