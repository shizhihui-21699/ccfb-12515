package extract_test

import (
	"testing"

	"redos-hunter/internal/extract"
)

func findPats(occs []extract.Occurrence) map[string]extract.Occurrence {
	m := map[string]extract.Occurrence{}
	for _, o := range occs {
		m[o.Pattern] = o
	}
	return m
}

func TestScanJavaScript(t *testing.T) {
	src := `
const a = /(a+)+$/g;
const b = x / 2;
function f() { return /\d+\.\d+/; }
const c = new RegExp("a*a*$", "i");
const d = /[a-z/]+/;
// const skip = /nope/;
`
	occs := extract.ScanJavaScript("x.js", src)
	m := findPats(occs)
	if _, ok := m[`(a+)+$`]; !ok {
		t.Errorf("未抽到正则字面量 (a+)+$，得到 %d 条: %+v", len(occs), occs)
	}
	if o, ok := m[`(a+)+$`]; ok && o.Flags != "g" {
		t.Errorf("flags 错误: %q", o.Flags)
	}
	if _, ok := m[`\d+\.\d+`]; !ok {
		t.Errorf("return 后的正则被误判为除法")
	}
	if o, ok := m[`a*a*$`]; !ok {
		t.Errorf("未抽到 RegExp 构造实参")
	} else if o.Flags != "i" || o.Kind != "constructor" {
		t.Errorf("构造式 flags/kind 错误: %+v", o)
	}
	if _, ok := m[`[a-z/]+`]; !ok {
		t.Errorf("字符类内 / 处理错误")
	}
	if _, ok := m["nope"]; ok {
		t.Errorf("注释中的正则被误抽")
	}
	// 除法不应被当正则。
	for _, o := range occs {
		if o.Pattern == " 2" || o.Kind == "literal" && o.Pattern == "" {
			t.Errorf("除法被误判: %+v", o)
		}
	}
}

func TestScanPython(t *testing.T) {
	src := `
import re
p1 = re.compile(r"(a|aa)*$")
p2 = re.search("\\d+-\\d+", text)
p3 = re.match(r"foo" r"bar", x)
not_re = "just a string (a+)+"
`
	occs := extract.ScanPython("x.py", src)
	m := findPats(occs)
	if o, ok := m[`(a|aa)*$`]; !ok {
		t.Errorf("raw 字符串正则未抽到")
	} else if !o.RawString {
		t.Errorf("raw 标记错误")
	}
	if o, ok := m[`\d+-\d+`]; !ok {
		t.Errorf("普通字符串反转义错误，现有: %+v", occs)
	} else if o.Pattern != `\d+-\d+` {
		t.Errorf("反转义结果错误: %q", o.Pattern)
	}
	if _, ok := m[`foobar`]; !ok {
		t.Errorf("相邻字符串拼接未合并: %+v", occs)
	}
	if _, ok := m["just a string (a+)+"]; ok {
		t.Errorf("非 re 调用的字符串被误抽")
	}
}

func TestScanGo(t *testing.T) {
	src := `
package main
import "regexp"
var re = regexp.MustCompile(` + "`" + `a+)+$` + "`" + `)
var re2 = regexp.Compile("\\d{3}-\\d{4}")
var x := 10 / 2
`
	occs := extract.ScanGo("x.go", src)
	m := findPats(occs)
	if _, ok := m[`a+)+$`]; !ok {
		t.Errorf("反引号原始串未抽到: %+v", occs)
	} else if o := m[`a+)+$`]; !o.RawString {
		t.Errorf("raw 标记错误")
	}
	if _, ok := m[`\d{3}-\d{4}`]; !ok {
		t.Errorf("双引号正则未反转义抽取: %+v", occs)
	}
}

func TestScanJava(t *testing.T) {
	src := `
import java.util.regex.Pattern;
class X {
  Pattern p = Pattern.compile("(a+)+$");
  String s = "normal";
}
`
	occs := extract.ScanJava("X.java", src)
	m := findPats(occs)
	if _, ok := m[`(a+)+$`]; !ok {
		t.Errorf("Pattern.compile 实参未抽到: %+v", occs)
	}
	if _, ok := m["normal"]; ok {
		t.Errorf("普通字符串被误抽")
	}
}

func TestLocations(t *testing.T) {
	src := "const x = /abc/;"
	occs := extract.ScanJavaScript("x.js", src)
	if len(occs) != 1 {
		t.Fatalf("期望 1 条，得到 %d", len(occs))
	}
	o := occs[0]
	if o.Line != 1 || o.Col != 11 {
		t.Errorf("位置错误: line=%d col=%d（期望 1,11）", o.Line, o.Col)
	}
}
