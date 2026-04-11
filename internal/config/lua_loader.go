package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	lua "github.com/yuin/gopher-lua"
)

func loadLua(path string) (*Config, error) {
	L := lua.NewState(lua.Options{SkipOpenLibs: true})
	defer L.Close()

	lua.OpenBase(L)
	lua.OpenTable(L)
	lua.OpenString(L)
	lua.OpenMath(L)

	L.SetGlobal("env", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		fallback := ""
		if L.GetTop() >= 2 {
			fallback = L.CheckString(2)
		}
		if v, ok := os.LookupEnv(key); ok {
			L.Push(lua.LString(v))
		} else {
			L.Push(lua.LString(fallback))
		}
		return 1
	}))

	fn, err := L.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load lua config: %w", err)
	}
	L.Push(fn)
	if err := L.PCall(0, 1, nil); err != nil {
		return nil, fmt.Errorf("execute lua config: %w", err)
	}

	ret := L.Get(-1)
	if ret == lua.LNil {
		return nil, errors.New("lua config must return table")
	}

	tbl, ok := ret.(*lua.LTable)
	if !ok {
		return nil, errors.New("lua config must return table")
	}

	obj, err := luaValueToAny(tbl)
	if err != nil {
		return nil, fmt.Errorf("convert lua config: %w", err)
	}

	data, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("marshal lua config: %w", err)
	}

	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("decode lua config: %w", err)
	}

	for i := range cfg.Plugins.Entries {
		if cfg.Plugins.Entries[i].Path != "" && !filepath.IsAbs(cfg.Plugins.Entries[i].Path) {
			cfg.Plugins.Entries[i].Path = filepath.Join(filepath.Dir(path), cfg.Plugins.Entries[i].Path)
		}
	}
	if len(cfg.Plugins.Scripts) > 0 {
		for i := range cfg.Plugins.Scripts {
			if cfg.Plugins.Scripts[i] != "" && !filepath.IsAbs(cfg.Plugins.Scripts[i]) {
				cfg.Plugins.Scripts[i] = filepath.Join(filepath.Dir(path), cfg.Plugins.Scripts[i])
			}
		}
	}

	return cfg, nil
}

func luaValueToAny(v lua.LValue) (any, error) {
	switch tv := v.(type) {
	case lua.LBool:
		return bool(tv), nil
	case lua.LNumber:
		f := float64(tv)
		if float64(int64(f)) == f {
			return int64(f), nil
		}
		return f, nil
	case lua.LString:
		return string(tv), nil
	case *lua.LTable:
		return luaTableToAny(tv)
	case *lua.LNilType:
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported lua value type: %s", v.Type().String())
	}
}

func luaTableToAny(tbl *lua.LTable) (any, error) {
	isArray, maxIndex := luaTableArrayMeta(tbl)
	if isArray {
		arr := make([]any, maxIndex)
		for i := 1; i <= maxIndex; i++ {
			v := tbl.RawGetInt(i)
			converted, err := luaValueToAny(v)
			if err != nil {
				return nil, err
			}
			arr[i-1] = converted
		}
		return arr, nil
	}

	obj := map[string]any{}
	var convErr error
	tbl.ForEach(func(k lua.LValue, v lua.LValue) {
		if convErr != nil {
			return
		}
		key := luaKeyToString(k)
		converted, err := luaValueToAny(v)
		if err != nil {
			convErr = err
			return
		}
		obj[key] = converted
	})
	if convErr != nil {
		return nil, convErr
	}
	return obj, nil
}

func luaTableArrayMeta(tbl *lua.LTable) (bool, int) {
	maxIndex := 0
	count := 0
	valid := true

	tbl.ForEach(func(k lua.LValue, _ lua.LValue) {
		if !valid {
			return
		}
		num, ok := k.(lua.LNumber)
		if !ok {
			valid = false
			return
		}
		f := float64(num)
		if f <= 0 || float64(int(f)) != f {
			valid = false
			return
		}
		i := int(f)
		if i > maxIndex {
			maxIndex = i
		}
		count++
	})

	if !valid || count == 0 {
		return false, 0
	}
	return count == maxIndex, maxIndex
}

func luaKeyToString(k lua.LValue) string {
	switch key := k.(type) {
	case lua.LString:
		return string(key)
	case lua.LNumber:
		f := float64(key)
		if float64(int64(f)) == f {
			return strconv.FormatInt(int64(f), 10)
		}
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", f), "0"), ".")
	default:
		return k.String()
	}
}
