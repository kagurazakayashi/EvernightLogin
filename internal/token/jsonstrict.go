package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// rejectDuplicateJSONFields 严格解析 JSON 并拒绝任意对象层级中的重复字段名。
// encoding/json 默认“后者覆盖前者”，攻击者可利用重复的 kid/alg/typ 等头部字段
// 制造解析歧义；JWS 头部与声明集在进入业务校验前必须拒绝重复顶层/嵌套字段。
func rejectDuplicateJSONFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanUniqueJSONValue(decoder); err != nil {
		return err
	}
	// 只允许单个 JSON 值，禁止尾随内容。
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON 存在尾随内容")
	}
	return nil
}

func scanUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return keyErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON 对象字段名不是字符串")
				}
				if _, duplicated := seen[key]; duplicated {
					return errors.New("JSON 对象包含重复字段")
				}
				seen[key] = struct{}{}
				if err := scanUniqueJSONValue(decoder); err != nil {
					return err
				}
			}
			end, endErr := decoder.Token()
			if endErr != nil || end != json.Delim('}') {
				return errors.New("JSON 对象未正确闭合")
			}
			return nil
		case '[':
			for decoder.More() {
				if err := scanUniqueJSONValue(decoder); err != nil {
					return err
				}
			}
			end, endErr := decoder.Token()
			if endErr != nil || end != json.Delim(']') {
				return errors.New("JSON 数组未正确闭合")
			}
			return nil
		default:
			return errors.New("JSON 定界符非法")
		}
	case string, json.Number, bool, nil:
		return nil
	default:
		return errors.New("JSON 值类型非法")
	}
}
