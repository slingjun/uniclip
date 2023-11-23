package common

import (
	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/encoding/unicode"
)

// Given IANA Charset name, return its corresponding encoding
func CvtEncoding(charsetName string) encoding.Encoding {
	switch charsetName {
	case "Shift_JIS":
		return japanese.ShiftJIS
	case "EUC-JP":
		return japanese.EUCJP
	case "ISO-2022-JP":
		return japanese.ISO2022JP
	case "EUC-KR":
		return korean.EUCKR
	case "GB-18030":
		return simplifiedchinese.GB18030
	case "HZ":
		return simplifiedchinese.HZGB2312
	case "Big5":
		return traditionalchinese.Big5
	case "ISO-8859-1":
		return charmap.ISO8859_1
	default:
		// default:
		return unicode.UTF8
	}
}

func GetBestCharset(input []byte) chardet.Result {
	detector := chardet.NewTextDetector()
	results, _ := detector.DetectAll(input)
	maxConfidence := results[0].Confidence

	for _, result := range results {
		if result.Confidence < maxConfidence {
			break
		}
		if result.Charset == "GB-18030" {
			return result
		}
	}
	return results[0]
}
