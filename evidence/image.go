package evidence

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
)

// 证据截图的内容级校验与重编码。
//
// 为什么必须重编码而不是"校验通过就落盘"：这是一个安全平台的上传点，任何能落盘的东西
// 都可能被别处引用（报告、Markdown 导出、内网镜像）。重编码会让这些全部失效：
//   - 追加在图片尾部的内容（zip/脚本/polyglot）被丢弃；
//   - EXIF 里的 GPS/设备/时间不进入交付物；
//   - 一张 PNG 开头、里面其实另有载荷的文件，解码后只剩像素。
//
// 因此流程是：识别真实类型（不信扩展名与客户端 MIME）→ 用 DecodeConfig 先看尺寸（防解压
// 炸弹）→ 整幅解码 → 重编码成 png/jpg。只接受 png/jpeg/gif。
const (
	// MaxBytes 是单张图的上限（16MB）。截图远超这个数说明是别的东西。
	MaxBytes = 16 << 20
	// MaxPixels 是解码前就拒绝的像素上限（5000 万），用来挡"几 KB 的 PNG 解出 8 亿像素"。
	MaxPixels = 50_000_000
	// MaxDim 是单边上限，避免 1×5000 万 这种极端长条。
	MaxDim = 20000
)

// Sanitize 校验并重编码一张图片，返回干净字节、扩展名与实际尺寸。
func Sanitize(raw []byte) (out []byte, ext string, w, h int, err error) {
	if len(raw) == 0 {
		return nil, "", 0, 0, fmt.Errorf("空文件")
	}
	if len(raw) > MaxBytes {
		return nil, "", 0, 0, fmt.Errorf("图片过大（上限 %d MB）", MaxBytes>>20)
	}
	ct := http.DetectContentType(raw)
	switch ct {
	case "image/png", "image/jpeg", "image/gif":
	default:
		return nil, "", 0, 0, fmt.Errorf("仅支持 png/jpg/gif 图片（检测到 %s）", ct)
	}
	// 先只读头部拿尺寸：整幅解码之前挡掉解压炸弹。
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, "", 0, 0, fmt.Errorf("不是有效图片")
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return nil, "", 0, 0, fmt.Errorf("图片尺寸无效")
	}
	if cfg.Width > MaxDim || cfg.Height > MaxDim || cfg.Width*cfg.Height > MaxPixels {
		return nil, "", 0, 0, fmt.Errorf("图片尺寸超限（%dx%d）", cfg.Width, cfg.Height)
	}
	img, _, err := image.Decode(io.LimitReader(bytes.NewReader(raw), MaxBytes))
	if err != nil {
		return nil, "", 0, 0, fmt.Errorf("图片解码失败")
	}
	b := img.Bounds()
	var buf bytes.Buffer
	if ct == "image/jpeg" {
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
			return nil, "", 0, 0, fmt.Errorf("图片重编码失败")
		}
		return buf.Bytes(), ".jpg", b.Dx(), b.Dy(), nil
	}
	// PNG / GIF 统一转 PNG：GIF 只取首帧，避免动图在报告里变成一张透明图。
	if err := png.Encode(&buf, img); err != nil {
		return nil, "", 0, 0, fmt.Errorf("图片重编码失败")
	}
	return buf.Bytes(), ".png", b.Dx(), b.Dy(), nil
}
