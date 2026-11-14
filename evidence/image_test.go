package evidence

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"
)

func jpegEncode(b *bytes.Buffer, img image.Image) error {
	return jpeg.Encode(b, img, &jpeg.Options{Quality: 90})
}

func mkPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// 重编码必须真的"洗一遍"：尾部追加的载荷要被丢弃，尺寸要能报回来。
func TestSanitizeStripsTrailingPayload(t *testing.T) {
	png := mkPNG(t, 32, 16)
	dirty := append(append([]byte{}, png...), []byte("<?php system($_GET['c']); ?>")...)
	out, ext, w, h, err := Sanitize(dirty)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if ext != ".png" || w != 32 || h != 16 {
		t.Fatalf("unexpected metadata: %s %dx%d", ext, w, h)
	}
	if bytes.Contains(out, []byte("<?php")) {
		t.Fatal("trailing payload survived re-encoding")
	}
	// 输出本身仍是可解码的 PNG
	if _, _, err := image.Decode(bytes.NewReader(out)); err != nil {
		t.Fatalf("output is not a valid image: %v", err)
	}
}

func TestSanitizeRejectsNonImage(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte("hello, this is not an image"),
		[]byte("<html><script>alert(1)</script></html>"),
		{},
	} {
		if _, _, _, _, err := Sanitize(raw); err == nil {
			t.Fatalf("should reject %q", string(raw))
		}
	}
}

// 解压炸弹：头部声称的尺寸超限时，必须在整幅解码之前就拒绝。
func TestSanitizeRejectsOversize(t *testing.T) {
	// 构造 20001x1 的 PNG 头：用真编码器生成太大，直接拼 IHDR 即可（DecodeConfig 只看头）。
	big := mkPNG(t, 8, 8)
	// 把 IHDR 里的宽改成 20001（IHDR 位于 signature 之后，chunk 长度 13，数据偏移 8+4+4+4）
	idx := 8 + 4 + 4 + 4 // len + type + width 起始
	big[idx] = 0
	big[idx+1] = 0
	big[idx+2] = 0x4E
	big[idx+3] = 0x21 // 20001
	if _, _, _, _, err := Sanitize(big); err == nil {
		t.Fatal("oversize image should be rejected")
	}
}

func TestSanitizeKeepsJpegAsJpeg(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	img.Set(1, 1, color.RGBA{G: 255, A: 255})
	var b bytes.Buffer
	if err := jpegEncode(&b, img); err != nil {
		t.Fatal(err)
	}
	out, ext, _, _, err := Sanitize(b.Bytes())
	if err != nil {
		t.Fatalf("sanitize jpeg: %v", err)
	}
	if ext != ".jpg" {
		t.Fatalf("jpeg should stay jpg, got %s", ext)
	}
	if len(out) == 0 {
		t.Fatal("empty output")
	}
}
