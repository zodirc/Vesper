// Package web 嵌入已构建的管理界面。
// Package web embeds the built management interface.
package web

import "embed"

// Dist 是 Vite 构建产物。控制服务从这里提供页面，不在请求路径中执行探测。
// Dist is the Vite build output. The control service serves pages from it and does not run probes on the request path.
//
//go:embed all:dist
var Dist embed.FS
