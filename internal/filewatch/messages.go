package filewatch

// filewatch 不产生任何中文错误文案：readFile 把 os 的错误原样返回给调用方，
// Watcher 唯一的中文输出是一条日志（「读取配置文件失败，稍后重试」），
// 日志按约定走 i18n.Text，词条登记在 internal/i18n/logs.go。
// 本文件是该包双语文案的落点：将来新增面向用户的错误文案时在这里集中定义
// i18n.Msg（中文与改造前保持逐字一致，英文为等价翻译，fmt 动词个数与顺序一致）。
